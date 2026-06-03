//! [`IpcWriteStream`] — per-stream socketpair write half with pull-based flow control.
//!
//! Wraps the write direction of a `SOCK_STREAM` socketpair, encoding the pipe
//! framing protocol and exposing it as `Sink<Bytes, Error = StreamError>` +
//! [`ResetStream`] + [`GetStreamId`], satisfying [`quic::WriteStream`].
//!
//! # Flow control
//!
//! The writer may only send data after the peer reader has granted permission
//! via a `PULL` frame.  The protocol is strictly serial: each `PULL` permits
//! exactly one `PUSH` frame.  `poll_ready` returns `Pending` when no `PULL`
//! has been received, and resumes once one arrives.
//!
//! # Flush / Close semantics
//!
//! - `poll_flush` — flushes the pending PUSH frame via vectored I/O.
//! - `poll_close` — flushes remaining data, then shuts down the write half
//!   (`SHUT_WR`), which the remote side observes as EOF (equivalent to QUIC FIN).

use std::{
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Sink;
use tokio::{
    io::AsyncWrite,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use tokio_util::codec::FramedRead;

use super::{
    codec::{Frame, StreamCodec, TAG_CANCEL, TAG_CONN_CLOSED},
    state::{
        PendingControl, PendingPush, PipeState, Step, Transition, check_lifecycle, drain,
        flush_control, flush_pending,
    },
};
use crate::{
    quic::{self, GetStreamId, ResetStream, StreamError},
    varint::VarInt,
};

/// Active-state fields for the writer.
struct WriterLive {
    read: FramedRead<OwnedReadHalf, StreamCodec>,
    write: OwnedWriteHalf,
    lifecycle: Arc<dyn quic::DynLifecycle>,
    pulled: bool,
    pending: Option<PendingPush>,
    pending_reset: Option<PendingControl>,
    reset_shutdown: bool,
    pending_close: bool,
}

impl WriterLive {
    fn reset_is_pending(&self) -> bool {
        self.pending_reset.is_some() || self.reset_shutdown
    }

    fn step_pending_reset(&mut self, cx: &mut Context<'_>) -> Step<()> {
        self.pending = None;
        self.pending_close = false;

        if self.pending_reset.is_some() {
            match flush_control(
                &mut self.write,
                &self.lifecycle,
                &mut self.pending_reset,
                cx,
            ) {
                Step::Done(()) => {
                    self.reset_shutdown = true;
                }
                Step::Pending => return Step::Pending,
                Step::Transition(t) => return Step::Transition(t),
            }
        }

        if self.reset_shutdown {
            match Pin::new(&mut self.write).poll_shutdown(cx) {
                Poll::Ready(_) => Step::Transition(Transition::Finish),
                Poll::Pending => Step::Pending,
            }
        } else {
            Step::Done(())
        }
    }

    /// Drain inbound control frames and check the lifecycle.
    ///
    /// - `PULL` → grant send permission
    /// - `STOP(code)` → peer requests reset
    /// - `CONN_CLOSED` → connection died
    /// - others → ignore
    ///
    /// On read-close: sends best-effort `CONN_CLOSED` (only when no partial
    /// PUSH is in flight) and transitions to `ConnDied`.  The pipe EOF is
    /// treated as authoritative — no more `PULL` frames can ever arrive —
    /// even if `lifecycle.check()` has not yet been updated.
    fn drain_and_check(&mut self, cx: &mut Context<'_>) -> Step<()> {
        let outcome = drain(&mut self.read, cx, |frame| match frame {
            Frame::Pull => {
                self.pulled = true;
                ControlFlow::Continue(())
            }
            Frame::Stop(code) => ControlFlow::Break(Transition::Reset(code)),
            Frame::ConnClosed => ControlFlow::Break(Transition::ConnDied(self.lifecycle.clone())),
            _ => ControlFlow::Continue(()),
        });

        outcome.resolve(|| {
            // Pipe read half is closed: the peer bridge task has exited
            // (either because the connection died or because it finished).
            // No more PULL frames can ever arrive, so continuing would
            // deadlock poll_ready.  Transition unconditionally.
            if self.pending.is_none() {
                let _ = Pin::new(&mut self.write).poll_write(cx, &[TAG_CONN_CLOSED]);
            }
            Step::Transition(Transition::ConnDied(self.lifecycle.clone()))
        })
    }

    /// `poll_ready` step: drain control → eagerly flush pending → check pulled.
    ///
    /// Callers (e.g. `SinkWriter::poll_write`) may call `poll_ready` after
    /// `start_send` without an intervening `poll_flush`.  To avoid deadlock
    /// we eagerly flush pending PUSH data here, ensuring the bridge-writer
    /// can receive it and send the next PULL.
    fn step_poll_ready(&mut self, cx: &mut Context<'_>) -> Step<()> {
        if self.reset_is_pending() {
            return self.step_pending_reset(cx);
        }

        let step = self.drain_and_check(cx);
        step.and_then(|()| {
            if self.pending_close {
                return self.step_poll_close(cx);
            }

            // Eagerly flush any pending PUSH — prevents deadlock when the
            // caller skips poll_flush between start_send and poll_ready.
            if self.pending.is_some() {
                match flush_pending(&mut self.write, &self.lifecycle, &mut self.pending, cx) {
                    Step::Transition(t) => return Step::Transition(t),
                    Step::Pending | Step::Done(()) => {}
                }
            }

            if self.pulled && self.pending.is_none() {
                Step::Done(())
            } else {
                Step::Pending
            }
        })
    }

    /// `poll_flush` step: drain control → flush pending PUSH via vectored I/O.
    fn step_poll_flush(&mut self, cx: &mut Context<'_>) -> Step<()> {
        if self.reset_is_pending() {
            return self.step_pending_reset(cx);
        }
        if self.pending_close {
            return self.step_poll_close(cx);
        }

        let step = self.drain_and_check(cx);
        step.and_then(|()| flush_pending(&mut self.write, &self.lifecycle, &mut self.pending, cx))
    }

    /// `poll_close` step: flush pending data → shutdown write half (SHUT_WR).
    fn step_poll_close(&mut self, cx: &mut Context<'_>) -> Step<()> {
        if self.reset_is_pending() {
            return self.step_pending_reset(cx);
        }

        let Self {
            write,
            lifecycle,
            pending,
            ..
        } = self;
        flush_pending(write, lifecycle, pending, cx).and_then(|()| {
            match Pin::new(&mut *write).poll_shutdown(cx) {
                Poll::Ready(Ok(())) => Step::Transition(Transition::Finish),
                Poll::Ready(Err(e)) => {
                    tracing::debug!(%e, "pipe write error during close shutdown");
                    check_lifecycle(lifecycle, Step::Transition(Transition::Finish))
                }
                Poll::Pending => Step::Pending,
            }
        })
    }

    /// `poll_reset` step: discard pending data → best-effort CANCEL → shutdown.
    fn step_poll_reset(&mut self, code: VarInt, cx: &mut Context<'_>) -> Step<()> {
        self.pending = None;
        self.pending_close = false;
        if !self.reset_is_pending() {
            self.pending_reset = Some(PendingControl::new(TAG_CANCEL, code));
        }
        self.step_pending_reset(cx)
    }
}

// ── IpcWriteStream ──────────────────────────────────────────────────────────────

/// IPC write stream backed by a per-stream Unix socketpair.
///
/// Sends PUSH frames through the write half of the socketpair.
/// Reads PULL/STOP/CONN_CLOSED frames from the read half for flow control
/// and lifecycle signals.
pub struct IpcWriteStream {
    stream_id: VarInt,
    state: PipeState<WriterLive>,
}

impl IpcWriteStream {
    /// Create a new writer from a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        socket: UnixStream,
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> Self {
        let (read_half, write_half) = socket.into_split();
        Self {
            stream_id,
            state: PipeState::Live(WriterLive {
                read: FramedRead::new(read_half, StreamCodec::new()),
                write: write_half,
                lifecycle,
                pulled: false,
                pending: None,
                pending_reset: None,
                reset_shutdown: false,
                pending_close: false,
            }),
        }
    }
}

impl GetStreamId for IpcWriteStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Sink<Bytes> for IpcWriteStream {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                return poll.map(|r| {
                    r.and(Err(StreamError::Reset {
                        code: VarInt::default(),
                    }))
                });
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_ready(cx) {
                Step::Done(()) => return Poll::Ready(Ok(())),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => this.state.apply(t, cx),
            }
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), StreamError> {
        let this = self.get_mut();
        let PipeState::Live(live) = &mut this.state else {
            return Err(StreamError::Reset {
                code: VarInt::default(),
            });
        };
        if !live.pulled || live.pending.is_some() {
            return Err(StreamError::Reset {
                code: VarInt::default(),
            });
        }
        live.pending = Some(PendingPush::new(item)?);
        live.pulled = false;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                return poll.map(|r| {
                    r.and(Err(StreamError::Reset {
                        code: VarInt::default(),
                    }))
                });
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_flush(cx) {
                Step::Done(()) => return Poll::Ready(Ok(())),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => this.state.apply(t, cx),
            }
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        if let PipeState::Live(live) = &mut this.state {
            live.pending_close = true;
        }
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                // Dead(Ok(())) = clean close succeeded; Dead(Err(_)) = already failed.
                return poll;
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_close(cx) {
                Step::Done(()) => return Poll::Ready(Ok(())),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => this.state.apply(t, cx),
            }
        }
    }
}

impl ResetStream for IpcWriteStream {
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                // Already dead — reset is a no-op.
                let _ = poll;
                return Poll::Ready(Ok(()));
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_reset(code, cx) {
                Step::Done(()) => return Poll::Ready(Ok(())),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => this.state.apply(t, cx),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        future::pending,
        os::fd::AsRawFd,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{FutureExt, Sink, SinkExt, StreamExt, future::poll_fn, task::noop_waker_ref};
    use tokio::{
        io::AsyncReadExt,
        net::{
            UnixStream,
            unix::{OwnedReadHalf, OwnedWriteHalf},
        },
        time::{Duration, timeout},
    };
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;
    use crate::quic::{ConnectionError, ResetStream};

    struct TestLifecycle {
        terminal: Option<ConnectionError>,
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            match &self.terminal {
                Some(err) => Err(err.clone()),
                None => Ok(()),
            }
        }

        async fn closed(&self) -> ConnectionError {
            match &self.terminal {
                Some(err) => err.clone(),
                None => pending().await,
            }
        }
    }

    fn test_connection_error(reason: &str) -> ConnectionError {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x31),
                frame_type: VarInt::from_u32(0x32),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn alive_lifecycle() -> Arc<dyn quic::DynLifecycle> {
        Arc::new(TestLifecycle { terminal: None })
    }

    fn dead_lifecycle(reason: &str) -> Arc<dyn quic::DynLifecycle> {
        Arc::new(TestLifecycle {
            terminal: Some(test_connection_error(reason)),
        })
    }

    async fn setup_writer_with_lifecycle(
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> (
        IpcWriteStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        FramedRead<OwnedReadHalf, StreamCodec>,
    ) {
        let (writer_side, peer_side) = UnixStream::pair().unwrap();
        let (peer_read, peer_write) = peer_side.into_split();

        let writer = IpcWriteStream::new(VarInt::from_u32(1), writer_side, lifecycle);

        (
            writer,
            FramedWrite::new(peer_write, StreamCodec::new()),
            FramedRead::new(peer_read, StreamCodec::new()),
        )
    }

    async fn setup_writer() -> (
        IpcWriteStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        FramedRead<OwnedReadHalf, StreamCodec>,
    ) {
        setup_writer_with_lifecycle(alive_lifecycle()).await
    }

    async fn setup_writer_with_raw_data_peer(
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> (
        IpcWriteStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        OwnedReadHalf,
    ) {
        let (writer_side, peer_side) = UnixStream::pair().unwrap();
        let (peer_read, peer_write) = peer_side.into_split();

        let writer = IpcWriteStream::new(VarInt::from_u32(1), writer_side, lifecycle);

        (
            writer,
            FramedWrite::new(peer_write, StreamCodec::new()),
            peer_read,
        )
    }

    fn shrink_send_buffer(write: &OwnedWriteHalf) {
        let size: nix::libc::c_int = 4096;
        let rc = unsafe {
            nix::libc::setsockopt(
                write.as_ref().as_raw_fd(),
                nix::libc::SOL_SOCKET,
                nix::libc::SO_SNDBUF,
                &size as *const _ as *const nix::libc::c_void,
                std::mem::size_of_val(&size) as nix::libc::socklen_t,
            )
        };
        assert_eq!(
            rc,
            0,
            "setsockopt(SO_SNDBUF) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    async fn fill_write_half(write: &mut OwnedWriteHalf, byte: u8) -> usize {
        shrink_send_buffer(write);
        timeout(Duration::from_millis(200), write.as_ref().writable())
            .await
            .expect("write half should become writable")
            .unwrap();
        let filler = [byte; 1024];
        let mut written_total = 0usize;
        loop {
            match write.as_ref().try_write(&filler) {
                Ok(0) => panic!("write half reported zero-byte write"),
                Ok(written) => {
                    written_total += written;
                    assert!(
                        written_total < 1_000_000,
                        "socket did not become full after {written_total} bytes"
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("write half failed while filling: {error}"),
            }
        }

        assert!(
            written_total > 0,
            "socket should accept filler before Pending"
        );
        written_total
    }

    fn poll_ready_once(writer: &mut IpcWriteStream) -> Poll<Result<(), StreamError>> {
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        Pin::new(writer).poll_ready(&mut cx)
    }

    #[tokio::test]
    async fn poll_ready_pending_without_pull() {
        let (mut writer, _peer_ctrl, _peer_data) = setup_writer().await;
        assert!(poll_ready_once(&mut writer).is_pending());
    }

    #[tokio::test]
    async fn pull_then_send_data_roundtrip() {
        let (mut writer, mut peer_ctrl, mut peer_data) = setup_writer().await;

        peer_ctrl.send(Frame::Pull).await.unwrap();

        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"hello pipe"))
            .unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
            .await
            .unwrap();

        let frame = peer_data.next().await.unwrap().unwrap();
        assert_eq!(frame, Frame::Push(Bytes::from_static(b"hello pipe")));
    }

    #[tokio::test]
    async fn pull_permission_consumed_per_data_frame() {
        let (mut writer, mut peer_ctrl, mut peer_data) = setup_writer().await;

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"first"))
            .unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
            .await
            .unwrap();
        let _ = peer_data.next().await.unwrap().unwrap();

        assert!(poll_ready_once(&mut writer).is_pending());

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"second"))
            .unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
            .await
            .unwrap();

        let frame = peer_data.next().await.unwrap().unwrap();
        assert_eq!(frame, Frame::Push(Bytes::from_static(b"second")));
    }

    #[tokio::test]
    async fn start_send_without_pull_returns_reset() {
        let (mut writer, _peer_ctrl, _peer_data) = setup_writer().await;

        let err = Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"no-pull"))
            .unwrap_err();
        assert!(matches!(err, StreamError::Reset { .. }));
    }

    #[tokio::test]
    async fn start_send_twice_without_flush_returns_reset() {
        let (mut writer, mut peer_ctrl, _peer_data) = setup_writer().await;

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();

        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"first"))
            .unwrap();
        let err = Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"second"))
            .unwrap_err();
        assert!(matches!(err, StreamError::Reset { .. }));
    }

    #[tokio::test]
    async fn poll_close_flushes_pending_push_and_shuts_down() {
        let (mut writer, mut peer_ctrl, mut peer_data) = setup_writer().await;

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"close-payload"))
            .unwrap();

        poll_fn(|cx| Pin::new(&mut writer).poll_close(cx))
            .await
            .unwrap();

        assert_eq!(
            peer_data.next().await.unwrap().unwrap(),
            Frame::Push(Bytes::from_static(b"close-payload"))
        );
        let eof = timeout(Duration::from_millis(200), peer_data.next())
            .await
            .expect("expected EOF after poll_close");
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn poll_reset_sends_cancel_and_discards_pending_push() {
        let (mut writer, mut peer_ctrl, mut peer_data) = setup_writer().await;
        let code = VarInt::from_u32(77);

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"discard-me"))
            .unwrap();

        poll_fn(|cx| Pin::new(&mut writer).poll_reset(cx, code))
            .await
            .unwrap();

        assert_eq!(
            peer_data.next().await.unwrap().unwrap(),
            Frame::Cancel(code)
        );
        let eof = timeout(Duration::from_millis(200), peer_data.next())
            .await
            .expect("expected EOF after poll_reset");
        assert!(eof.is_none());
    }

    #[tokio::test]
    async fn poll_reset_committed_while_pipe_full_is_driven_by_poll_ready() {
        let (mut writer, _peer_ctrl, mut peer_data) =
            setup_writer_with_raw_data_peer(alive_lifecycle()).await;
        let code = VarInt::from_u32(7);
        let filler_count = {
            let live = writer.state.live_mut().expect("writer should be live");
            fill_write_half(&mut live.write, TAG_CONN_CLOSED).await
        };

        assert!(
            poll_fn(|cx| Pin::new(&mut writer).poll_reset(cx, code))
                .now_or_never()
                .is_none(),
            "reset should remain pending until the CANCEL frame is written"
        );

        let mut filler = vec![0_u8; filler_count];
        timeout(
            Duration::from_millis(200),
            peer_data.read_exact(&mut filler),
        )
        .await
        .expect("filler bytes should be readable")
        .unwrap();
        assert!(filler.iter().all(|byte| *byte == TAG_CONN_CLOSED));

        let mut observed = Vec::new();
        timeout(Duration::from_millis(200), async {
            while observed.len() < 2 {
                let _ = poll_ready_once(&mut writer);
                let mut buf = [0_u8; 16];
                if let Ok(Ok(read)) =
                    timeout(Duration::from_millis(10), peer_data.read(&mut buf)).await
                    && read > 0
                {
                    observed.extend_from_slice(&buf[..read]);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("CANCEL bytes should be emitted");
        assert_eq!(&observed[..2], [TAG_CANCEL, code.into_inner() as u8]);
    }

    #[tokio::test]
    async fn poll_close_committed_during_pending_push_is_driven_by_poll_ready() {
        let (mut writer, mut peer_ctrl, mut peer_data) =
            setup_writer_with_raw_data_peer(alive_lifecycle()).await;
        {
            let live = writer.state.live_mut().expect("writer should be live");
            shrink_send_buffer(&live.write);
        }

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from(vec![0xab; 1_000_000]))
            .unwrap();

        assert!(
            poll_fn(|cx| Pin::new(&mut writer).poll_close(cx))
                .now_or_never()
                .is_none(),
            "close should commit and wait for pending PUSH bytes"
        );

        let mut buf = [0_u8; 16 * 1024];
        timeout(Duration::from_secs(2), async {
            loop {
                let _ = poll_ready_once(&mut writer);
                match timeout(Duration::from_millis(10), peer_data.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => panic!("peer read failed: {error}"),
                    Err(_) => {}
                }
            }
        })
        .await
        .expect("committed close should eventually shut down the pipe");
    }

    #[tokio::test]
    async fn stop_frame_turns_writer_into_reset() {
        let (mut writer, mut peer_ctrl, _peer_data) = setup_writer().await;

        peer_ctrl
            .send(Frame::Stop(VarInt::from_u32(7)))
            .await
            .unwrap();

        let err = poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap_err();
        match err {
            StreamError::Reset { code } => assert_eq!(code, VarInt::from_u32(7)),
            other => panic!("expected reset error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn conn_closed_frame_with_dead_lifecycle_returns_connection_error() {
        let (mut writer, mut peer_ctrl, _peer_data) =
            setup_writer_with_lifecycle(dead_lifecycle("writer conn closed")).await;

        peer_ctrl.send(Frame::ConnClosed).await.unwrap();
        let err = poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::Connection { .. }));
    }

    #[tokio::test]
    async fn read_eof_with_dead_lifecycle_sends_conn_closed_when_no_pending() {
        let (mut writer, peer_ctrl, mut peer_data) =
            setup_writer_with_lifecycle(dead_lifecycle("writer eof dead")).await;

        drop(peer_ctrl);
        let err = poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap_err();
        assert!(matches!(err, StreamError::Connection { .. }));

        let frame = timeout(Duration::from_millis(200), peer_data.next())
            .await
            .expect("expected CONN_CLOSED frame")
            .expect("expected a frame")
            .expect("expected successful decode");
        assert_eq!(frame, Frame::ConnClosed);
    }

    #[tokio::test]
    async fn conn_closed_with_pending_push_returns_connection_error_without_conn_closed_echo() {
        let (mut writer, mut peer_ctrl, mut peer_data) =
            setup_writer_with_lifecycle(dead_lifecycle("writer eof with pending")).await;

        peer_ctrl.send(Frame::Pull).await.unwrap();
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap();
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"in-flight"))
            .unwrap();

        peer_ctrl.send(Frame::ConnClosed).await.unwrap();
        let flush_result = poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx)).await;
        if let Err(err) = flush_result {
            assert!(matches!(err, StreamError::Connection { .. }));
        }

        if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(50), peer_data.next()).await {
            assert_ne!(frame, Frame::ConnClosed);
        }
    }

    #[tokio::test]
    async fn unexpected_cancel_frame_is_ignored_while_waiting_for_pull() {
        let (mut writer, mut peer_ctrl, _peer_data) = setup_writer().await;

        peer_ctrl
            .send(Frame::Cancel(VarInt::from_u32(1)))
            .await
            .unwrap();
        assert!(poll_ready_once(&mut writer).is_pending());
    }

    #[tokio::test]
    async fn reset_is_noop_after_writer_is_dead() {
        let (mut writer, mut peer_ctrl, _peer_data) = setup_writer().await;

        peer_ctrl
            .send(Frame::Stop(VarInt::from_u32(123)))
            .await
            .unwrap();
        let _ = poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .unwrap_err();

        poll_fn(|cx| Pin::new(&mut writer).poll_reset(cx, VarInt::from_u32(9)))
            .await
            .unwrap();
    }
}
