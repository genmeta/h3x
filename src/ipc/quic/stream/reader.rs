//! [`IpcReadStream`] — per-stream socketpair read half with pull-based flow control.
//!
//! Wraps the read direction of a `SOCK_STREAM` socketpair, decoding the
//! framing protocol and exposing it as `Stream<Item = Result<Bytes, StreamError>>` +
//! [`StopStream`] + [`GetStreamId`], satisfying [`quic::ReadStream`].
//!
//! # Flow control
//!
//! The reader sends a parameterless `PULL` frame to grant the writer permission
//! to send exactly one `PUSH` frame.  The protocol is strictly serial:
//! PULL → PUSH → PULL → PUSH → …  This prevents back-pressure breakage
//! across the socketpair.

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Stream;
use tokio::{
    io::AsyncWrite,
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use tokio_util::codec::FramedRead;

use super::{
    codec::{Frame, StreamCodec, TAG_PULL, TAG_STOP},
    state::{PendingControl, PipeState, Step, Transition, check_lifecycle, flush_control},
};
use crate::{
    quic::{self, GetStreamId, StopStream, StreamError},
    varint::VarInt,
};

/// Active-state fields for the reader.
struct ReaderLive {
    /// Whether a `PULL` frame has been sent and we are waiting for the
    /// corresponding `PUSH` reply.
    pulling: bool,
    read: FramedRead<OwnedReadHalf, StreamCodec>,
    write: OwnedWriteHalf,
    lifecycle: Arc<dyn quic::DynLifecycle>,
    pending_stop: Option<PendingControl>,
}

impl ReaderLive {
    fn step_pending_stop(&mut self, cx: &mut Context<'_>) -> Step<()> {
        flush_control(&mut self.write, &self.lifecycle, &mut self.pending_stop, cx)
    }

    /// `poll_recv` step: send PULL → block-wait for PUSH.
    ///
    /// Uses atomic single-byte `poll_write` for PULL, eliminating the double-
    /// PULL bug that existed with the FramedWrite approach.
    fn step_poll_recv(&mut self, cx: &mut Context<'_>) -> Step<Bytes> {
        if self.pending_stop.is_some() {
            match self.step_pending_stop(cx) {
                Step::Done(()) => {}
                Step::Pending => return Step::Pending,
                Step::Transition(t) => return Step::Transition(t),
            }
        }

        let Self {
            pulling,
            read,
            write,
            lifecycle,
            pending_stop: _,
        } = self;

        // 1. Send PULL if we haven't yet (atomic single-byte write).
        if !*pulling {
            match Pin::new(&mut *write).poll_write(cx, &[TAG_PULL]) {
                Poll::Ready(Ok(1)) => *pulling = true,
                Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                    return check_lifecycle(lifecycle, Step::Transition(Transition::Finish))
                        .map(|()| unreachable!());
                }
                Poll::Pending => return Step::Pending,
            }
        }

        // 2. Block-wait for the next meaningful frame.
        loop {
            match Pin::new(&mut *read).poll_next(cx) {
                Poll::Ready(Some(Ok(Frame::Push(data)))) => {
                    *pulling = false;
                    return Step::Done(data);
                }
                Poll::Ready(Some(Ok(Frame::Cancel(code)))) => {
                    return Step::Transition(Transition::Reset(code));
                }
                Poll::Ready(Some(Ok(Frame::ConnClosed))) => {
                    return Step::Transition(Transition::ConnDied(lifecycle.clone()));
                }
                // PULL/STOP on a reader — protocol mismatch, skip.
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    tracing::debug!(%e, "pipe codec error on reader");
                    return check_lifecycle(lifecycle, Step::Transition(Transition::Finish))
                        .map(|()| unreachable!());
                }
                Poll::Ready(None) => {
                    // EOF — clean close if connection alive, else connection error.
                    return check_lifecycle(lifecycle, Step::Transition(Transition::Finish))
                        .map(|()| unreachable!());
                }
                Poll::Pending => return Step::Pending,
            }
        }
    }

    /// `poll_stop` step: encode STOP into a stack buffer and write it once.
    fn step_poll_stop(&mut self, code: VarInt, cx: &mut Context<'_>) -> Step<()> {
        if self.pending_stop.is_none() {
            self.pending_stop = Some(PendingControl::new(TAG_STOP, code));
        }
        self.step_pending_stop(cx)
    }
}

// ── IpcReadStream ───────────────────────────────────────────────────────────

/// IPC read stream backed by a per-stream Unix socketpair.
///
/// Reads PUSH/CANCEL/CONN_CLOSED frames from the socketpair.
/// Sends PULL and STOP frames back through the write half of the same
/// socketpair.
pub struct IpcReadStream {
    stream_id: VarInt,
    state: PipeState<ReaderLive>,
}

impl IpcReadStream {
    /// Create a new reader from a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        socket: UnixStream,
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> Self {
        let (read_half, write_half) = socket.into_split();
        Self {
            stream_id,
            state: PipeState::Live(ReaderLive {
                pulling: false,
                read: FramedRead::new(read_half, StreamCodec::new()),
                write: write_half,
                lifecycle,
                pending_stop: None,
            }),
        }
    }

    /// Core read method — strict PULL → PUSH serial flow control.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, StreamError>>> {
        loop {
            if let Some(poll) = self.state.poll_non_live(cx) {
                return match poll {
                    Poll::Ready(Ok(())) => Poll::Ready(None),
                    Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
                    Poll::Pending => Poll::Pending,
                };
            }
            let live = self.state.live_mut().unwrap();
            match live.step_poll_recv(cx) {
                Step::Done(data) => return Poll::Ready(Some(Ok(data))),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => self.state.apply(t, cx),
            }
        }
    }
}

impl GetStreamId for IpcReadStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Stream for IpcReadStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_recv(cx)
    }
}

impl StopStream for IpcReadStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                // Already dead — stop is a no-op.
                let _ = poll;
                return Poll::Ready(Ok(()));
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_stop(code, cx) {
                Step::Done(()) => return Poll::Ready(Ok(())),
                Step::Pending => return Poll::Pending,
                Step::Transition(t) => this.state.apply(t, cx),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, future::pending, os::fd::AsRawFd, pin::Pin, sync::Arc};

    use bytes::Bytes;
    use futures::{FutureExt, SinkExt, StreamExt, future::poll_fn};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{
            UnixStream,
            unix::{OwnedReadHalf, OwnedWriteHalf},
        },
        time::{Duration, timeout},
    };
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;
    use crate::quic::{ConnectionError, GetStreamId, StopStream};

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
                kind: VarInt::from_u32(0x11),
                frame_type: VarInt::from_u32(0x22),
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

    async fn setup_reader_with_lifecycle(
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> (
        IpcReadStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        FramedRead<OwnedReadHalf, StreamCodec>,
    ) {
        let (reader_side, peer_side) = UnixStream::pair().unwrap();

        let (peer_read, peer_write) = peer_side.into_split();

        let reader = IpcReadStream::new(VarInt::from_u32(7), reader_side, lifecycle);

        (
            reader,
            FramedWrite::new(peer_write, StreamCodec::new()),
            FramedRead::new(peer_read, StreamCodec::new()),
        )
    }

    async fn setup_reader() -> (
        IpcReadStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        FramedRead<OwnedReadHalf, StreamCodec>,
    ) {
        setup_reader_with_lifecycle(alive_lifecycle()).await
    }

    async fn setup_reader_with_raw_control_peer(
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> (
        IpcReadStream,
        FramedWrite<OwnedWriteHalf, StreamCodec>,
        OwnedReadHalf,
    ) {
        let (reader_side, peer_side) = UnixStream::pair().unwrap();
        let (peer_read, peer_write) = peer_side.into_split();

        let reader = IpcReadStream::new(VarInt::from_u32(7), reader_side, lifecycle);

        (
            reader,
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

    #[tokio::test]
    async fn stream_id_matches_constructor() {
        let (mut reader, _peer_in, _peer_out) = setup_reader().await;
        let id = poll_fn(|cx| Pin::new(&mut reader).poll_stream_id(cx))
            .await
            .unwrap();
        assert_eq!(id, VarInt::from_u32(7));
    }

    #[tokio::test]
    async fn pull_is_sent_once_while_waiting_for_push() {
        let (mut reader, mut peer_in, mut peer_out) = setup_reader().await;

        let mut recv = Box::pin(reader.next());
        let first = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(first, Frame::Pull);

        assert!(
            timeout(Duration::from_millis(50), peer_out.next())
                .await
                .is_err()
        );

        peer_in
            .send(Frame::Push(Bytes::from_static(b"drain")))
            .await
            .unwrap();
        let got = recv.await.unwrap().unwrap();
        assert_eq!(got, Bytes::from_static(b"drain"));
    }

    #[tokio::test]
    async fn push_roundtrip_and_next_poll_requests_again() {
        let (mut reader, mut peer_in, mut peer_out) = setup_reader().await;

        let mut recv = Box::pin(reader.next());
        let first_pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(first_pull, Frame::Pull);

        peer_in
            .send(Frame::Push(Bytes::from_static(b"reader-payload")))
            .await
            .unwrap();

        let got = recv.await.unwrap().unwrap();
        assert_eq!(got, Bytes::from_static(b"reader-payload"));

        let mut recv2 = Box::pin(reader.next());
        let second_pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv2 => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(second_pull, Frame::Pull);

        peer_in
            .send(Frame::Push(Bytes::from_static(b"reader-payload-2")))
            .await
            .unwrap();
        let got2 = recv2.await.unwrap().unwrap();
        assert_eq!(got2, Bytes::from_static(b"reader-payload-2"));
    }

    #[tokio::test]
    async fn protocol_mismatch_frames_are_ignored_until_push() {
        let (mut reader, mut peer_in, mut peer_out) = setup_reader().await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);

        peer_in.send(Frame::Pull).await.unwrap();
        peer_in
            .send(Frame::Stop(VarInt::from_u32(1)))
            .await
            .unwrap();
        peer_in
            .send(Frame::Push(Bytes::from_static(b"ok")))
            .await
            .unwrap();

        let got = recv.await.unwrap().unwrap();
        assert_eq!(got, Bytes::from_static(b"ok"));
    }

    #[tokio::test]
    async fn cancel_frame_turns_reader_into_reset() {
        let (mut reader, mut peer_in, mut peer_out) = setup_reader().await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);
        peer_in
            .send(Frame::Cancel(VarInt::from_u32(9)))
            .await
            .unwrap();

        let err = recv.await.unwrap().unwrap_err();
        match err {
            StreamError::Reset { code } => assert_eq!(code, VarInt::from_u32(9)),
            other => panic!("expected reset error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn conn_closed_with_dead_lifecycle_returns_connection_error() {
        let (mut reader, mut peer_in, mut peer_out) =
            setup_reader_with_lifecycle(dead_lifecycle("reader conn closed")).await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);
        peer_in.send(Frame::ConnClosed).await.unwrap();

        let err = recv.await.unwrap().unwrap_err();
        assert!(matches!(err, StreamError::Connection { .. }));
    }

    #[tokio::test]
    async fn eof_with_alive_lifecycle_finishes_stream() {
        let (mut reader, peer_in, mut peer_out) = setup_reader().await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);
        drop(peer_in);

        assert!(recv.await.is_none());
    }

    #[tokio::test]
    async fn eof_with_dead_lifecycle_returns_connection_error() {
        let (mut reader, peer_in, mut peer_out) =
            setup_reader_with_lifecycle(dead_lifecycle("reader eof while dead")).await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);
        drop(peer_in);

        let err = recv.await.unwrap().unwrap_err();
        assert!(matches!(err, StreamError::Connection { .. }));
    }

    #[tokio::test]
    async fn stop_sends_stop_frame_with_code() {
        let (mut reader, _peer_in, mut peer_out) = setup_reader().await;
        let code = VarInt::from_u32(77);

        poll_fn(|cx| Pin::new(&mut reader).poll_stop(cx, code))
            .await
            .unwrap();

        // STOP is best-effort: if it is observed on wire, it must carry the
        // same code. Implementations may still report success when the frame
        // has only been queued locally.
        if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(100), peer_out.next()).await {
            assert_eq!(frame, Frame::Stop(code));
        }
    }

    #[tokio::test]
    async fn stop_committed_while_pipe_full_is_driven_by_next_poll() {
        let (mut reader, _peer_in, mut peer_out) =
            setup_reader_with_raw_control_peer(alive_lifecycle()).await;
        let code = VarInt::from_u32(7);
        let filler_count = {
            let live = reader.state.live_mut().expect("reader should be live");
            fill_write_half(&mut live.write, TAG_PULL).await
        };

        assert!(
            poll_fn(|cx| Pin::new(&mut reader).poll_stop(cx, code))
                .now_or_never()
                .is_none(),
            "stop should remain pending until the STOP frame is written"
        );

        let mut filler = vec![0_u8; filler_count];
        timeout(Duration::from_millis(200), peer_out.read_exact(&mut filler))
            .await
            .expect("filler bytes should be readable")
            .unwrap();
        assert!(filler.iter().all(|byte| *byte == TAG_PULL));

        let mut observed = Vec::new();
        timeout(Duration::from_millis(200), async {
            while observed.len() < 2 {
                assert!(
                    poll_fn(|cx| Pin::new(&mut reader).poll_next(cx))
                        .now_or_never()
                        .is_none(),
                    "next poll should drive committed STOP then wait for data"
                );
                let mut buf = [0_u8; 16];
                if let Ok(Ok(read)) =
                    timeout(Duration::from_millis(10), peer_out.read(&mut buf)).await
                    && read > 0
                {
                    observed.extend_from_slice(&buf[..read]);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("STOP bytes should be emitted");
        assert_eq!(&observed[..2], [TAG_STOP, code.into_inner() as u8]);
    }

    #[tokio::test]
    async fn stop_is_noop_after_reader_is_dead() {
        let (mut reader, mut peer_in, mut peer_out) =
            setup_reader_with_lifecycle(dead_lifecycle("reader dead before stop")).await;

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);
        peer_in.send(Frame::ConnClosed).await.unwrap();
        let _ = recv.await;

        let code = VarInt::from_u32(5);
        poll_fn(|cx| Pin::new(&mut reader).poll_stop(cx, code))
            .await
            .unwrap();

        if let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(50), peer_out.next()).await {
            assert_ne!(frame, Frame::Stop(code));
        }
    }

    #[tokio::test]
    async fn codec_error_finishes_reader_when_connection_alive() {
        let (reader_side, peer_side) = UnixStream::pair().unwrap();

        let (peer_read, mut peer_write) = peer_side.into_split();

        let lifecycle = alive_lifecycle();
        let mut reader = IpcReadStream::new(VarInt::from_u32(1), reader_side, lifecycle);
        let mut peer_out = FramedRead::new(peer_read, StreamCodec::new());

        let mut recv = Box::pin(reader.next());
        let pull = tokio::select! {
            frame = peer_out.next() => frame.unwrap().unwrap(),
            item = &mut recv => panic!("reader completed unexpectedly: {item:?}"),
        };
        assert_eq!(pull, Frame::Pull);

        peer_write.write_all(&[0xff]).await.unwrap();

        assert!(recv.await.is_none());
    }
}
