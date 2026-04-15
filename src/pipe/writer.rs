//! [`PipeWriter`] — per-stream socketpair write half with pull-based flow control.
//!
//! Wraps the write direction of a `SOCK_STREAM` socketpair, encoding the pipe
//! framing protocol and exposing it as `Sink<Bytes, Error = StreamError>` +
//! [`CancelStream`] + [`GetStreamId`], satisfying [`quic::WriteStream`].
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
    net::unix::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_util::codec::FramedRead;

use super::{
    codec::{Frame, PipeCodec, TAG_CANCEL, TAG_CONN_CLOSED},
    state::{
        PendingPush, PipeState, Step, Transition, check_lifecycle, drain, encode_control,
        flush_pending,
    },
};
use crate::{
    quic::{self, CancelStream, GetStreamId, StreamError},
    varint::VarInt,
};

/// Active-state fields for the writer.
struct WriterLive {
    read: FramedRead<OwnedReadHalf, PipeCodec>,
    write: OwnedWriteHalf,
    lifecycle: Arc<dyn quic::DynLifecycle>,
    pulled: bool,
    pending: Option<PendingPush>,
}

impl WriterLive {
    /// Drain inbound control frames and check the lifecycle.
    ///
    /// - `PULL` → grant send permission
    /// - `STOP(code)` → peer requests reset
    /// - `CONN_CLOSED` → connection died
    /// - others → ignore
    ///
    /// On read-close: if the connection is dead, sends best-effort `CONN_CLOSED`
    /// (only when no partial DATA is in flight) and transitions to `ConnDied`.
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
            if self.lifecycle.check().is_err() {
                // Only send CONN_CLOSED if no partial DATA is in flight.
                if self.pending.is_none() {
                    let _ = Pin::new(&mut self.write).poll_write(cx, &[TAG_CONN_CLOSED]);
                }
                Step::Transition(Transition::ConnDied(self.lifecycle.clone()))
            } else {
                Step::Done(())
            }
        })
    }

    /// `poll_ready` step: drain control → check pulled + no pending data.
    fn step_poll_ready(&mut self, cx: &mut Context<'_>) -> Step<()> {
        let step = self.drain_and_check(cx);
        step.and_then(|()| {
            if self.pulled && self.pending.is_none() {
                Step::Done(())
            } else {
                Step::Pending
            }
        })
    }

    /// `poll_flush` step: drain control → flush pending PUSH via vectored I/O.
    fn step_poll_flush(&mut self, cx: &mut Context<'_>) -> Step<()> {
        let step = self.drain_and_check(cx);
        step.and_then(|()| flush_pending(&mut self.write, &self.lifecycle, &mut self.pending, cx))
    }

    /// `poll_close` step: flush pending data → shutdown write half (SHUT_WR).
    fn step_poll_close(&mut self, cx: &mut Context<'_>) -> Step<()> {
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

    /// `poll_cancel` step: discard pending data → best-effort CANCEL → shutdown.
    fn step_poll_cancel(&mut self, code: VarInt, cx: &mut Context<'_>) -> Step<()> {
        self.pending = None;
        let (buf, len) = encode_control(TAG_CANCEL, code);
        let _ = Pin::new(&mut self.write).poll_write(cx, &buf[..len]);
        match Pin::new(&mut self.write).poll_shutdown(cx) {
            Poll::Ready(_) => Step::Transition(Transition::Finish),
            Poll::Pending => Step::Pending,
        }
    }
}

// ── PipeWriter ──────────────────────────────────────────────────────────────

/// Write half of a per-stream pipe.
///
/// Sends PUSH frames through the write half of the socketpair.
/// Reads PULL/STOP/CONN_CLOSED frames from the read half for flow control
/// and lifecycle signals.
pub struct PipeWriter {
    stream_id: VarInt,
    state: PipeState<WriterLive>,
}

impl PipeWriter {
    /// Create a new writer from the two halves of a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        read_half: OwnedReadHalf,
        write_half: OwnedWriteHalf,
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> Self {
        Self {
            stream_id,
            state: PipeState::Live(WriterLive {
                read: FramedRead::new(read_half, PipeCodec::new()),
                write: write_half,
                lifecycle,
                pulled: false,
                pending: None,
            }),
        }
    }
}

impl GetStreamId for PipeWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Sink<Bytes> for PipeWriter {
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

impl CancelStream for PipeWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        loop {
            if let Some(poll) = this.state.poll_non_live(cx) {
                // Already dead — cancel is a no-op.
                let _ = poll;
                return Poll::Ready(Ok(()));
            }
            let live = this.state.live_mut().unwrap();
            match live.step_poll_cancel(code, cx) {
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
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, StreamExt, future::poll_fn, task::noop_waker_ref};
    use tokio::net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    };
    use tokio_util::codec::{FramedRead, FramedWrite};

    use super::*;
    use crate::quic::ConnectionError;

    struct TestLifecycle;

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> ConnectionError {
            pending().await
        }
    }

    async fn setup_writer() -> (
        PipeWriter,
        FramedWrite<OwnedWriteHalf, PipeCodec>,
        FramedRead<OwnedReadHalf, PipeCodec>,
    ) {
        let (writer_side, peer_side) = UnixStream::pair().unwrap();
        let (writer_read, writer_write) = writer_side.into_split();
        let (peer_read, peer_write) = peer_side.into_split();

        let lifecycle: Arc<dyn quic::DynLifecycle> = Arc::new(TestLifecycle);
        let writer = PipeWriter::new(VarInt::from_u32(1), writer_read, writer_write, lifecycle);

        (
            writer,
            FramedWrite::new(peer_write, PipeCodec::new()),
            FramedRead::new(peer_read, PipeCodec::new()),
        )
    }

    fn poll_ready_once(writer: &mut PipeWriter) -> Poll<Result<(), StreamError>> {
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
}
