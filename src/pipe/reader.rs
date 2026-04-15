//! [`PipeReader`] — per-stream socketpair read half with pull-based flow control.
//!
//! Wraps the read direction of a `SOCK_STREAM` socketpair, decoding the pipe
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
    net::unix::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio_util::codec::FramedRead;

use super::{
    codec::{Frame, PipeCodec, TAG_PULL, TAG_STOP},
    state::{PipeState, Step, Transition, check_lifecycle, encode_control},
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
    read: FramedRead<OwnedReadHalf, PipeCodec>,
    write: OwnedWriteHalf,
    lifecycle: Arc<dyn quic::DynLifecycle>,
}

impl ReaderLive {
    /// `poll_recv` step: send PULL → block-wait for PUSH.
    ///
    /// Uses atomic single-byte `poll_write` for PULL, eliminating the double-
    /// PULL bug that existed with the FramedWrite approach.
    fn step_poll_recv(&mut self, cx: &mut Context<'_>) -> Step<Bytes> {
        let Self {
            pulling,
            read,
            write,
            lifecycle,
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
        let Self {
            write, lifecycle, ..
        } = self;
        let (buf, len) = encode_control(TAG_STOP, code);
        match Pin::new(&mut *write).poll_write(cx, &buf[..len]) {
            Poll::Ready(Ok(_)) => Step::Done(()),
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe write error sending STOP");
                check_lifecycle(lifecycle, Step::Done(()))
            }
            // Frame buffered in kernel — report success.
            Poll::Pending => Step::Done(()),
        }
    }
}

// ── PipeReader ──────────────────────────────────────────────────────────────

/// Read half of a per-stream pipe.
///
/// Reads PUSH/CANCEL/CONN_CLOSED frames from the socketpair.
/// Sends PULL and STOP frames back through the write half of the same
/// socketpair.
pub struct PipeReader {
    stream_id: VarInt,
    state: PipeState<ReaderLive>,
}

impl PipeReader {
    /// Create a new reader from the two halves of a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        read_half: OwnedReadHalf,
        write_half: OwnedWriteHalf,
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> Self {
        Self {
            stream_id,
            state: PipeState::Live(ReaderLive {
                pulling: false,
                read: FramedRead::new(read_half, PipeCodec::new()),
                write: write_half,
                lifecycle,
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

impl GetStreamId for PipeReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Stream for PipeReader {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_recv(cx)
    }
}

impl StopStream for PipeReader {
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
