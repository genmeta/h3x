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
//! exactly one `DATA` frame.  `poll_ready` returns `Pending` when no `PULL`
//! has been received, and resumes once one arrives.
//!
//! # Flush / Close semantics
//!
//! - `poll_flush` — flushes the user-space codec buffer.
//! - `poll_close` — flushes remaining data, then shuts down the write half
//!   (`SHUT_WR`), which the remote side observes as EOF (equivalent to QUIC FIN).

use std::{
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture, ready};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::codec::{Frame, PipeCodec};
use crate::{
    quic::{self, CancelStream, ConnectionError, GetStreamId, StreamError},
    varint::VarInt,
};

/// Signal from [`ActiveWriter::drain_control`] indicating what action the
/// caller should take.
enum ControlSignal {
    /// No state-changing signal; continue normally.
    Ok,
    /// STOP received — finish with Reset.
    Stop(VarInt),
    /// CONN_CLOSED or read half broken — enter Closing.
    Close,
}

/// Active-state fields for the writer.
///
/// Holds the socket halves and connection lifecycle handle.  These are only
/// meaningful while the stream is alive; once the stream transitions to
/// `Closing` or `Finished` they are dropped.
struct ActiveWriter {
    /// Whether a `PULL` frame has been received, granting permission to send
    /// one `DATA` frame.
    pulled: bool,
    read: FramedRead<OwnedReadHalf, PipeCodec>,
    write: FramedWrite<OwnedWriteHalf, PipeCodec>,
    connection: Arc<dyn quic::DynLifecycle>,
}

impl ActiveWriter {
    /// Non-blocking drain of incoming control frames (PULL / STOP / CONN_CLOSED).
    ///
    /// Updates `pulled` on PULL and returns a signal on STOP / CONN_CLOSED.
    fn drain_control(&mut self, cx: &mut Context<'_>) -> ControlSignal {
        loop {
            match Pin::new(&mut self.read).poll_next(cx) {
                Poll::Ready(Some(Ok(Frame::Pull))) => {
                    self.pulled = true;
                }
                Poll::Ready(Some(Ok(Frame::Stop(code)))) => {
                    return ControlSignal::Stop(code);
                }
                Poll::Ready(Some(Ok(Frame::ConnClosed))) => {
                    return ControlSignal::Close;
                }
                Poll::Ready(Some(Ok(_))) => {
                    // DATA or CANCEL on a writer — ignore (protocol mismatch).
                    continue;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    // Read half closed/errored — connection is likely dead.
                    if self.connection.check().is_err() {
                        return ControlSignal::Close;
                    }
                    return ControlSignal::Ok;
                }
                Poll::Pending => return ControlSignal::Ok,
            }
        }
    }
}

/// Write half of a per-stream pipe.
///
/// Sends DATA frames through the write half of the socketpair.
/// Reads PULL/STOP/CONN_CLOSED frames from the read half for flow control
/// and lifecycle signals.
pub struct PipeWriter {
    stream_id: VarInt,
    state: WriterState,
}

enum WriterState {
    /// Normal operation.
    Active(ActiveWriter),
    /// Connection closed — waiting for the real terminal error.
    Closing(BoxFuture<'static, ConnectionError>),
    /// Stream has ended.  `Ok(())` = clean close, `Err` = error termination.
    Finished(Result<(), StreamError>),
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
            state: WriterState::Active(ActiveWriter {
                pulled: false,
                read: FramedRead::new(read_half, PipeCodec::new()),
                write: FramedWrite::new(write_half, PipeCodec::new()),
                connection: lifecycle,
            }),
        }
    }

    /// Transition to `Closing` and start polling for the real connection error.
    ///
    /// Takes ownership of the `connection` handle from the `Active` state via
    /// `mem::replace`, then polls `closed()`.  If `check()` already returns
    /// an error, go straight to `Finished`.
    fn enter_closing(&mut self, cx: &mut Context<'_>) {
        let WriterState::Active(active) =
            mem::replace(&mut self.state, WriterState::Finished(Ok(())))
        else {
            return;
        };
        let connection = active.connection;
        if let Err(e) = connection.check() {
            self.state = WriterState::Finished(Err(StreamError::Connection { source: e }));
            return;
        }
        let mut fut: BoxFuture<'static, ConnectionError> =
            Box::pin(async move { connection.closed().await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(e) => {
                self.state = WriterState::Finished(Err(StreamError::Connection { source: e }));
            }
            Poll::Pending => {
                self.state = WriterState::Closing(fut);
            }
        }
    }

    /// Poll a non-Active state for the terminal `StreamError`.
    ///
    /// Drives `Closing` → `Finished` promotion, then returns the latched
    /// error.  Returns `Pending` only when `Closing` future is not yet ready.
    fn poll_terminal_error(&mut self, cx: &mut Context<'_>) -> Poll<StreamError> {
        loop {
            match &mut self.state {
                WriterState::Active(_) => unreachable!("called in Active state"),
                WriterState::Closing(fut) => {
                    let e = ready!(fut.as_mut().poll(cx));
                    self.state = WriterState::Finished(Err(StreamError::Connection { source: e }));
                    continue;
                }
                WriterState::Finished(Err(e)) => return Poll::Ready(e.clone()),
                WriterState::Finished(Ok(())) => {
                    return Poll::Ready(StreamError::Reset {
                        code: VarInt::default(),
                    });
                }
            }
        }
    }

    /// Ensure we are in `Active` state (draining control frames and checking
    /// the lifecycle), then run `f`.  If the state has transitioned away from
    /// `Active`, returns the terminal error instead.
    fn with_active<T>(
        &mut self,
        cx: &mut Context<'_>,
        f: impl FnOnce(&mut ActiveWriter, &mut Context<'_>) -> Poll<Result<T, StreamError>>,
    ) -> Poll<Result<T, StreamError>> {
        loop {
            // ── Non-Active: resolve terminal error ──
            if !matches!(self.state, WriterState::Active(_)) {
                return Poll::Ready(Err(ready!(self.poll_terminal_error(cx))));
            }

            // ── Active: drain control frames ──
            let signal = {
                let WriterState::Active(active) = &mut self.state else {
                    unreachable!();
                };
                active.drain_control(cx)
            };
            match signal {
                ControlSignal::Stop(code) => {
                    self.state = WriterState::Finished(Err(StreamError::Reset { code }));
                    continue;
                }
                ControlSignal::Close => {
                    self.enter_closing(cx);
                    continue;
                }
                ControlSignal::Ok => {}
            }

            // ── Active: check lifecycle ──
            let dead = {
                let WriterState::Active(active) = &mut self.state else {
                    unreachable!();
                };
                if active.connection.check().is_err() {
                    let _ = Pin::new(&mut active.write).start_send(Frame::ConnClosed);
                    let _ = Pin::new(&mut active.write).poll_flush(cx);
                    true
                } else {
                    false
                }
            };
            if dead {
                self.enter_closing(cx);
                continue;
            }

            // ── Active: run closure ──
            let WriterState::Active(active) = &mut self.state else {
                unreachable!();
            };
            return f(active, cx);
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
        this.with_active(cx, |active, cx| {
            if !active.pulled {
                return Poll::Pending;
            }
            Pin::new(&mut active.write).poll_ready(cx).map_err(|e| {
                tracing::debug!(%e, "pipe codec error on writer poll_ready");
                active
                    .connection
                    .check()
                    .expect_err("pipe IO failed but lifecycle check passed")
                    .into()
            })
        })
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), StreamError> {
        let this = self.get_mut();
        let WriterState::Active(active) = &mut this.state else {
            return Err(StreamError::Reset {
                code: VarInt::default(),
            });
        };
        active.pulled = false;
        Pin::new(&mut active.write)
            .start_send(Frame::Data(item))
            .map_err(|e| {
                tracing::debug!(%e, "pipe codec error on writer start_send");
                active
                    .connection
                    .check()
                    .expect_err("pipe encode failed but lifecycle check passed")
                    .into()
            })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        this.with_active(cx, |active, cx| {
            Pin::new(&mut active.write).poll_flush(cx).map_err(|e| {
                tracing::debug!(%e, "pipe codec error on writer poll_flush");
                active
                    .connection
                    .check()
                    .expect_err("pipe IO failed but lifecycle check passed")
                    .into()
            })
        })
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        let close_result = match &mut this.state {
            WriterState::Active(active) => Pin::new(&mut active.write).poll_close(cx),
            _ => return Poll::Ready(Ok(())),
        };
        match close_result {
            Poll::Ready(Ok(())) => {
                this.state = WriterState::Finished(Ok(()));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe codec error on writer poll_close");
                let WriterState::Active(active) =
                    mem::replace(&mut this.state, WriterState::Finished(Ok(())))
                else {
                    unreachable!();
                };
                match active.connection.check() {
                    Err(conn_err) => {
                        this.state = WriterState::Finished(Err(StreamError::Connection {
                            source: conn_err.clone(),
                        }));
                        Poll::Ready(Err(StreamError::Connection { source: conn_err }))
                    }
                    Ok(()) => Poll::Ready(Ok(())),
                }
            }
            Poll::Pending => Poll::Pending,
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
        let close_result = {
            let WriterState::Active(active) = &mut this.state else {
                return Poll::Ready(Ok(()));
            };
            // Best-effort: ready → send CANCEL → close.
            if Pin::new(&mut active.write).poll_ready(cx).is_ready() {
                let _ = Pin::new(&mut active.write).start_send(Frame::Cancel(code));
            }
            Pin::new(&mut active.write).poll_close(cx)
        };
        match close_result {
            Poll::Ready(Ok(())) => {
                this.state = WriterState::Finished(Ok(()));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe codec error on writer poll_cancel");
                let WriterState::Active(active) =
                    mem::replace(&mut this.state, WriterState::Finished(Ok(())))
                else {
                    unreachable!();
                };
                match active.connection.check() {
                    Err(conn_err) => {
                        this.state = WriterState::Finished(Err(StreamError::Connection {
                            source: conn_err.clone(),
                        }));
                        Poll::Ready(Err(StreamError::Connection { source: conn_err }))
                    }
                    Ok(()) => Poll::Ready(Ok(())),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
