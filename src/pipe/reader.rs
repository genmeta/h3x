//! [`PipeReader`] — per-stream socketpair read half with pull-based flow control.
//!
//! Wraps the read direction of a `SOCK_STREAM` socketpair, decoding the pipe
//! framing protocol and exposing it as `Stream<Item = Result<Bytes, StreamError>>` +
//! [`StopStream`] + [`GetStreamId`], satisfying [`quic::ReadStream`].
//!
//! # Flow control
//!
//! The reader sends a parameterless `PULL` frame to grant the writer permission
//! to send exactly one `DATA` frame.  The protocol is strictly serial:
//! PULL → DATA → PULL → DATA → …  This prevents back-pressure breakage
//! across the socketpair.

use std::{
    mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture, ready};
use tokio::net::unix::OwnedWriteHalf;
use tokio_util::codec::{FramedRead, FramedWrite};

use super::codec::{Frame, PipeCodec};
use crate::{
    quic::{self, ConnectionError, GetStreamId, StopStream, StreamError},
    varint::VarInt,
};

/// Active-state fields for the reader.
///
/// Holds the socket halves and connection lifecycle handle.  These are only
/// meaningful while the stream is alive; once the stream transitions to
/// `Closing` or `Finished` they are dropped.
struct ActiveReader {
    /// Whether a `PULL` frame has been sent and we are waiting for the
    /// corresponding `DATA` reply.
    pulling: bool,
    read: FramedRead<tokio::net::unix::OwnedReadHalf, PipeCodec>,
    write: FramedWrite<OwnedWriteHalf, PipeCodec>,
    connection: Arc<dyn quic::DynLifecycle>,
}

/// Read half of a per-stream pipe.
///
/// Reads DATA/CANCEL/CONN_CLOSED frames from the socketpair.
/// Sends PULL and STOP frames back through the write half of the same
/// socketpair.
pub struct PipeReader {
    stream_id: VarInt,
    state: ReaderState,
}

enum ReaderState {
    /// Normal operation — reading DATA frames.
    Active(ActiveReader),
    /// Connection closed — waiting for the real terminal error from the
    /// lifecycle.
    Closing(BoxFuture<'static, ConnectionError>),
    /// Stream has ended.  `Ok(())` = clean EOF, `Err` = error termination.
    Finished(Result<(), StreamError>),
}

impl PipeReader {
    /// Create a new reader from the two halves of a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        read_half: tokio::net::unix::OwnedReadHalf,
        write_half: OwnedWriteHalf,
        lifecycle: Arc<dyn quic::DynLifecycle>,
    ) -> Self {
        Self {
            stream_id,
            state: ReaderState::Active(ActiveReader {
                pulling: false,
                read: FramedRead::new(read_half, PipeCodec::new()),
                write: FramedWrite::new(write_half, PipeCodec::new()),
                connection: lifecycle,
            }),
        }
    }

    /// Transition to `Closing` and poll for the real connection error.
    ///
    /// Takes ownership of the `connection` handle from the `Active` state via
    /// `mem::replace`, then polls `closed()`.  If `check()` already returns
    /// an error, skip straight to `Finished`.
    fn enter_closing(&mut self, cx: &mut Context<'_>) {
        let ReaderState::Active(active) =
            mem::replace(&mut self.state, ReaderState::Finished(Ok(())))
        else {
            return;
        };
        let connection = active.connection;
        if let Err(e) = connection.check() {
            self.state = ReaderState::Finished(Err(StreamError::Connection { source: e }));
            return;
        }
        let mut fut: BoxFuture<'static, ConnectionError> =
            Box::pin(async move { connection.closed().await });
        match fut.as_mut().poll(cx) {
            Poll::Ready(e) => {
                self.state = ReaderState::Finished(Err(StreamError::Connection { source: e }));
            }
            Poll::Pending => {
                self.state = ReaderState::Closing(fut);
            }
        }
    }

    /// Finish the stream based on the current connection lifecycle state.
    ///
    /// Called when the read half produces an error or EOF.  If the connection
    /// is dead, transitions to `Finished(Err(Connection))`, otherwise to
    /// `Finished(Ok(()))` (clean EOF).
    fn finish_on_read_end(&mut self) {
        let ReaderState::Active(active) =
            mem::replace(&mut self.state, ReaderState::Finished(Ok(())))
        else {
            return;
        };
        if let Err(e) = active.connection.check() {
            self.state = ReaderState::Finished(Err(StreamError::Connection { source: e }));
        }
    }

    /// Core read method — strict PULL → DATA serial flow control.
    ///
    /// Sends a parameterless `PULL` frame to grant the writer permission to
    /// send one `DATA` frame, then waits for the response.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, StreamError>>> {
        loop {
            // ── Terminal states and Closing → Finished promotion ──
            match &mut self.state {
                ReaderState::Closing(fut) => {
                    let e = ready!(fut.as_mut().poll(cx));
                    self.state = ReaderState::Finished(Err(StreamError::Connection { source: e }));
                    continue;
                }
                ReaderState::Finished(Ok(())) => return Poll::Ready(None),
                ReaderState::Finished(Err(e)) => return Poll::Ready(Some(Err(e.clone()))),
                ReaderState::Active(_) => {}
            }

            // ── Send PULL if we haven’t yet ──
            let flush_result = {
                let ReaderState::Active(active) = &mut self.state else {
                    unreachable!();
                };
                if !active.pulling {
                    let _ = Pin::new(&mut active.write).start_send(Frame::Pull);
                    Some(Pin::new(&mut active.write).poll_flush(cx))
                } else {
                    None
                }
            };
            if let Some(result) = flush_result {
                match result {
                    Poll::Ready(Ok(())) => {
                        let ReaderState::Active(active) = &mut self.state else {
                            unreachable!();
                        };
                        active.pulling = true;
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::debug!(%e, "pipe codec error flushing PULL");
                        self.finish_on_read_end();
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }

            // ── Wait for DATA from the writer ──
            let frame = {
                let ReaderState::Active(active) = &mut self.state else {
                    unreachable!();
                };
                ready!(Pin::new(&mut active.read).poll_next(cx))
            };
            match frame {
                Some(Ok(Frame::Data(data))) => {
                    let ReaderState::Active(active) = &mut self.state else {
                        unreachable!();
                    };
                    active.pulling = false;
                    return Poll::Ready(Some(Ok(data)));
                }
                Some(Ok(Frame::Cancel(code))) => {
                    self.state = ReaderState::Finished(Err(StreamError::Reset { code }));
                    continue;
                }
                Some(Ok(Frame::ConnClosed)) => {
                    self.enter_closing(cx);
                    continue;
                }
                Some(Ok(Frame::Pull | Frame::Stop(_))) => continue,
                Some(Err(codec_err)) => {
                    tracing::debug!(%codec_err, "pipe codec error on reader");
                    self.finish_on_read_end();
                    continue;
                }
                None => {
                    self.finish_on_read_end();
                    continue;
                }
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
        let ReaderState::Active(active) = &mut this.state else {
            return Poll::Ready(Ok(()));
        };
        ready!(Pin::new(&mut active.write).poll_ready(cx).map_err(|e| {
            tracing::debug!(%e, "pipe codec error sending STOP (poll_ready)");
            match active.connection.check() {
                Err(conn_err) => StreamError::Connection { source: conn_err },
                Ok(()) => StreamError::Reset {
                    code: VarInt::default(),
                },
            }
        })?);
        let _ = Pin::new(&mut active.write).start_send(Frame::Stop(code));
        // Flush the STOP frame to the socket.
        match Pin::new(&mut active.write).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe codec error flushing STOP");
                match active.connection.check() {
                    Err(conn_err) => Poll::Ready(Err(StreamError::Connection { source: conn_err })),
                    Ok(()) => Poll::Ready(Ok(())),
                }
            }
            // Flush registered the waker — frame is buffered, report success.
            Poll::Pending => Poll::Ready(Ok(())),
        }
    }
}
