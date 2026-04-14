//! [`PipeWriter`] — per-stream socketpair write half.
//!
//! Wraps the write direction of a `SOCK_STREAM` socketpair, encoding the pipe
//! framing protocol and exposing it as `Sink<Bytes, Error = StreamError>` +
//! [`CancelStream`] + [`GetStreamId`], satisfying [`quic::WriteStream`].
//!
//! # Flush / Close semantics
//!
//! - `poll_flush` — flushes the user-space codec buffer.  The kernel socketpair
//!   buffer has no delay so this is effectively a no-op once the codec buffer
//!   is drained.
//! - `poll_close` — sends any remaining buffered data, then calls
//!   `shutdown(SHUT_WR)` on the underlying socketpair, which the remote side
//!   observes as EOF (equivalent to QUIC FIN).

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, ready};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};

use super::codec::{Frame, PipeCodec};
use crate::{
    quic::{self, CancelStream, GetStreamId, StreamError},
    util::set_once::SetOnce,
    varint::VarInt,
};

/// Write half of a per-stream pipe.
///
/// Sends DATA frames through the write half of the socketpair.
/// Reads STOP/CONN_CLOSED frames from the read half for control signals.
pub struct PipeWriter {
    stream_id: VarInt,
    write: FramedWrite<OwnedWriteHalf, PipeCodec>,
    read: FramedRead<OwnedReadHalf, PipeCodec>,
    terminal_error: SetOnce<quic::ConnectionError>,
    state: WriterState,
}

enum WriterState {
    /// Normal operation.
    Active,
    /// Received STOP from remote — further writes should error.
    Stopped { code: VarInt },
    /// Connection closed — return terminal error.
    ConnClosed,
    /// Stream finished (after cancel or close).
    Finished,
}

impl PipeWriter {
    /// Create a new writer from the two halves of a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        read_half: OwnedReadHalf,
        write_half: OwnedWriteHalf,
        terminal_error: SetOnce<quic::ConnectionError>,
    ) -> Self {
        Self {
            stream_id,
            write: FramedWrite::new(write_half, PipeCodec::new()),
            read: FramedRead::new(read_half, PipeCodec::new()),
            terminal_error,
            state: WriterState::Active,
        }
    }

    /// Non-blocking check for incoming control frames (STOP / CONN_CLOSED).
    ///
    /// Drains available control frames from the read half and updates state
    /// accordingly. Does NOT block if no data is available.
    fn poll_control(&mut self, cx: &mut Context<'_>) {
        loop {
            match Pin::new(&mut self.read).poll_next(cx) {
                Poll::Ready(Some(Ok(Frame::Stop(code)))) => {
                    if matches!(self.state, WriterState::Active) {
                        self.state = WriterState::Stopped { code };
                    }
                }
                Poll::Ready(Some(Ok(Frame::ConnClosed))) => {
                    self.state = WriterState::ConnClosed;
                    return;
                }
                Poll::Ready(Some(Ok(_))) => {
                    // DATA or CANCEL on a writer — ignore (protocol mismatch).
                    continue;
                }
                Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                    // Read half closed/errored — check terminal error.
                    if self.terminal_error.is_set() {
                        self.state = WriterState::ConnClosed;
                    }
                    return;
                }
                Poll::Pending => return,
            }
        }
    }

    fn make_stream_error(&self) -> StreamError {
        match &self.state {
            WriterState::Stopped { code } => StreamError::Reset { code: *code },
            WriterState::ConnClosed => StreamError::Connection {
                source: super::connection_error_or_fallback(
                    &self.terminal_error,
                    "connection closed",
                ),
            },
            _ => unreachable!("make_stream_error called in non-error state"),
        }
    }

    fn codec_err_to_stream_err(&self, codec_err: super::codec::CodecError) -> StreamError {
        tracing::debug!(%codec_err, "pipe codec error on writer");
        StreamError::Connection {
            source: super::connection_error_or_fallback(&self.terminal_error, "pipe broken"),
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
        // Check for incoming control signals.
        this.poll_control(cx);

        match this.state {
            WriterState::Stopped { .. } | WriterState::ConnClosed => {
                Poll::Ready(Err(this.make_stream_error()))
            }
            WriterState::Finished => Poll::Ready(Err(StreamError::Connection {
                source: super::connection_error_or_fallback(
                    &this.terminal_error,
                    "stream already finished",
                ),
            })),
            WriterState::Active => Pin::new(&mut this.write)
                .poll_ready(cx)
                .map_err(|e| this.codec_err_to_stream_err(e)),
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), StreamError> {
        let this = self.get_mut();
        match this.state {
            WriterState::Stopped { .. } | WriterState::ConnClosed => Err(this.make_stream_error()),
            WriterState::Finished => Err(StreamError::Connection {
                source: super::connection_error_or_fallback(
                    &this.terminal_error,
                    "stream already finished",
                ),
            }),
            WriterState::Active => Pin::new(&mut this.write)
                .start_send(Frame::Data(item))
                .map_err(|e| this.codec_err_to_stream_err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        // Check for incoming control signals.
        this.poll_control(cx);

        match this.state {
            WriterState::Stopped { .. } | WriterState::ConnClosed => {
                Poll::Ready(Err(this.make_stream_error()))
            }
            WriterState::Finished => Poll::Ready(Err(StreamError::Connection {
                source: super::connection_error_or_fallback(
                    &this.terminal_error,
                    "stream already finished",
                ),
            })),
            WriterState::Active => Pin::new(&mut this.write)
                .poll_flush(cx)
                .map_err(|e| this.codec_err_to_stream_err(e)),
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        // Flush + shutdown(SHUT_WR) via the underlying AsyncWrite.
        ready!(
            Pin::new(&mut this.write)
                .poll_close(cx)
                .map_err(|e| this.codec_err_to_stream_err(e))
        )?;
        this.state = WriterState::Finished;
        Poll::Ready(Ok(()))
    }
}

impl CancelStream for PipeWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        // Send CANCEL frame, then close the write half.
        ready!(
            Pin::new(&mut this.write)
                .poll_ready(cx)
                .map_err(|e| this.codec_err_to_stream_err(e))
        )?;
        Pin::new(&mut this.write)
            .start_send(Frame::Cancel(code))
            .map_err(|e| this.codec_err_to_stream_err(e))?;
        ready!(
            Pin::new(&mut this.write)
                .poll_close(cx)
                .map_err(|e| this.codec_err_to_stream_err(e))
        )?;
        this.state = WriterState::Finished;
        Poll::Ready(Ok(()))
    }
}
