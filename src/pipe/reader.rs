//! [`PipeReader`] — per-stream socketpair read half.
//!
//! Wraps the read direction of a `SOCK_STREAM` socketpair, decoding the pipe
//! framing protocol and exposing it as `Stream<Item = Result<Bytes, StreamError>>` +
//! [`StopStream`] + [`GetStreamId`], satisfying [`quic::ReadStream`].

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, ready};
use tokio::net::unix::OwnedWriteHalf;
use tokio_util::codec::{FramedRead, FramedWrite};

use super::codec::{Frame, PipeCodec};
use crate::{
    quic::{GetStreamId, StopStream, StreamError},
    util::set_once::SetOnce,
    varint::VarInt,
};

/// Read half of a per-stream pipe.
///
/// Reads DATA/CANCEL/CONN_CLOSED frames from the socketpair.
/// Sends STOP frames back through the write half of the same socketpair.
pub struct PipeReader {
    stream_id: VarInt,
    read: FramedRead<tokio::net::unix::OwnedReadHalf, PipeCodec>,
    write: FramedWrite<OwnedWriteHalf, PipeCodec>,
    terminal_error: SetOnce<crate::quic::ConnectionError>,
    state: ReaderState,
}

enum ReaderState {
    /// Normal operation — reading DATA frames.
    Active,
    /// Connection closed — return terminal error on subsequent polls.
    ConnClosed,
    /// Stream ended (EOF or after CANCEL).
    Finished,
}

impl PipeReader {
    /// Create a new reader from the two halves of a `tokio::net::UnixStream`.
    pub fn new(
        stream_id: VarInt,
        read_half: tokio::net::unix::OwnedReadHalf,
        write_half: OwnedWriteHalf,
        terminal_error: SetOnce<crate::quic::ConnectionError>,
    ) -> Self {
        Self {
            stream_id,
            read: FramedRead::new(read_half, PipeCodec::new()),
            write: FramedWrite::new(write_half, PipeCodec::new()),
            terminal_error,
            state: ReaderState::Active,
        }
    }

    /// Return the latched connection error if available, otherwise a
    /// synthetic application error.
    fn connection_error(&self) -> StreamError {
        StreamError::Connection {
            source: super::connection_error_or_fallback(&self.terminal_error, "connection closed"),
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
        let this = self.get_mut();
        match this.state {
            ReaderState::ConnClosed => Poll::Ready(Some(Err(this.connection_error()))),
            ReaderState::Finished => Poll::Ready(None),
            ReaderState::Active => {
                match ready!(Pin::new(&mut this.read).poll_next(cx)) {
                    Some(Ok(Frame::Data(data))) => Poll::Ready(Some(Ok(data))),
                    Some(Ok(Frame::Cancel(code))) => {
                        this.state = ReaderState::Finished;
                        Poll::Ready(Some(Err(StreamError::Reset { code })))
                    }
                    Some(Ok(Frame::ConnClosed)) => {
                        this.state = ReaderState::ConnClosed;
                        Poll::Ready(Some(Err(this.connection_error())))
                    }
                    Some(Ok(Frame::Stop(_))) => {
                        // STOP on a reader is a protocol error — ignore gracefully.
                        // Wake again to read the next frame.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Some(Err(codec_err)) => {
                        tracing::debug!(%codec_err, "pipe codec error on reader");
                        this.state = ReaderState::Finished;
                        // Check if this is a connection-level error.
                        if let Some(conn_err) = this.terminal_error.peek() {
                            Poll::Ready(Some(Err(StreamError::Connection { source: conn_err })))
                        } else {
                            Poll::Ready(None)
                        }
                    }
                    None => {
                        // EOF — check for connection error first.
                        this.state = ReaderState::Finished;
                        if let Some(conn_err) = this.terminal_error.peek() {
                            Poll::Ready(Some(Err(StreamError::Connection { source: conn_err })))
                        } else {
                            Poll::Ready(None)
                        }
                    }
                }
            }
        }
    }
}

impl StopStream for PipeReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();
        ready!(
            Pin::new(&mut this.write)
                .poll_ready(cx)
                .map_err(|codec_err| {
                    tracing::debug!(%codec_err, "pipe codec error sending STOP (poll_ready)");
                    StreamError::Connection {
                        source: super::connection_error_or_fallback(
                            &this.terminal_error,
                            "pipe broken",
                        ),
                    }
                })?
        );
        Pin::new(&mut this.write)
            .start_send(Frame::Stop(code))
            .map_err(|codec_err| {
                tracing::debug!(%codec_err, "pipe codec error sending STOP (start_send)");
                StreamError::Connection {
                    source: super::connection_error_or_fallback(
                        &this.terminal_error,
                        "pipe broken",
                    ),
                }
            })?;
        Poll::Ready(Ok(()))
    }
}
