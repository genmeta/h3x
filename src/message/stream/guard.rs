use std::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream};
use tracing::Instrument;

use crate::{
    codec::{BoxReadStream, BoxWriteStream},
    error::Code,
    quic::{self, CancelStreamExt, StopStreamExt},
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// Sentinel — panics if the stream is used after take / drop
// ---------------------------------------------------------------------------

struct DroppedStream;

fn stream_used_after_dropped() -> ! {
    panic!("guarded QUIC stream used after being taken or dropped, this is a bug")
}

impl Stream for DroppedStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        stream_used_after_dropped()
    }
}

impl Sink<Bytes> for DroppedStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        stream_used_after_dropped()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }
}

impl quic::CancelStream for DroppedStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::StopStream for DroppedStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::GetStreamId for DroppedStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        stream_used_after_dropped()
    }
}

fn dropped_reader() -> BoxReadStream {
    Box::pin(DroppedStream)
}

fn dropped_writer() -> BoxWriteStream {
    Box::pin(DroppedStream)
}

// ---------------------------------------------------------------------------
// GuardedQuicReader
// ---------------------------------------------------------------------------

/// A QUIC read stream wrapper that automatically stops the stream on drop
/// if it hasn't been fully consumed (EOF) or explicitly stopped.
pub struct GuardedQuicReader {
    inner: BoxReadStream,
    completed: bool,
}

impl GuardedQuicReader {
    pub fn new(inner: BoxReadStream) -> Self {
        Self {
            inner,
            completed: false,
        }
    }

    /// Take the inner stream, replacing it with a sentinel.
    /// Marks this guard as completed (no cleanup on drop).
    pub fn take(&mut self) -> Self {
        let inner = mem::replace(&mut self.inner, dropped_reader());
        let completed = self.completed;
        self.completed = true;
        Self { inner, completed }
    }
}

impl Stream for GuardedQuicReader {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(None) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::StopStream for GuardedQuicReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_stop(cx, code);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::GetStreamId for GuardedQuicReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.get_mut().inner.as_mut().poll_stream_id(cx)
    }
}

impl Drop for GuardedQuicReader {
    fn drop(&mut self) {
        if !self.completed {
            let mut inner = mem::replace(&mut self.inner, dropped_reader());
            tokio::spawn(
                async move {
                    _ = inner.stop(Code::H3_NO_ERROR.into()).await;
                }
                .in_current_span(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// GuardedQuicWriter
// ---------------------------------------------------------------------------

/// A QUIC write stream wrapper that automatically cancels the stream on drop
/// if it hasn't been properly closed or explicitly cancelled.
pub struct GuardedQuicWriter {
    inner: BoxWriteStream,
    completed: bool,
}

impl GuardedQuicWriter {
    pub fn new(inner: BoxWriteStream) -> Self {
        Self {
            inner,
            completed: false,
        }
    }

    /// Take the inner stream, replacing it with a sentinel.
    /// Marks this guard as completed (no cleanup on drop).
    pub fn take(&mut self) -> Self {
        let inner = mem::replace(&mut self.inner, dropped_writer());
        let completed = self.completed;
        self.completed = true;
        Self { inner, completed }
    }
}

impl Sink<Bytes> for GuardedQuicWriter {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.as_mut().poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.get_mut().inner.as_mut().start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_close(cx);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::CancelStream for GuardedQuicWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_cancel(cx, code);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::GetStreamId for GuardedQuicWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.get_mut().inner.as_mut().poll_stream_id(cx)
    }
}

impl Drop for GuardedQuicWriter {
    fn drop(&mut self) {
        if !self.completed {
            let mut inner = mem::replace(&mut self.inner, dropped_writer());
            tokio::spawn(
                async move {
                    _ = inner.cancel(Code::H3_NO_ERROR.into()).await;
                }
                .in_current_span(),
            );
        }
    }
}
