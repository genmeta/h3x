use std::{
    error::Error,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures::Stream;
use snafu::Snafu;
use tokio::io::{self, ReadBuf};

use crate::error::StreamError;

pin_project_lite::pin_project! {
    /// Stream reader that support both [`Stream`] and [`AsyncRead`] interface.
    pub struct StreamReader<S> {
        #[pin]
        stream: S,
        chunk: Bytes,
    }
}

impl<S> StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            chunk: Bytes::new(),
        }
    }

    /// Poll a chunk of data from the stream without consuming it.
    ///
    /// If `cap` is `Some`, it will return at most `cap` bytes.
    pub fn poll_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        cap: Option<usize>,
    ) -> Poll<Option<Result<Bytes, StreamError>>> {
        let mut project = self.as_mut().project();
        while project.chunk.is_empty() {
            *project.chunk = match ready!(project.stream.as_mut().poll_next(cx)?) {
                Some(chunk) => chunk,
                None => return Poll::Ready(None),
            };
        }

        let at = match cap {
            Some(0) => return Poll::Ready(None),
            Some(cap) => cap.min(project.chunk.len()),
            None => project.chunk.len(),
        };
        Poll::Ready(Some(Ok(project.chunk.slice(..at))))
    }

    /// Poll a chunk of data from the stream and consume it.
    ///
    /// If `cap` is `Some`, it will return at most `cap` bytes.
    pub fn poll_consume_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        cap: Option<usize>,
    ) -> Poll<Option<Result<Bytes, StreamError>>> {
        let chunk = self.as_mut().poll_chunk(cx, cap);
        if let Poll::Ready(Some(Ok(chunk))) = &chunk {
            self.consume(chunk.len());
        }
        chunk
    }

    pub fn consume(mut self: Pin<&mut Self>, amt: usize) {
        _ = self.as_mut().project().chunk.split_to(amt);
    }
}

impl<S> Stream for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_consume_chunk(cx, None)
    }
}

impl<S> tokio::io::AsyncRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let chunk = match ready!(self.poll_consume_chunk(cx, Some(buf.remaining()))?) {
            Some(chunk) => chunk,
            None => return Poll::Ready(Ok(())),
        };
        buf.put_slice(&chunk);

        Poll::Ready(Ok(()))
    }
}

impl<S> tokio::io::AsyncBufRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        // Ensure we have some data in the chunk
        if ready!(self.as_mut().poll_chunk(cx, None)?).is_none() {
            return Poll::Ready(Ok(&[]));
        }

        // Note: slice to avoid auto-deref makes local borrow checker unhappy
        Poll::Ready(Ok(&self.project().chunk[..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        StreamReader::consume(self, amt);
    }
}

impl<S> futures::io::AsyncRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut chunk = match ready!(self.poll_consume_chunk(cx, Some(buf.len()))?) {
            Some(chunk) => chunk,
            None => return Poll::Ready(Ok(0)),
        };
        chunk.copy_to_slice(&mut buf[..chunk.len()]);
        debug_assert!(chunk.is_empty(), "all data in chunk should be consumed");
        Poll::Ready(Ok(chunk.len()))
    }
}

impl<S> futures::io::AsyncBufRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, StreamError>>,
{
    fn poll_fill_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        // Ensure we have some data in the chunk
        if ready!(self.as_mut().poll_chunk(cx, None)?).is_none() {
            return Poll::Ready(Ok(&[]));
        }

        // Note: slice to avoid auto-deref makes local borrow checker unhappy
        Poll::Ready(Ok(&self.project().chunk[..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        StreamReader::consume(self, amt);
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum DecodeStreamError<E: Error + 'static> {
    #[snafu(display("Stream error"))]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Custom { source: E },
}

impl<E: Error + 'static> DecodeStreamError<E> {
    pub fn from_io_error(source: io::Error) -> Self
    where
        E: Send + Sync,
    {
        match source.downcast::<StreamError>() {
            Ok(source) => DecodeStreamError::Stream { source },
            Err(source) => match source.downcast::<E>() {
                Ok(source) => DecodeStreamError::Custom { source },
                Err(_source) => unreachable!("io::Error is not from StreamReader nor custom error"),
            },
        }
    }

    pub fn map_err<E2>(self, f: impl FnOnce(E) -> E2) -> DecodeStreamError<E2>
    where
        E2: Error + 'static,
    {
        match self {
            DecodeStreamError::Stream { source } => DecodeStreamError::Stream { source },
            DecodeStreamError::Custom { source } => DecodeStreamError::Custom { source: f(source) },
        }
    }
}
