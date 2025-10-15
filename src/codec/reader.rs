use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::Stream;
use tokio::io::{self, AsyncBufRead, AsyncRead, ReadBuf};

pin_project_lite::pin_project! {
    /// Stream reader that support both [`Stream`] and [`AsyncRead`] interface.
    pub struct StreamReader<S> {
        #[pin]
        stream: S,
        chunk: Bytes,
    }
}

impl<S, E> StreamReader<S>
where
    S: Stream<Item = Result<Bytes, E>>,
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
    ) -> Poll<Option<Result<Bytes, E>>> {
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
    ) -> Poll<Option<Result<Bytes, E>>> {
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

impl<S, E> Stream for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_consume_chunk(cx, None)
    }
}

impl<S, E> AsyncRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, E>>,
    io::Error: From<E>,
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

impl<S, E> AsyncBufRead for StreamReader<S>
where
    S: Stream<Item = Result<Bytes, E>>,
    io::Error: From<E>,
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
