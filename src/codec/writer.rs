use std::{
    future::poll_fn,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, Bytes};
use futures::{Sink, Stream, StreamExt};
use tokio::io::{self, AsyncWrite};

use crate::{
    error::StreamError,
    quic::{CancelStream, GetStreamId},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Sink writer that support both [`Sink`] and [`AsyncWrite`] interface.
    ///
    /// Be different from [`SinkWriter`] in [`tokio-util`], this writer will buffer
    /// data written by `AsyncWrite` interface, and you may need to call [`Self::poll_flush_buffer`]
    /// or [`Self::flush_buffer`] to flush the buffer to the underlying sink.
    ///
    /// [`SinkWriter`]: tokio_util::io::SinkWriter
    pub struct SinkWriter<S: ?Sized> {
        buffer: Bytes,
        #[pin]
        stream: S,
    }
}

impl<S> SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
{
    pub const fn new(stream: S) -> Self
    where
        S: Sized,
    {
        Self {
            stream,
            buffer: Bytes::new(),
        }
    }

    pub fn poll_flush_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        let mut project = self.as_mut().project();
        while !project.buffer.is_empty() {
            ready!(project.stream.as_mut().poll_ready(cx)?);
            let bytes = mem::take(project.buffer);
            project.stream.as_mut().start_send(bytes)?;
        }
        Poll::Ready(Ok(()))
    }

    pub async fn flush_buffer(mut self: Pin<&mut Self>) -> Result<(), S::Error> {
        poll_fn(|cx| self.as_mut().poll_flush_buffer(cx)).await
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.stream
    }
}

impl<S> Sink<Bytes> for SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_buffer(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        debug_assert!(
            project.buffer.is_empty(),
            "poll_ready must be called before start_send"
        );
        *project.buffer = item;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // ready!(self.as_mut().poll_flush_buffer(cx)?);
        // self.project().stream.poll_flush(cx)
        self.poll_flush_buffer(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        self.project().stream.poll_close(cx)
    }
}

impl<S> AsyncWrite for SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
    io::Error: From<S::Error>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let project = self.as_mut().project();

        // optimize: try to write into the internal buffer without flushing
        if project.buffer.len() + buf.len() < 8 * 1024 {
            match mem::take(project.buffer).try_into_mut() {
                Ok(mut bytes_mut) => {
                    bytes_mut.put(buf);
                    *project.buffer = bytes_mut.freeze();
                    return Poll::Ready(Ok(buf.len()));
                }
                Err(bytes) => {
                    *project.buffer = bytes;
                }
            }
        }
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        *self.project().buffer = Bytes::copy_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(self, cx).map_err(io::Error::from)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_close(self, cx).map_err(io::Error::from)
    }
}

impl<S: CancelStream + ?Sized> CancelStream for SinkWriter<S> {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().stream.poll_cancel(cx, code)
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for SinkWriter<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().stream.poll_stream_id(cx)
    }
}

pin_project_lite::pin_project! {
    /// A sink wrapper that guaranteed once `poll_ready` returns `Ready`, the item will not lost.
    pub struct Feed<S, T> {
        item: Option<T>,
        #[pin]
        stream: S,
    }
}

impl<S, T> Feed<S, T>
where
    S: Sink<T>,
{
    pub const fn new(stream: S) -> Self {
        Self { stream, item: None }
    }

    pub async fn ready(self: Pin<&mut Self>) -> Result<(), S::Error> {
        let mut project = self.project();
        poll_fn(|cx| project.stream.as_mut().poll_ready(cx)).await
    }

    pub async fn send_all(
        mut self: Pin<&mut Self>,
        items: impl Stream<Item = T>,
    ) -> Result<(), S::Error> {
        tokio::pin!(items);
        loop {
            self.as_mut().ready().await?;
            match items.next().await {
                Some(item) => self.as_mut().start_send(item)?,
                None => break,
            }
        }
        Ok(())
    }
}

impl<S, T> Sink<T> for Feed<S, T>
where
    S: Sink<T>,
{
    type Error = S::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.as_mut().project();
        while project.item.is_some() {
            ready!(project.stream.as_mut().poll_ready(cx)?);
            let item = project.item.take().expect("item is Some");
            project.stream.as_mut().start_send(item)?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let project = self.project();
        assert!(
            project.item.is_none(),
            "start_send called before poll_ready"
        );
        *project.item = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx)?);
        self.project().stream.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx)?);
        self.project().stream.poll_close(cx)
    }
}
