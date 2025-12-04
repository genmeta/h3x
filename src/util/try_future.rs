use std::{
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{Sink, Stream};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    quic::{self, CancelStream, GetStreamId, StopStream},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// A lazily opened stream.
    #[project = TryFutureProj]
    #[project_ref = TryFutureProjRef]
    pub enum TryFuture<T, E, F> {
        Future { #[pin] future: F },
        Stream { #[pin] stream: T },
        Error { error: E },
    }
}

impl<S, E, F: Future<Output = Result<S, E>>> From<F> for TryFuture<S, E, F> {
    fn from(future: F) -> Self {
        TryFuture::Future { future }
    }
}

impl<T, E, F> TryFuture<T, E, F> {
    fn poll<'s>(
        mut self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&'s mut T>, E>>
    where
        F: Future<Output = Result<T, E>>,
        E: Clone,
    {
        match self.as_mut().project() {
            TryFutureProj::Future { future, .. } => {
                match ready!(future.poll(cx)) {
                    Ok(stream) => self.set(TryFuture::Stream { stream }),
                    Err(error) => self.set(TryFuture::Error { error }),
                };
                self.poll(cx)
            }
            TryFutureProj::Stream { .. } | TryFutureProj::Error { .. } => {
                // as_mut() returns short-lived Pin<&mut Self>, so we need to re-project without as_mut()
                Poll::Ready(self.try_peek_mut().unwrap())
            }
        }
    }

    fn try_peek_mut(self: Pin<&mut Self>) -> Option<Result<Pin<&mut T>, E>>
    where
        E: Clone,
    {
        match self.project() {
            TryFutureProj::Future { .. } => None,
            TryFutureProj::Stream { stream } => Some(Ok(stream)),
            TryFutureProj::Error { error } => Some(Err(error.clone())),
        }
    }
}

impl<T, E, F> Future for TryFuture<T, E, F>
where
    F: Future<Output = Result<T, E>>,
    T: Clone,
    E: Clone,
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        TryFuture::poll(self, cx).map(|result| result.map(|t| t.clone()))
    }
}

impl<S, E, F> GetStreamId for TryFuture<S, E, F>
where
    S: GetStreamId,
    E: Clone,
    quic::StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        ready!(self.poll(cx)?).poll_stream_id(cx)
    }
}

impl<S, E, F> StopStream for TryFuture<S, E, F>
where
    S: StopStream,
    E: Clone,
    quic::StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        ready!(self.poll(cx)?).poll_stop(cx, code)
    }
}

impl<S, E, F> AsyncRead for TryFuture<S, E, F>
where
    S: AsyncRead,
    E: Clone,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll(cx)?).poll_read(cx, buf)
    }
}

impl<R, E, F> AsyncBufRead for TryFuture<R, E, F>
where
    R: AsyncBufRead,
    E: Clone + Debug,
    io::Error: From<E>,
    F: Future<Output = Result<R, E>>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        ready!(self.poll(cx)?).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.try_peek_mut()
            .expect("consume before read")
            .expect("consume on error")
            .consume(amt);
    }
}

impl<S, E, F, Item, SE> Stream for TryFuture<S, E, F>
where
    S: Stream<Item = Result<Item, SE>>,
    E: Clone,
    SE: From<E>,
    F: Future<Output = Result<S, E>>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        ready!(self.poll(cx)?).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<S, E, F> CancelStream for TryFuture<S, E, F>
where
    S: CancelStream,
    E: Clone,
    quic::StreamError: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        ready!(self.poll(cx)?).poll_cancel(cx, code)
    }
}

impl<W, E, F> AsyncWrite for TryFuture<W, E, F>
where
    W: AsyncWrite,
    E: Clone,
    io::Error: From<E>,
    F: Future<Output = Result<W, E>>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll(cx)?).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll(cx)?).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll(cx)?).poll_shutdown(cx)
    }
}

impl<E, W, F, Item> Sink<Item> for TryFuture<W, E, F>
where
    W: Sink<Item>,
    E: Clone,
    W::Error: From<E>,
    F: Future<Output = Result<W, E>>,
{
    type Error = W::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        ready!(self.poll(cx)?).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), W::Error> {
        self.try_peek_mut()
            .expect("start_send before poll_ready completed")?
            .start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        ready!(self.poll(cx)?).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        ready!(self.poll(cx)?).poll_close(cx)
    }
}
