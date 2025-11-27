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
    #[project = FutureStreamProj]
    #[project_ref = FutureStreamProjRef]
    pub enum TryFutureStream<S, E, F> {
        Future { #[pin] future: F },
        Stream { #[pin] stream: S },
        Error { error: E },
    }
}

impl<S, E, F: Future<Output = Result<S, E>>> From<F> for TryFutureStream<S, E, F> {
    fn from(future: F) -> Self {
        TryFutureStream::Future { future }
    }
}

impl<S, E, F> TryFutureStream<S, E, F> {
    fn poll_try_stream<'s>(
        mut self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&'s mut S>, E>>
    where
        F: Future<Output = Result<S, E>>,
        E: Clone,
    {
        match self.as_mut().project() {
            FutureStreamProj::Future { future, .. } => {
                match ready!(future.poll(cx)) {
                    Ok(stream) => self.set(TryFutureStream::Stream { stream }),
                    Err(error) => self.set(TryFutureStream::Error { error }),
                };
                self.poll_try_stream(cx)
            }
            FutureStreamProj::Stream { .. } | FutureStreamProj::Error { .. } => {
                // as_mut() returns short-lived Pin<&mut Self>, so we need to re-project without as_mut()
                Poll::Ready(self.pin_stream_mut().unwrap())
            }
        }
    }

    fn pin_stream_mut(self: Pin<&mut Self>) -> Option<Result<Pin<&mut S>, E>>
    where
        E: Clone,
    {
        match self.project() {
            FutureStreamProj::Future { .. } => None,
            FutureStreamProj::Stream { stream } => Some(Ok(stream)),
            FutureStreamProj::Error { error } => Some(Err(error.clone())),
        }
    }
}

impl<S, E, F> GetStreamId for TryFutureStream<S, E, F>
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
        ready!(self.poll_try_stream(cx)?).poll_stream_id(cx)
    }
}

impl<S, E, F> StopStream for TryFutureStream<S, E, F>
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
        ready!(self.poll_try_stream(cx)?).poll_stop(cx, code)
    }
}

impl<S, E, F> AsyncRead for TryFutureStream<S, E, F>
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
        ready!(self.poll_try_stream(cx)?).poll_read(cx, buf)
    }
}

impl<S, E, F> AsyncBufRead for TryFutureStream<S, E, F>
where
    S: AsyncBufRead,
    E: Clone + Debug,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        ready!(self.poll_try_stream(cx)?).poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.pin_stream_mut()
            .expect("consume before read")
            .expect("consume on error")
            .consume(amt);
    }
}

impl<S, E, F, T, SE> Stream for TryFutureStream<S, E, F>
where
    S: Stream<Item = Result<T, SE>>,
    E: Clone,
    SE: From<E>,
    F: Future<Output = Result<S, E>>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        ready!(self.poll_try_stream(cx)?).poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<S, E, F> CancelStream for TryFutureStream<S, E, F>
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
        ready!(self.poll_try_stream(cx)?).poll_cancel(cx, code)
    }
}

impl<S, E, F> AsyncWrite for TryFutureStream<S, E, F>
where
    S: AsyncWrite,
    E: Clone,
    io::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_try_stream(cx)?).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_try_stream(cx)?).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_try_stream(cx)?).poll_shutdown(cx)
    }
}

impl<E, S, F, T> Sink<T> for TryFutureStream<S, E, F>
where
    S: Sink<T>,
    E: Clone,
    S::Error: From<E>,
    F: Future<Output = Result<S, E>>,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), S::Error> {
        self.pin_stream_mut()
            .expect("start_send before poll_ready completed")?
            .start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        ready!(self.poll_try_stream(cx)?).poll_close(cx)
    }
}
