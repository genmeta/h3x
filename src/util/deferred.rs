//! Lazy stream resolution with two-phase state: [`Resolved`] and [`Deferred`].
//!
//! [`Resolved`] represents a stream that has already been resolved to either a
//! concrete value or an error.  It implements all the standard stream and I/O
//! traits (AsyncRead, AsyncWrite, Stream, Sink, etc.) by delegating to the
//! inner value on success or returning the error on failure.
//!
//! [`Deferred`] wraps a future that resolves to a `Result<T, E>`.  While the
//! future is pending, trait method calls drive it to completion; once resolved,
//! it transitions to a [`Resolved`] state and delegates all further calls.

use std::{
    fmt::Debug,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures::{Sink, Stream, stream::FusedStream};
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

use crate::{quic, varint::VarInt};

// ============================================================================
// Resolved<T, E>
// ============================================================================

pin_project_lite::pin_project! {
    /// A stream that has been resolved to either a value or an error.
    ///
    /// All I/O trait implementations delegate to the inner value on `Value`,
    /// or return an appropriate error on `Error`.
    #[project = ResolvedProj]
    pub enum Resolved<T, E> {
        /// The stream resolved successfully.
        Value { #[pin] value: T },
        /// The stream resolved with an error.
        Error { error: E },
    }
}

impl<T, E> Resolved<T, E> {
    /// Construct a successful resolution.
    pub fn ok(value: T) -> Self {
        Resolved::Value { value }
    }

    /// Construct an error resolution.
    pub fn err(error: E) -> Self {
        Resolved::Error { error }
    }

    /// Convert into a `Result<T, E>`.
    #[allow(dead_code)]
    pub fn into_result(self) -> Result<T, E> {
        match self {
            Resolved::Value { value } => Ok(value),
            Resolved::Error { error } => Err(error),
        }
    }

    /// Access the inner value if resolved successfully, returning the error
    /// otherwise.
    fn poll_inner(self: Pin<&mut Self>) -> Result<Pin<&mut T>, E>
    where
        E: Clone,
    {
        match self.project() {
            ResolvedProj::Value { value } => Ok(value),
            ResolvedProj::Error { error } => Err(error.clone()),
        }
    }
}

impl<T, E> From<Result<T, E>> for Resolved<T, E> {
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Resolved::ok(value),
            Err(error) => Resolved::err(error),
        }
    }
}

// ---------------------------------------------------------------------------
// Serde: serialize/deserialize via Result<T, E> proxy
// ---------------------------------------------------------------------------

#[cfg(feature = "serde")]
impl<T, E> serde::Serialize for Resolved<T, E>
where
    T: serde::Serialize,
    E: serde::Serialize,
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Resolved::Value { value } => Result::<&T, &E>::Ok(value).serialize(serializer),
            Resolved::Error { error } => Result::<&T, &E>::Err(error).serialize(serializer),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, T, E> serde::Deserialize<'de> for Resolved<T, E>
where
    T: serde::Deserialize<'de>,
    E: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Result::<T, E>::deserialize(deserializer).map(Resolved::from)
    }
}

impl<S, E> quic::GetStreamId for Resolved<S, E>
where
    S: quic::GetStreamId,
    E: Clone,
    quic::StreamError: From<E>,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.poll_inner()?.poll_stream_id(cx)
    }
}

impl<S, E> quic::StopStream for Resolved<S, E>
where
    S: quic::StopStream,
    E: Clone,
    quic::StreamError: From<E>,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.poll_inner()?.poll_stop(cx, code)
    }
}

impl<S, E> quic::CancelStream for Resolved<S, E>
where
    S: quic::CancelStream,
    E: Clone,
    quic::StreamError: From<E>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.poll_inner()?.poll_cancel(cx, code)
    }
}

impl<S, E> AsyncRead for Resolved<S, E>
where
    S: AsyncRead,
    E: Clone,
    io::Error: From<E>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_inner()?.poll_read(cx, buf)
    }
}

impl<R, E> AsyncBufRead for Resolved<R, E>
where
    R: AsyncBufRead,
    E: Clone + Debug,
    io::Error: From<E>,
{
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        self.poll_inner()?.poll_fill_buf(cx)
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        self.poll_inner().expect("consume on error").consume(amt);
    }
}

impl<W, E> AsyncWrite for Resolved<W, E>
where
    W: AsyncWrite,
    E: Clone,
    io::Error: From<E>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_inner()?.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_inner()?.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_inner()?.poll_shutdown(cx)
    }
}

impl<S, E, Item, SE> Stream for Resolved<S, E>
where
    S: Stream<Item = Result<Item, SE>>,
    E: Clone,
    SE: From<E>,
{
    type Item = S::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.poll_inner() {
            Ok(inner) => inner.poll_next(cx),
            Err(e) => Poll::Ready(Some(Err(SE::from(e)))),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Resolved::Value { value } => value.size_hint(),
            Resolved::Error { .. } => (0, None),
        }
    }
}

impl<S, E, Item, SE> FusedStream for Resolved<S, E>
where
    S: FusedStream<Item = Result<Item, SE>>,
    E: Clone,
    SE: From<E>,
{
    fn is_terminated(&self) -> bool {
        match self {
            Resolved::Value { value } => value.is_terminated(),
            Resolved::Error { .. } => true,
        }
    }
}

impl<E, W, Item> Sink<Item> for Resolved<W, E>
where
    W: Sink<Item>,
    E: Clone,
    W::Error: From<E>,
{
    type Error = W::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        self.poll_inner()?.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), W::Error> {
        self.poll_inner()?.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        self.poll_inner()?.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), W::Error>> {
        self.poll_inner()?.poll_close(cx)
    }
}

// ============================================================================
// Deferred<T, E, F>
// ============================================================================

pin_project_lite::pin_project! {
    /// A lazily opened stream.
    ///
    /// Wraps a future that resolves to `Result<T, E>`.  While the future is
    /// pending, trait method calls drive it to completion; once resolved,
    /// the enum transitions to `Ready` and delegates all calls to the inner
    /// [`Resolved`].
    #[project = DeferredProj]
    pub enum Deferred<T, E, F> {
        /// The opening future has not yet completed.
        Pending { #[pin] future: F },
        /// The future has completed — the result is stored in a [`Resolved`].
        Ready { #[pin] resolved: Resolved<T, E> },
    }
}

impl<S, E, F: Future<Output = Result<S, E>>> From<F> for Deferred<S, E, F> {
    fn from(future: F) -> Self {
        Deferred::Pending { future }
    }
}

impl<T, E, F> Deferred<T, E, F> {
    fn poll<'s>(
        mut self: Pin<&'s mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Pin<&'s mut T>, E>>
    where
        F: Future<Output = Result<T, E>>,
        E: Clone,
    {
        // Phase 1: resolve pending future (projection borrow scoped to match)
        let resolved = match self.as_mut().project() {
            DeferredProj::Pending { future } => Some(ready!(future.poll(cx))),
            DeferredProj::Ready { .. } => None,
        };
        // Phase 2: transition to Ready if just resolved
        if let Some(result) = resolved {
            self.as_mut().set(match result {
                Ok(value) => Deferred::Ready {
                    resolved: Resolved::ok(value),
                },
                Err(error) => Deferred::Ready {
                    resolved: Resolved::err(error),
                },
            });
        }
        // Phase 3: delegate to Resolved (consumes the Pin for full lifetime)
        match self.project() {
            DeferredProj::Ready { resolved } => Poll::Ready(resolved.poll_inner()),
            DeferredProj::Pending { .. } => unreachable!(),
        }
    }

    fn try_peek_mut(self: Pin<&mut Self>) -> Option<Result<Pin<&mut T>, E>>
    where
        E: Clone,
    {
        match self.project() {
            DeferredProj::Pending { .. } => None,
            DeferredProj::Ready { resolved } => Some(resolved.poll_inner()),
        }
    }
}

impl<T, E, F> Future for Deferred<T, E, F>
where
    F: Future<Output = Result<T, E>>,
    T: Clone,
    E: Clone,
{
    type Output = Result<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Deferred::poll(self, cx).map(|result| result.map(|t| t.clone()))
    }
}

impl<S, E, F> quic::GetStreamId for Deferred<S, E, F>
where
    S: quic::GetStreamId,
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

impl<S, E, F> quic::StopStream for Deferred<S, E, F>
where
    S: quic::StopStream,
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

impl<S, E, F> quic::CancelStream for Deferred<S, E, F>
where
    S: quic::CancelStream,
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

impl<S, E, F> AsyncRead for Deferred<S, E, F>
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

impl<R, E, F> AsyncBufRead for Deferred<R, E, F>
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

impl<S, E, F, Item, SE> Stream for Deferred<S, E, F>
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

impl<S, E, F, Item, SE> FusedStream for Deferred<S, E, F>
where
    S: FusedStream<Item = Result<Item, SE>>,
    E: Clone,
    SE: From<E>,
    F: Future<Output = Result<S, E>>,
{
    fn is_terminated(&self) -> bool {
        match self {
            Deferred::Pending { .. } => false,
            Deferred::Ready { resolved } => resolved.is_terminated(),
        }
    }
}

impl<W, E, F> AsyncWrite for Deferred<W, E, F>
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

impl<E, W, F, Item> Sink<Item> for Deferred<W, E, F>
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
