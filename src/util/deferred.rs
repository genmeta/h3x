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
    collections::VecDeque,
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

impl<S, E> quic::ResetStream for Resolved<S, E>
where
    S: quic::ResetStream,
    E: Clone,
    quic::StreamError: From<E>,
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.poll_inner()?.poll_reset(cx, code)
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
    /// A lazy value adapter.
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

pin_project_lite::pin_project! {
    /// Stream-specific lazy reader wrapper that remembers committed receive-side controls.
    ///
    /// The generic [`Deferred`] wrapper remains a plain lazy value adapter. This
    /// type adds read-stream semantics on top: `poll_stop` records a committed
    /// STOP_SENDING request even while the opening future is still pending, then
    /// applies it before later reads once the stream exists.
    pub struct DeferredStreamReader<InnerStream, Error, OpenFuture> {
        #[pin]
        inner: Deferred<InnerStream, Error, OpenFuture>,
        pending_stop: Option<VarInt>,
        cached_id: Option<VarInt>,
    }
}

impl<InnerStream, Error, OpenFuture> DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    /// Wrap an opening future without a known stream id.
    pub fn new(open: OpenFuture) -> Self {
        Self {
            inner: Deferred::from(open),
            pending_stop: None,
            cached_id: None,
        }
    }
}

impl<InnerStream, Error, OpenFuture> From<OpenFuture>
    for DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn from(open: OpenFuture) -> Self {
        Self::new(open)
    }
}

pin_project_lite::pin_project! {
    /// Stream-specific lazy writer wrapper that remembers committed send-side controls.
    ///
    /// The wrapper records reset, flush, and close operations that are first
    /// polled before the opening future resolves. After resolution it drains
    /// those operations before accepting new data.
    pub struct DeferredStreamWriter<InnerStream, Error, OpenFuture> {
        #[pin]
        inner: Deferred<InnerStream, Error, OpenFuture>,
        pending: PendingWriteQueue,
        cached_id: Option<VarInt>,
    }
}

impl<InnerStream, Error, OpenFuture> DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    /// Wrap an opening future without a known stream id.
    pub fn new(open: OpenFuture) -> Self {
        Self {
            inner: Deferred::from(open),
            pending: PendingWriteQueue::default(),
            cached_id: None,
        }
    }
}

impl<InnerStream, Error, OpenFuture> From<OpenFuture>
    for DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn from(open: OpenFuture) -> Self {
        Self::new(open)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PendingWriteOp {
    Reset(VarInt),
    Flush,
    Close,
}

#[derive(Debug, Default)]
struct PendingWriteQueue {
    ops: VecDeque<PendingWriteOp>,
}

impl PendingWriteQueue {
    fn contains_reset(&self) -> bool {
        matches!(self.ops.front(), Some(PendingWriteOp::Reset(_)))
    }

    fn contains_flush(&self) -> bool {
        self.ops.contains(&PendingWriteOp::Flush)
    }

    fn contains_close(&self) -> bool {
        self.ops.contains(&PendingWriteOp::Close)
    }

    fn contains_kind(&self, op: PendingWriteOp) -> bool {
        match op {
            PendingWriteOp::Reset(_) => self.contains_reset(),
            PendingWriteOp::Flush => self.contains_flush(),
            PendingWriteOp::Close => self.contains_close(),
        }
    }

    fn enqueue_reset(&mut self, code: VarInt) {
        if !self.contains_reset() {
            self.ops.clear();
            self.ops.push_back(PendingWriteOp::Reset(code));
        }
    }

    fn enqueue_flush(&mut self) {
        if !self.contains_reset() && !self.contains_flush() {
            self.ops.push_back(PendingWriteOp::Flush);
        }
    }

    fn enqueue_close(&mut self) {
        if !self.contains_reset() && !self.contains_close() {
            self.ops.push_back(PendingWriteOp::Close);
        }
    }

    fn front(&self) -> Option<PendingWriteOp> {
        self.ops.front().copied()
    }

    fn pop_front(&mut self) {
        self.ops.pop_front();
    }

    fn is_empty(&self) -> bool {
        self.ops.is_empty()
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

impl<InnerStream, Error, OpenFuture> quic::GetStreamId
    for DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::GetStreamId,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_stream_id(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        if let Some(stream_id) = self.as_mut().project().cached_id.as_ref().copied() {
            return Poll::Ready(Ok(stream_id));
        }

        let stream_id = {
            let project = self.as_mut().project();
            let stream = match ready!(project.inner.poll(cx)) {
                Ok(stream) => stream,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            ready!(stream.poll_stream_id(cx))?
        };
        *self.as_mut().project().cached_id = Some(stream_id);
        Poll::Ready(Ok(stream_id))
    }
}

impl<InnerStream, Error, OpenFuture> quic::StopStream
    for DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::StopStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        if self.as_mut().project().pending_stop.is_none() {
            *self.as_mut().project().pending_stop = Some(code);
        }
        let code = self
            .as_mut()
            .project()
            .pending_stop
            .expect("pending stop code should be present");

        let result = {
            let project = self.as_mut().project();
            let stream = match ready!(project.inner.poll(cx)) {
                Ok(stream) => stream,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            ready!(stream.poll_stop(cx, code))
        };
        *self.as_mut().project().pending_stop = None;
        Poll::Ready(result)
    }
}

impl<InnerStream, Error, OpenFuture, Item, StreamItemError> futures::Stream
    for DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    InnerStream: futures::Stream<Item = Result<Item, StreamItemError>> + quic::StopStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    StreamItemError: From<Error> + From<quic::StreamError>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    type Item = InnerStream::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(code) = self.as_mut().project().pending_stop.as_ref().copied()
            && let Err(error) = ready!(quic::StopStream::poll_stop(self.as_mut(), cx, code))
        {
            return Poll::Ready(Some(Err(StreamItemError::from(error))));
        }

        let project = self.as_mut().project();
        let stream = match ready!(project.inner.poll(cx)) {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Some(Err(StreamItemError::from(error)))),
        };
        stream.poll_next(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}

impl<InnerStream, Error, OpenFuture, Item, StreamItemError> FusedStream
    for DeferredStreamReader<InnerStream, Error, OpenFuture>
where
    InnerStream: FusedStream<Item = Result<Item, StreamItemError>> + quic::StopStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    StreamItemError: From<Error> + From<quic::StreamError>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn is_terminated(&self) -> bool {
        if self.pending_stop.is_some() {
            return false;
        }
        match &self.inner {
            Deferred::Pending { .. } => false,
            Deferred::Ready { resolved } => resolved.is_terminated(),
        }
    }
}

impl<InnerStream, Error, OpenFuture> quic::GetStreamId
    for DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::GetStreamId,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_stream_id(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        if let Some(stream_id) = self.as_mut().project().cached_id.as_ref().copied() {
            return Poll::Ready(Ok(stream_id));
        }

        let stream_id = {
            let project = self.as_mut().project();
            let stream = match ready!(project.inner.poll(cx)) {
                Ok(stream) => stream,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            ready!(stream.poll_stream_id(cx))?
        };
        *self.as_mut().project().cached_id = Some(stream_id);
        Poll::Ready(Ok(stream_id))
    }
}

impl<InnerStream, Error, OpenFuture> DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::ResetStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_reset_op(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), quic::StreamError>> {
        let Some(PendingWriteOp::Reset(code)) = self.as_mut().project().pending.front() else {
            return Poll::Ready(Ok(()));
        };

        let result = {
            let project = self.as_mut().project();
            let stream = match ready!(project.inner.poll(cx)) {
                Ok(stream) => stream,
                Err(error) => return Poll::Ready(Err(error.into())),
            };
            ready!(stream.poll_reset(cx, code))
        };
        self.as_mut().project().pending.pop_front();
        Poll::Ready(result)
    }
}

impl<InnerStream, Error, OpenFuture> quic::ResetStream
    for DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::ResetStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_reset(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.as_mut().project().pending.enqueue_reset(code);
        self.poll_reset_op(cx)
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

impl<InnerStream, Error, OpenFuture> DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    InnerStream: quic::ResetStream,
    Error: Clone,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    fn poll_pending_until<Item, SinkError>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: Option<PendingWriteOp>,
    ) -> Poll<Result<(), SinkError>>
    where
        InnerStream: Sink<Item, Error = SinkError>,
        SinkError: From<Error> + From<quic::StreamError>,
    {
        loop {
            let op = {
                let project = self.as_mut().project();
                if let Some(target) = target
                    && !project.pending.contains_kind(target)
                {
                    return Poll::Ready(Ok(()));
                }
                match project.pending.front() {
                    Some(op) => op,
                    None => return Poll::Ready(Ok(())),
                }
            };

            match op {
                PendingWriteOp::Reset(_) => {
                    ready!(self.as_mut().poll_reset_op(cx)).map_err(SinkError::from)?;
                }
                PendingWriteOp::Flush => {
                    let result = {
                        let project = self.as_mut().project();
                        let stream = match ready!(project.inner.poll(cx)) {
                            Ok(stream) => stream,
                            Err(error) => return Poll::Ready(Err(error.into())),
                        };
                        ready!(stream.poll_flush(cx))
                    };
                    self.as_mut().project().pending.pop_front();
                    result?;
                    if target == Some(PendingWriteOp::Flush) {
                        return Poll::Ready(Ok(()));
                    }
                }
                PendingWriteOp::Close => {
                    let result = {
                        let project = self.as_mut().project();
                        let stream = match ready!(project.inner.poll(cx)) {
                            Ok(stream) => stream,
                            Err(error) => return Poll::Ready(Err(error.into())),
                        };
                        ready!(stream.poll_close(cx))
                    };
                    self.as_mut().project().pending.pop_front();
                    result?;
                    if target == Some(PendingWriteOp::Close) {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<InnerStream, Error, OpenFuture, Item> Sink<Item>
    for DeferredStreamWriter<InnerStream, Error, OpenFuture>
where
    InnerStream: Sink<Item> + quic::ResetStream,
    Error: Clone,
    InnerStream::Error: From<Error> + From<quic::StreamError>,
    quic::StreamError: From<Error>,
    OpenFuture: Future<Output = Result<InnerStream, Error>>,
{
    type Error = InnerStream::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        while !self.as_mut().project().pending.is_empty() {
            ready!(
                self.as_mut()
                    .poll_pending_until::<Item, Self::Error>(cx, None)?
            );
        }

        let project = self.as_mut().project();
        let stream = match ready!(project.inner.poll(cx)) {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        stream.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let project = self.project();
        assert!(
            project.pending.is_empty(),
            "start_send called without poll_ready being called first"
        );
        project
            .inner
            .try_peek_mut()
            .expect("start_send before poll_ready completed")?
            .start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().project().pending.enqueue_flush();
        self.poll_pending_until(cx, Some(PendingWriteOp::Flush))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().project().pending.enqueue_close();
        self.poll_pending_until(cx, Some(PendingWriteOp::Close))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        future::{Ready, pending, ready},
        io::Cursor,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{
        FutureExt, Sink, SinkExt, Stream, StreamExt, future::poll_fn, stream::FusedStream,
        task::noop_waker_ref,
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf},
        sync::oneshot,
    };

    use super::*;
    use crate::{
        codec::{DecodeError, EncodeError},
        quic::{GetStreamIdExt, ResetStream, ResetStreamExt, StopStream, StopStreamExt},
    };

    fn varint(value: u32) -> VarInt {
        VarInt::from_u32(value)
    }

    fn assert_reset(error: quic::StreamError, expected: VarInt) {
        let quic::StreamError::Reset { code } = error else {
            panic!("expected stream reset");
        };
        assert_eq!(code, expected);
    }

    fn resolved_quic_error<T>(value: T, code: u32) -> Resolved<T, quic::StreamError> {
        drop(value);
        Resolved::err(quic::StreamError::Reset { code: varint(code) })
    }

    fn deferred_quic_error<T>(
        value: T,
        code: u32,
    ) -> Deferred<T, quic::StreamError, Ready<Result<T, quic::StreamError>>> {
        drop(value);
        Deferred::from(ready(Err(quic::StreamError::Reset { code: varint(code) })))
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum DeferredStreamEvent {
        Stop(VarInt),
        Write(Bytes),
        Flush,
        Close,
        Reset(VarInt),
    }

    #[derive(Debug)]
    struct RecordingReader {
        stream_id: VarInt,
        events: Arc<Mutex<Vec<DeferredStreamEvent>>>,
        chunks: VecDeque<Result<Bytes, quic::StreamError>>,
        terminated: bool,
    }

    impl quic::GetStreamId for RecordingReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for RecordingReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(DeferredStreamEvent::Stop(code));
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for RecordingReader {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            match this.chunks.pop_front() {
                Some(item) => Poll::Ready(Some(item)),
                None => {
                    this.terminated = true;
                    Poll::Ready(None)
                }
            }
        }
    }

    impl FusedStream for RecordingReader {
        fn is_terminated(&self) -> bool {
            self.terminated
        }
    }

    #[derive(Debug)]
    struct RecordingWriter {
        stream_id: VarInt,
        events: Arc<Mutex<Vec<DeferredStreamEvent>>>,
    }

    impl quic::GetStreamId for RecordingWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::ResetStream for RecordingWriter {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(DeferredStreamEvent::Reset(code));
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for RecordingWriter {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(DeferredStreamEvent::Write(item));
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(DeferredStreamEvent::Flush);
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(DeferredStreamEvent::Close);
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn resolved_converts_from_result_and_back() {
        assert_eq!(Resolved::<_, DecodeError>::from(Ok(7)).into_result(), Ok(7));
        assert_eq!(
            Resolved::<i32, _>::from(Err(DecodeError::Incomplete)).into_result(),
            Err(DecodeError::Incomplete)
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn resolved_serializes_and_deserializes_error_result() {
        let resolved: Resolved<u8, u16> = Resolved::err(7);

        let encoded = serde_json::to_value(&resolved).expect("error result serializes");
        assert_eq!(encoded, serde_json::json!({ "Err": 7 }));

        let decoded: Resolved<u8, u16> =
            serde_json::from_value(encoded).expect("error result deserializes");
        assert_eq!(decoded.into_result(), Err(7));
    }

    #[tokio::test]
    async fn resolved_delegates_async_read_and_write() {
        let (mut input, output) = tokio::io::duplex(16);
        input.write_all(b"hello").await.expect("write input");
        input.shutdown().await.expect("shutdown input");

        let mut reader: Resolved<_, DecodeError> = Resolved::ok(output);
        let mut received = Vec::new();
        reader
            .read_to_end(&mut received)
            .await
            .expect("read resolved value");
        assert_eq!(received, b"hello");

        let (writer_side, mut output) = tokio::io::duplex(16);
        let mut writer: Resolved<_, EncodeError> = Resolved::ok(writer_side);
        writer
            .write_all(b"world")
            .await
            .expect("write resolved value");
        writer.flush().await.expect("flush resolved value");
        writer.shutdown().await.expect("shutdown resolved value");

        let mut received = Vec::new();
        output
            .read_to_end(&mut received)
            .await
            .expect("read written bytes");
        assert_eq!(received, b"world");
    }

    #[tokio::test]
    async fn resolved_error_maps_to_async_io_errors() {
        let (_input, output) = tokio::io::duplex(1);
        let mut reader: Resolved<tokio::io::DuplexStream, DecodeError> =
            Resolved::err(DecodeError::Incomplete);
        let error = reader.read(&mut [0]).await.expect_err("read should fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        drop(output);

        let (writer_side, _output) = tokio::io::duplex(1);
        let mut writer: Resolved<tokio::io::DuplexStream, EncodeError> =
            Resolved::err(EncodeError::FramePayloadTooLarge);
        let error = writer.write_all(b"x").await.expect_err("write should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(writer_side);
    }

    #[tokio::test]
    async fn resolved_error_maps_to_buffered_read_flush_and_shutdown_errors() {
        let mut reader: Resolved<BufReader<Cursor<Vec<u8>>>, DecodeError> =
            Resolved::err(DecodeError::Incomplete);
        let error = reader.fill_buf().await.expect_err("fill_buf should fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        let mut writer: Resolved<tokio::io::DuplexStream, EncodeError> =
            Resolved::err(EncodeError::FramePayloadTooLarge);
        let error = writer.flush().await.expect_err("flush should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error = writer.shutdown().await.expect_err("shutdown should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn resolved_delegates_buffered_read() {
        let cursor = Cursor::new(b"line\nrest".to_vec());
        let mut reader: Resolved<_, DecodeError> = Resolved::ok(BufReader::new(cursor));

        let bytes = reader.fill_buf().await.expect("fill buffer");
        assert_eq!(bytes, b"line\nrest");
        reader.consume(5);

        let mut rest = String::new();
        reader
            .read_to_string(&mut rest)
            .await
            .expect("read after consume");
        assert_eq!(rest, "rest");
    }

    #[tokio::test]
    async fn resolved_delegates_quic_stream_traits_and_stream_sink() {
        let (reader, writer) = quic::test::mock_stream_pair(varint(11));
        let mut reader: Resolved<_, quic::StreamError> = Resolved::ok(reader);
        let mut writer: Resolved<_, quic::StreamError> = Resolved::ok(writer);

        assert_eq!(reader.stream_id().await.expect("reader id"), varint(11));
        assert_eq!(writer.stream_id().await.expect("writer id"), varint(11));

        writer
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("send");
        assert_eq!(
            reader.next().await.expect("item").expect("read"),
            Bytes::from_static(b"payload")
        );

        reader.stop(varint(12)).await.expect("stop");
        writer.reset(varint(13)).await.expect("reset");

        let (_reader, writer) = quic::test::mock_stream_pair(varint(14));
        let mut writer: Resolved<_, quic::StreamError> = Resolved::ok(writer);
        writer.close().await.expect("close");
    }

    #[tokio::test]
    async fn resolved_error_maps_to_quic_stream_error_for_control_traits() {
        let (reader, _writer) = quic::test::mock_stream_pair(varint(51));
        let mut stream_id = resolved_quic_error(reader, 52);
        assert_reset(
            stream_id
                .stream_id()
                .await
                .expect_err("stream id should fail"),
            varint(52),
        );

        let (reader, _writer) = quic::test::mock_stream_pair(varint(53));
        let mut stop = resolved_quic_error(reader, 54);
        assert_reset(
            stop.stop(varint(55)).await.expect_err("stop should fail"),
            varint(54),
        );

        let (_reader, writer) = quic::test::mock_stream_pair(varint(56));
        let mut reset = resolved_quic_error(writer, 57);
        assert_reset(
            reset
                .reset(varint(58))
                .await
                .expect_err("reset should fail"),
            varint(57),
        );
    }

    #[test]
    fn resolved_error_maps_to_sink_operation_errors() {
        let (_reader, writer) = quic::test::mock_stream_pair(varint(59));
        let mut sink = Box::pin(resolved_quic_error(writer, 60));
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let Poll::Ready(Err(error)) = sink.as_mut().poll_ready(&mut cx) else {
            panic!("poll_ready should return reset");
        };
        assert_reset(error, varint(60));

        let error = sink
            .as_mut()
            .start_send(Bytes::from_static(b"ignored"))
            .expect_err("start_send should fail");
        assert_reset(error, varint(60));

        let Poll::Ready(Err(error)) = sink.as_mut().poll_flush(&mut cx) else {
            panic!("poll_flush should return reset");
        };
        assert_reset(error, varint(60));

        let Poll::Ready(Err(error)) = sink.as_mut().poll_close(&mut cx) else {
            panic!("poll_close should return reset");
        };
        assert_reset(error, varint(60));
    }

    #[tokio::test]
    async fn resolved_stream_error_yields_error_item_and_is_terminated() {
        let mut stream: Resolved<
            futures::stream::Empty<Result<Bytes, quic::StreamError>>,
            quic::StreamError,
        > = Resolved::err(quic::StreamError::Reset { code: varint(31) });
        assert_eq!(stream.size_hint(), (0, None));
        let item = stream.next().await.expect("error item").expect_err("reset");
        assert_reset(item, varint(31));
        assert!(stream.is_terminated());

        let value: Resolved<_, Infallible> =
            Resolved::ok(futures::stream::iter([Ok::<_, Infallible>(
                Bytes::from_static(b"one"),
            )]));
        assert_eq!(value.size_hint(), (1, Some(1)));
    }

    #[tokio::test]
    async fn deferred_future_resolves_success_and_error() {
        let value = Deferred::from(ready(Ok::<_, DecodeError>(42)))
            .await
            .expect("deferred value");
        assert_eq!(value, 42);

        let error = Deferred::from(ready(Err::<i32, _>(DecodeError::IntegerOverflow)))
            .await
            .expect_err("deferred error");
        assert_eq!(error, DecodeError::IntegerOverflow);
    }

    #[tokio::test]
    async fn deferred_delegates_async_read_write_and_buffered_read() {
        let (mut input, output) = tokio::io::duplex(16);
        input.write_all(b"hello").await.expect("write input");
        input.shutdown().await.expect("shutdown input");

        let mut reader = Deferred::from(ready(Ok::<_, DecodeError>(output)));
        let mut received = Vec::new();
        reader
            .read_to_end(&mut received)
            .await
            .expect("read deferred value");
        assert_eq!(received, b"hello");

        let (writer_side, mut output) = tokio::io::duplex(16);
        let mut writer = Deferred::from(ready(Ok::<_, EncodeError>(writer_side)));
        writer
            .write_all(b"world")
            .await
            .expect("write deferred value");
        writer.flush().await.expect("flush deferred value");
        writer.shutdown().await.expect("shutdown deferred value");
        let mut received = Vec::new();
        output
            .read_to_end(&mut received)
            .await
            .expect("read written bytes");
        assert_eq!(received, b"world");

        let cursor = Cursor::new(b"line\nrest".to_vec());
        let mut reader = Deferred::from(ready(Ok::<_, DecodeError>(BufReader::new(cursor))));
        assert_eq!(reader.fill_buf().await.expect("fill buffer"), b"line\nrest");
        reader.consume(5);
        let mut rest = String::new();
        reader
            .read_to_string(&mut rest)
            .await
            .expect("read after consume");
        assert_eq!(rest, "rest");
    }

    #[tokio::test]
    async fn deferred_error_maps_to_async_io_errors() {
        let (_input, output) = tokio::io::duplex(1);
        let mut reader = Deferred::from(ready({
            drop(output);
            Err::<tokio::io::DuplexStream, _>(DecodeError::Incomplete)
        }));
        let error = reader.read(&mut [0]).await.expect_err("read should fail");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        let (writer_side, _output) = tokio::io::duplex(1);
        let mut writer = Deferred::from(ready({
            drop(writer_side);
            Err::<tokio::io::DuplexStream, _>(EncodeError::HuffmanEncoding)
        }));
        let error = writer.write_all(b"x").await.expect_err("write should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn deferred_stream_wrappers_delegate_quic_stream_traits_and_stream_sink() {
        let (reader, writer) = quic::test::mock_stream_pair(varint(21));
        let mut reader = DeferredStreamReader::from(ready(Ok::<_, quic::StreamError>(reader)));
        let mut writer = DeferredStreamWriter::from(ready(Ok::<_, quic::StreamError>(writer)));

        assert_eq!(reader.stream_id().await.expect("reader id"), varint(21));
        assert_eq!(writer.stream_id().await.expect("writer id"), varint(21));

        writer
            .send(Bytes::from_static(b"deferred"))
            .await
            .expect("send");
        assert_eq!(
            reader.next().await.expect("item").expect("read"),
            Bytes::from_static(b"deferred")
        );

        assert_eq!(reader.size_hint(), (0, None));

        reader.stop(varint(22)).await.expect("stop");
        writer.reset(varint(23)).await.expect("reset");

        let (_reader, writer) = quic::test::mock_stream_pair(varint(24));
        let mut writer = Deferred::from(ready(Ok::<_, quic::StreamError>(writer)));
        writer.close().await.expect("close");
    }

    #[tokio::test]
    async fn deferred_stream_reader_applies_stop_committed_before_resolution() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (open_tx, open_rx) = oneshot::channel();
        let stop_code = varint(101);
        let mut reader = Box::pin(DeferredStreamReader::from(async move {
            open_rx
                .await
                .expect("stream opener should resolve before test ends")
        }));

        assert!(
            poll_fn(|cx| reader.as_mut().poll_stop(cx, stop_code))
                .now_or_never()
                .is_none()
        );
        assert!(events.lock().expect("event log poisoned").is_empty());

        open_tx
            .send(Ok::<_, quic::StreamError>(RecordingReader {
                stream_id: varint(102),
                events: events.clone(),
                chunks: VecDeque::from([Ok(Bytes::from_static(b"after stop"))]),
                terminated: false,
            }))
            .expect("send opener result");

        assert_eq!(
            reader
                .as_mut()
                .next()
                .await
                .expect("chunk after stop")
                .expect("read succeeds"),
            Bytes::from_static(b"after stop")
        );
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![DeferredStreamEvent::Stop(stop_code)]
        );
    }

    #[tokio::test]
    async fn deferred_stream_writer_reset_replaces_flush_committed_before_resolution() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (open_tx, open_rx) = oneshot::channel();
        let reset_code = varint(111);
        let mut writer = Box::pin(DeferredStreamWriter::from(async move {
            open_rx
                .await
                .expect("stream opener should resolve before test ends")
        }));

        assert!(
            poll_fn(|cx| writer.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
                .now_or_never()
                .is_none()
        );
        assert!(events.lock().expect("event log poisoned").is_empty());

        open_tx
            .send(Ok::<_, quic::StreamError>(RecordingWriter {
                stream_id: varint(112),
                events: events.clone(),
            }))
            .expect("send opener result");

        poll_fn(|cx| writer.as_mut().poll_ready(cx))
            .await
            .expect("writer becomes ready after reset drains");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![DeferredStreamEvent::Reset(reset_code)]
        );
    }

    #[tokio::test]
    async fn deferred_stream_writer_drains_flush_and_close_in_commit_order_after_resolution() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (open_tx, open_rx) = oneshot::channel();
        let mut writer = Box::pin(DeferredStreamWriter::from(async move {
            open_rx
                .await
                .expect("stream opener should resolve before test ends")
        }));

        assert!(
            poll_fn(|cx| writer.as_mut().poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| writer.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );

        open_tx
            .send(Ok::<_, quic::StreamError>(RecordingWriter {
                stream_id: varint(113),
                events: events.clone(),
            }))
            .expect("send opener result");

        poll_fn(|cx| writer.as_mut().poll_ready(cx))
            .await
            .expect("writer becomes ready after controls drain");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![DeferredStreamEvent::Close, DeferredStreamEvent::Flush]
        );
    }

    #[tokio::test]
    async fn deferred_fused_stream_tracks_pending_and_ready_state() {
        let stream =
            futures::stream::iter([Ok::<_, Infallible>(Bytes::from_static(b"one"))]).fuse();
        let mut stream = Deferred::from(ready(Ok::<_, Infallible>(stream)));

        assert!(!stream.is_terminated());
        assert_eq!(
            stream.next().await.expect("item").expect("stream value"),
            Bytes::from_static(b"one")
        );
        assert!(stream.next().await.is_none());
        assert!(stream.is_terminated());
    }

    #[tokio::test]
    async fn deferred_error_maps_to_stream_and_sink_errors() {
        let (reader, _writer) = quic::test::mock_stream_pair(varint(39));
        let mut stream = deferred_quic_error(reader, 40);
        let item = stream.next().await.expect("error item").expect_err("reset");
        assert_reset(item, varint(40));

        let (_reader, writer) = quic::test::mock_stream_pair(varint(41));
        let mut sink = deferred_quic_error(writer, 42);
        let error = sink
            .send(Bytes::from_static(b"ignored"))
            .await
            .expect_err("send should fail");
        assert_reset(error, varint(42));
    }

    #[test]
    fn deferred_ready_error_maps_to_start_send_error() {
        let (_reader, writer) = quic::test::mock_stream_pair(varint(61));
        let mut sink = Box::pin(deferred_quic_error(writer, 62));
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let Poll::Ready(Err(error)) = sink.as_mut().poll_ready(&mut cx) else {
            panic!("poll_ready should resolve to reset");
        };
        assert_reset(error, varint(62));

        let error = sink
            .as_mut()
            .start_send(Bytes::from_static(b"ignored"))
            .expect_err("start_send should fail");
        assert_reset(error, varint(62));
    }

    #[test]
    fn deferred_pending_read_stays_pending_without_transitioning() {
        let mut reader =
            Deferred::<Cursor<Vec<u8>>, DecodeError, _>::from(pending::<Result<_, _>>());
        let mut output = [0; 8];
        let mut read_buf = ReadBuf::new(&mut output);
        let waker = noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        assert!(matches!(
            Pin::new(&mut reader).poll_read(&mut cx, &mut read_buf),
            Poll::Pending
        ));
        assert!(matches!(reader, Deferred::Pending { .. }));
    }

    #[test]
    #[should_panic(expected = "start_send before poll_ready completed")]
    fn deferred_start_send_before_ready_panics() {
        let (_reader, writer) = quic::test::mock_stream_pair(varint(43));
        let mut sink = Box::pin(Deferred::from(async move {
            pending::<()>().await;
            Ok::<_, quic::StreamError>(writer)
        }));

        sink.as_mut()
            .start_send(Bytes::from_static(b"not ready"))
            .expect("panic before result");
    }

    #[test]
    #[should_panic(expected = "consume before read")]
    fn deferred_consume_before_read_panics() {
        let reader = BufReader::new(Cursor::new(b"pending".to_vec()));
        let mut reader = Deferred::from(ready(Ok::<_, DecodeError>(reader)));
        Pin::new(&mut reader).consume(1);
    }
}
