use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};

use crate::varint::VarInt;

pub mod unfold;

/// Read-only observation of a stream id.
///
/// Polling for the id has no committed stream side effect and no ordering
/// relationship with data, stop, or reset operations. An implementation may
/// return the id immediately or wait until the id is observable. Dropping a
/// pending [`StreamId`] future commits nothing.
pub trait GetStreamId<E> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<VarInt, E>>;
}

impl<P, E> GetStreamId<E> for Pin<P>
where
    P: DerefMut,
    P::Target: GetStreamId<E>,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<VarInt, E>> {
        <P::Target as GetStreamId<E>>::poll_stream_id(self.as_deref_mut(), cx)
    }
}

impl<S, E> GetStreamId<E> for &mut S
where
    S: GetStreamId<E> + Unpin + ?Sized,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<VarInt, E>> {
        S::poll_stream_id(Pin::new(self.get_mut()), cx)
    }
}

pin_project_lite::pin_project! {
    pub struct StreamId<S: ?Sized, E> {
        _error: std::marker::PhantomData<fn() -> E>,
        #[pin]
        stream: S,
    }
}

impl<S, E> StreamId<S, E> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            _error: std::marker::PhantomData,
        }
    }
}

impl<S, E> Future for StreamId<S, E>
where
    S: GetStreamId<E> + ?Sized,
{
    type Output = Result<VarInt, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().stream.poll_stream_id(cx)
    }
}

pub trait GetStreamIdExt<E>: GetStreamId<E> {
    fn stream_id(&mut self) -> StreamId<&mut Self, E> {
        StreamId::new(self)
    }
}

impl<T, E> GetStreamIdExt<E> for T where T: GetStreamId<E> + ?Sized {}

/// Receive-side stop control for a stream.
///
/// The first poll of [`poll_stop`](StopStream::poll_stop) commits the stop
/// request and its code. Dropping the caller future after that first poll does
/// not cancel the request; later polls for the same outstanding stop operation
/// continue it rather than creating a new one.
///
/// Stop asks the peer to stop sending. It does not reset the local send side,
/// and it must not discard bytes that were already received locally but have not
/// yet been delivered to the caller.
pub trait StopStream<E> {
    fn poll_stop(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>>;
}

impl<P, E> StopStream<E> for Pin<P>
where
    P: DerefMut,
    P::Target: StopStream<E>,
{
    fn poll_stop(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>> {
        <P::Target as StopStream<E>>::poll_stop(self.as_deref_mut(), cx, code)
    }
}

impl<S, E> StopStream<E> for &mut S
where
    S: StopStream<E> + Unpin + ?Sized,
{
    fn poll_stop(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>> {
        S::poll_stop(Pin::new(self.get_mut()), cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct Stop<S: ?Sized, E> {
        code: VarInt,
        _error: std::marker::PhantomData<fn() -> E>,
        #[pin]
        stream: S,
    }
}

impl<S, E> Stop<S, E> {
    pub(crate) fn new(stream: S, code: VarInt) -> Self {
        Self {
            code,
            stream,
            _error: std::marker::PhantomData,
        }
    }
}

impl<S, E> Future for Stop<S, E>
where
    S: StopStream<E> + ?Sized,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        project.stream.poll_stop(cx, *project.code)
    }
}

pub trait StopStreamExt<E>: StopStream<E> {
    fn stop(&mut self, code: VarInt) -> Stop<&mut Self, E> {
        Stop::new(self, code)
    }
}

impl<T, E> StopStreamExt<E> for T where T: StopStream<E> + ?Sized {}

/// Send-side reset control for a stream.
///
/// This operation is stream reset rather than cancellation of a Rust future.
/// The first poll of [`poll_reset`](ResetStream::poll_reset) commits the reset
/// code. Once committed, reset may interrupt in-flight send-side work such as
/// data send, flush, or shutdown. Reset does not stop local receive-side byte
/// delivery.
pub trait ResetStream<E> {
    fn poll_reset(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>>;
}

impl<P, E> ResetStream<E> for Pin<P>
where
    P: DerefMut,
    P::Target: ResetStream<E>,
{
    fn poll_reset(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>> {
        <P::Target as ResetStream<E>>::poll_reset(self.as_deref_mut(), cx, code)
    }
}

impl<S, E> ResetStream<E> for &mut S
where
    S: ResetStream<E> + Unpin + ?Sized,
{
    fn poll_reset(self: Pin<&mut Self>, cx: &mut Context<'_>, code: VarInt) -> Poll<Result<(), E>> {
        S::poll_reset(Pin::new(self.get_mut()), cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct Reset<S: ?Sized, E> {
        code: VarInt,
        _error: std::marker::PhantomData<fn() -> E>,
        #[pin]
        stream: S,
    }
}

impl<S, E> Reset<S, E> {
    pub(crate) fn new(stream: S, code: VarInt) -> Self {
        Self {
            code,
            stream,
            _error: std::marker::PhantomData,
        }
    }
}

impl<S, E> Future for Reset<S, E>
where
    S: ResetStream<E> + ?Sized,
{
    type Output = Result<(), E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        project.stream.poll_reset(cx, *project.code)
    }
}

pub trait ResetStreamExt<E>: ResetStream<E> {
    fn reset(&mut self, code: VarInt) -> Reset<&mut Self, E> {
        Reset::new(self, code)
    }
}

impl<T, E> ResetStreamExt<E> for T where T: ResetStream<E> + ?Sized {}

pub trait ReadStream<D, IoE, StopE, IdE>:
    Stream<Item = Result<D, IoE>> + StopStream<StopE> + GetStreamId<IdE>
{
}

impl<T, D, IoE, StopE, IdE> ReadStream<D, IoE, StopE, IdE> for T where
    T: Stream<Item = Result<D, IoE>> + StopStream<StopE> + GetStreamId<IdE> + ?Sized
{
}

pub trait WriteStream<D, IoE, ResetE, IdE>:
    Sink<D, Error = IoE> + ResetStream<ResetE> + GetStreamId<IdE>
{
}

impl<T, D, IoE, ResetE, IdE> WriteStream<D, IoE, ResetE, IdE> for T where
    T: Sink<D, Error = IoE> + ResetStream<ResetE> + GetStreamId<IdE> + ?Sized
{
}

pub type BoxStreamReader<D, IoE, StopE = IoE, IdE = StopE> =
    Pin<Box<dyn ReadStream<D, IoE, StopE, IdE> + Send>>;

pub type LocalBoxStreamReader<D, IoE, StopE = IoE, IdE = StopE> =
    Pin<Box<dyn ReadStream<D, IoE, StopE, IdE>>>;

pub type BoxStreamWriter<D, IoE, ResetE = IoE, IdE = ResetE> =
    Pin<Box<dyn WriteStream<D, IoE, ResetE, IdE> + Send>>;

pub type LocalBoxStreamWriter<D, IoE, ResetE = IoE, IdE = ResetE> =
    Pin<Box<dyn WriteStream<D, IoE, ResetE, IdE>>>;

pub trait ManageStream {
    type Data;

    type ReadError;
    type WriteError;
    type StopError;
    type ResetError;
    type StreamIdError;

    type OpenBiError;
    type OpenUniError;
    type AcceptBiError;
    type AcceptUniError;

    type StreamReader: ReadStream<Self::Data, Self::ReadError, Self::StopError, Self::StreamIdError>;

    type StreamWriter: WriteStream<Self::Data, Self::WriteError, Self::ResetError, Self::StreamIdError>;

    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::OpenBiError>>
    + Send
    + '_;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamWriter, Self::OpenUniError>> + Send + '_;

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::AcceptBiError>>
    + Send
    + '_;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamReader, Self::AcceptUniError>> + Send + '_;
}
