use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Sink, Stream};

use crate::varint::VarInt;

pub mod unfold;

pub trait GetStreamId<E = crate::quic::StreamError> {
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

impl<S, E> Future for StreamId<S, E>
where
    S: GetStreamId<E> + ?Sized,
{
    type Output = Result<VarInt, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().stream.poll_stream_id(cx)
    }
}

pub trait GetStreamIdExt<E = crate::quic::StreamError>: GetStreamId<E> {
    fn stream_id(&mut self) -> StreamId<&mut Self, E> {
        StreamId {
            stream: self,
            _error: std::marker::PhantomData,
        }
    }
}

impl<T, E> GetStreamIdExt<E> for T where T: GetStreamId<E> + ?Sized {}

pub trait StopStream<E = crate::quic::StreamError> {
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

pub trait StopStreamExt<E = crate::quic::StreamError>: StopStream<E> {
    fn stop(&mut self, code: VarInt) -> Stop<&mut Self, E> {
        Stop {
            code,
            stream: self,
            _error: std::marker::PhantomData,
        }
    }
}

impl<T, E> StopStreamExt<E> for T where T: StopStream<E> + ?Sized {}

pub trait ResetStream<E = crate::quic::StreamError> {
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

pub trait ResetStreamExt<E = crate::quic::StreamError>: ResetStream<E> {
    fn reset(&mut self, code: VarInt) -> Reset<&mut Self, E> {
        Reset {
            code,
            stream: self,
            _error: std::marker::PhantomData,
        }
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

#[doc(hidden)]
pub trait BoxStreamReaderTarget<D, IoE, StopE, IdE, S: ?Sized> {
    type Target: ?Sized;
}

impl<D, IoE, StopE, IdE, S> BoxStreamReaderTarget<D, IoE, StopE, IdE, S> for ()
where
    S: ReadStream<D, IoE, StopE, IdE> + ?Sized,
{
    type Target = S;
}

#[doc(hidden)]
pub trait BoxStreamWriterTarget<D, IoE, ResetE, IdE, S: ?Sized> {
    type Target: ?Sized;
}

impl<D, IoE, ResetE, IdE, S> BoxStreamWriterTarget<D, IoE, ResetE, IdE, S> for ()
where
    S: WriteStream<D, IoE, ResetE, IdE> + ?Sized,
{
    type Target = S;
}

pub type BoxStreamReader<
    D,
    IoE,
    StopE = IoE,
    IdE = StopE,
    S = dyn ReadStream<D, IoE, StopE, IdE> + Send,
> = Pin<Box<<() as BoxStreamReaderTarget<D, IoE, StopE, IdE, S>>::Target>>;

pub type LocalBoxStreamReader<
    D,
    IoE,
    StopE = IoE,
    IdE = StopE,
    S = dyn ReadStream<D, IoE, StopE, IdE>,
> = Pin<Box<<() as BoxStreamReaderTarget<D, IoE, StopE, IdE, S>>::Target>>;

pub type BoxStreamWriter<
    D,
    IoE,
    ResetE = IoE,
    IdE = ResetE,
    S = dyn WriteStream<D, IoE, ResetE, IdE> + Send,
> = Pin<Box<<() as BoxStreamWriterTarget<D, IoE, ResetE, IdE, S>>::Target>>;

pub type LocalBoxStreamWriter<
    D,
    IoE,
    ResetE = IoE,
    IdE = ResetE,
    S = dyn WriteStream<D, IoE, ResetE, IdE>,
> = Pin<Box<<() as BoxStreamWriterTarget<D, IoE, ResetE, IdE, S>>::Target>>;

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
