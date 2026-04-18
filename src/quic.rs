use std::{
    any::Any,
    borrow::Cow,
    convert::Infallible,
    error::Error,
    future::Future,
    io,
    ops::DerefMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture};
use http::uri::Authority;
use snafu::Snafu;

pub mod agent;

use crate::{error::Code, varint::VarInt};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum StreamError {
    #[snafu(transparent)]
    Connection { source: ConnectionError },
    #[snafu(display("stream reset with code {code}"))]
    Reset { code: VarInt },
}

impl StreamError {
    /// Returns `true` if the stream error is [`Reset`].
    ///
    /// [`Reset`]: StreamError::Reset
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset { .. })
    }
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            error @ StreamError::Reset { .. } => io::Error::new(io::ErrorKind::BrokenPipe, error),
            StreamError::Connection { source } => io::Error::from(source),
        }
    }
}

impl From<Infallible> for StreamError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl StreamError {
    pub(crate) fn try_from(error: io::Error) -> Result<Self, io::Error> {
        let source = match error.downcast::<Self>() {
            Ok(error) => return Ok(error),
            Err(error) => error,
        };
        source.downcast::<ConnectionError>().map(Self::from)
    }
}

impl From<io::Error> for StreamError {
    fn from(error: io::Error) -> Self {
        match Self::try_from(error) {
            Ok(error) => error,
            Err(error) => {
                unreachable!(
                    "io::Error({error:?}) cannot be converted to quic::StreamError, this is a bug"
                )
            }
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
#[snafu(display("transport error (0x{kind:x} in frame 0x{frame_type:x}): {reason}"))]
pub struct TransportError {
    pub kind: VarInt,
    pub frame_type: VarInt,
    pub reason: Cow<'static, str>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
#[snafu(display("application error ({code}): {reason}"))]
pub struct ApplicationError {
    pub code: Code,
    pub reason: Cow<'static, str>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum ConnectionError {
    #[snafu(transparent)]
    Transport { source: TransportError },
    #[snafu(transparent)]
    Application { source: ApplicationError },
}

impl From<ConnectionError> for io::Error {
    fn from(value: ConnectionError) -> Self {
        io::Error::new(io::ErrorKind::BrokenPipe, value)
    }
}

impl ConnectionError {
    pub const fn is_transport(&self) -> bool {
        matches!(self, ConnectionError::Transport { .. })
    }

    pub const fn is_application(&self) -> bool {
        matches!(self, ConnectionError::Application { .. })
    }
}

pub trait Connect: Send + Sync {
    type Connection: Connection;
    type Error: Error + Any;

    fn connect<'a>(
        &'a self,
        server: &'a Authority,
    ) -> impl Future<Output = Result<Arc<Self::Connection>, Self::Error>> + Send + 'a;
}

pub trait Listen: Send + Sync {
    type Connection: Connection;
    type Error: Error + Any;

    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<Arc<Self::Connection>, Self::Error>> + Send + '_;

    fn shutdown(&self) -> impl Future<Output = Result<(), Self::Error>> + Send + '_;
}

/// AFIT version of stream management with concrete associated types.
///
/// Implement this for concrete connection types. A blanket impl provides
/// [`DynManageStream`] automatically.
pub trait ManageStream: Send + Sync {
    type StreamReader: ReadStream + Unpin;
    type StreamWriter: WriteStream + Unpin;

    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>
    + Send
    + '_;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamWriter, ConnectionError>> + Send + '_;

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>
    + Send
    + '_;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamReader, ConnectionError>> + Send + '_;
}

/// Type-erased read stream: `Pin<Box<dyn ReadStream + Send>>`.
pub type BoxReadStream = Pin<Box<dyn ReadStream + Send>>;

/// Type-erased write stream: `Pin<Box<dyn WriteStream + Send>>`.
pub type BoxWriteStream = Pin<Box<dyn WriteStream + Send>>;

/// Object-safe version of [`ManageStream`] with type-erased streams.
///
/// Stream types are fixed to [`BoxReadStream`] / [`BoxWriteStream`].
/// A blanket impl is provided for all `T: ManageStream`.
pub trait DynManageStream: Send + Sync {
    #[allow(clippy::type_complexity)]
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), ConnectionError>>;

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, ConnectionError>>;

    #[allow(clippy::type_complexity)]
    fn accept_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), ConnectionError>>;

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, ConnectionError>>;
}

impl<T: ManageStream> DynManageStream for T {
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), ConnectionError>> {
        Box::pin(async {
            let (r, w) = ManageStream::open_bi(self).await?;
            Ok((Box::pin(r) as BoxReadStream, Box::pin(w) as BoxWriteStream))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, ConnectionError>> {
        Box::pin(async {
            let w = ManageStream::open_uni(self).await?;
            Ok(Box::pin(w) as BoxWriteStream)
        })
    }

    fn accept_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), ConnectionError>> {
        Box::pin(async {
            let (r, w) = ManageStream::accept_bi(self).await?;
            Ok((Box::pin(r) as BoxReadStream, Box::pin(w) as BoxWriteStream))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, ConnectionError>> {
        Box::pin(async {
            let r = ManageStream::accept_uni(self).await?;
            Ok(Box::pin(r) as BoxReadStream)
        })
    }
}

/// AFIT version of local agent access.
pub trait WithLocalAgent: Send + Sync {
    type LocalAgent: agent::LocalAgent + 'static;
    fn local_agent(
        &self,
    ) -> impl Future<Output = Result<Option<Self::LocalAgent>, ConnectionError>> + Send + '_;
}

/// Object-safe version of [`WithLocalAgent`] with type-erased agent.
pub trait DynWithLocalAgent: Send + Sync {
    fn local_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::LocalAgent>>, ConnectionError>>;
}

impl<T: WithLocalAgent> DynWithLocalAgent for T {
    fn local_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::LocalAgent>>, ConnectionError>> {
        Box::pin(async {
            WithLocalAgent::local_agent(self)
                .await
                .map(|opt| opt.map(|a| Arc::new(a) as Arc<dyn agent::LocalAgent>))
        })
    }
}

/// AFIT version of remote agent access.
pub trait WithRemoteAgent: Send + Sync {
    type RemoteAgent: agent::RemoteAgent + 'static;
    fn remote_agent(
        &self,
    ) -> impl Future<Output = Result<Option<Self::RemoteAgent>, ConnectionError>> + Send + '_;
}

/// Object-safe version of [`WithRemoteAgent`] with type-erased agent.
pub trait DynWithRemoteAgent: Send + Sync {
    fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::RemoteAgent>>, ConnectionError>>;
}

impl<T: WithRemoteAgent> DynWithRemoteAgent for T {
    fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<Arc<dyn agent::RemoteAgent>>, ConnectionError>> {
        Box::pin(async {
            WithRemoteAgent::remote_agent(self)
                .await
                .map(|opt| opt.map(|a| Arc::new(a) as Arc<dyn agent::RemoteAgent>))
        })
    }
}

/// AFIT version of connection lifecycle management.
///
/// Only `closed()` benefits from AFIT; `close()` and `check()` are synchronous.
///
/// # Error latching contract
///
/// A connection has a single terminal error. Once **any** operation on the same
/// connection — including [`ManageStream`], [`WithLocalAgent`],
/// [`WithRemoteAgent`], or [`Lifecycle`] methods — returns a
/// [`ConnectionError`] (directly, or wrapped in
/// [`StreamError::Connection`]), the connection is considered dead and:
///
/// * [`check()`](Lifecycle::check) **must** return `Err` with the same error on
///   every subsequent call.
/// * [`closed()`](Lifecycle::closed) **must** resolve immediately (without
///   blocking) and yield the same error.
///
/// Implementations are responsible for latching the first observed
/// `ConnectionError` internally so that callers never see a transient "healthy"
/// state after a failure has already been observed.
pub trait Lifecycle: Send + Sync {
    fn close(&self, code: Code, reason: Cow<'static, str>);

    /// Check if the connection is still usable for reuse.
    ///
    /// Returns `Ok(())` if the connection is alive and can be reused,
    /// or `Err(ConnectionError)` if the connection is dead.
    ///
    /// Once this method (or any other connection operation) has returned
    /// `Err(ConnectionError)`, all future calls **must** return `Err` with
    /// the same error.
    fn check(&self) -> Result<(), ConnectionError>;

    /// Wait for the connection to close.
    ///
    /// Returns the error that caused the connection to terminate.
    ///
    /// This method **must** be idempotent: after the connection has terminated,
    /// every call must resolve immediately and return the same error that
    /// [`check()`](Lifecycle::check) would return.
    fn closed(&self) -> impl Future<Output = ConnectionError> + Send + '_;
}

/// Object-safe version of [`Lifecycle`].
pub trait DynLifecycle: Send + Sync {
    fn close(&self, code: Code, reason: Cow<'static, str>);

    fn check(&self) -> Result<(), ConnectionError>;

    fn closed(&self) -> BoxFuture<'_, ConnectionError>;
}

impl<T: ?Sized + Lifecycle> DynLifecycle for T {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        Lifecycle::close(self, code, reason)
    }

    fn check(&self) -> Result<(), ConnectionError> {
        Lifecycle::check(self)
    }

    fn closed(&self) -> BoxFuture<'_, ConnectionError> {
        Box::pin(Lifecycle::closed(self))
    }
}

/// Composite AFIT trait: a fully-featured connection.
///
/// Not object-safe due to associated types. Use [`DynConnection`] for
/// type-erased usage.
pub trait Connection:
    ManageStream + WithLocalAgent + WithRemoteAgent + Lifecycle + Send + Sync + Any
{
}

impl<C: ManageStream + WithLocalAgent + WithRemoteAgent + Lifecycle + Send + Sync + Any> Connection
    for C
{
}

/// Object-safe composite trait for type-erased connections.
pub trait DynConnection:
    DynManageStream + DynWithLocalAgent + DynWithRemoteAgent + DynLifecycle + Send + Sync + Any
{
}

impl<C: DynManageStream + DynWithLocalAgent + DynWithRemoteAgent + DynLifecycle + Send + Sync + Any>
    DynConnection for C
{
}

pub trait GetStreamId {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>>;
}

impl<P> GetStreamId for Pin<P>
where
    P: DerefMut<Target: GetStreamId>,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        <P::Target as GetStreamId>::poll_stream_id(self.as_deref_mut(), cx)
    }
}

impl<S> GetStreamId for &mut S
where
    S: GetStreamId + Unpin + ?Sized,
{
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        S::poll_stream_id(Pin::new(self.get_mut()), cx)
    }
}

pin_project_lite::pin_project! {
    pub struct StreamId<S: ?Sized>{
        #[pin]
        stream: S
    }
}

impl<S: GetStreamId + ?Sized> Future for StreamId<S> {
    type Output = Result<VarInt, StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        project.stream.poll_stream_id(cx)
    }
}

pub trait GetStreamIdExt {
    fn stream_id(&mut self) -> StreamId<&mut Self> {
        StreamId { stream: self }
    }
}

impl<T: GetStreamId + ?Sized> GetStreamIdExt for T {}

pub trait StopStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>>;
}

impl<P> StopStream for Pin<P>
where
    P: DerefMut<Target: StopStream>,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        <P::Target as StopStream>::poll_stop(self.as_deref_mut(), cx, code)
    }
}

impl<S> StopStream for &mut S
where
    S: StopStream + Unpin + ?Sized,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        S::poll_stop(Pin::new(self.get_mut()), cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct Stop<S: ?Sized>{
        code: VarInt,
        #[pin]
        stream: S
    }
}

impl<S: StopStream + ?Sized> Future for Stop<S> {
    type Output = Result<(), StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        project.stream.poll_stop(cx, *project.code)
    }
}

pub trait StopStreamExt {
    fn stop(&mut self, code: VarInt) -> Stop<&mut Self> {
        Stop { code, stream: self }
    }
}

impl<T: StopStream + ?Sized> StopStreamExt for T {}

pub trait ReadStream:
    StopStream + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + Send + Any
{
}

impl<S: StopStream + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + Send + ?Sized + Any>
    ReadStream for S
{
}

pub trait CancelStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>>;
}

impl<S> CancelStream for &mut S
where
    S: CancelStream + Unpin + ?Sized,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        S::poll_cancel(Pin::new(self.get_mut()), cx, code)
    }
}

impl<P> CancelStream for Pin<P>
where
    P: DerefMut<Target: CancelStream>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        <P::Target as CancelStream>::poll_cancel(self.as_deref_mut(), cx, code)
    }
}

pin_project_lite::pin_project! {
    pub struct Cancel<S:?Sized>{
        code: VarInt,
        #[pin]
        stream: S
    }
}

impl<S: CancelStream + ?Sized> Future for Cancel<S> {
    type Output = Result<(), StreamError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        project.stream.poll_cancel(cx, *project.code)
    }
}

pub trait CancelStreamExt {
    fn cancel(&mut self, code: VarInt) -> Cancel<&mut Self> {
        Cancel { code, stream: self }
    }
}

impl<T: CancelStream + ?Sized> CancelStreamExt for T {}

pub trait WriteStream:
    CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + Send + Any
{
}

impl<S: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + Send + ?Sized + Any>
    WriteStream for S
{
}

#[cfg(any(test, feature = "testing"))]
pub mod test {
    use std::{
        pin::Pin,
        task::{Context, Poll, ready},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use tokio::sync::oneshot;

    use crate::{
        quic::{CancelStream, GetStreamId, StopStream, StreamError},
        varint::VarInt,
    };

    pin_project_lite::pin_project! {
        pub struct MockStreamWriter<S: ?Sized> {
            stream_id: VarInt,
            #[pin]
            stop_sending: oneshot::Receiver<VarInt>,
            #[pin]
            stream: S,
        }

        impl<S:? Sized> PinnedDrop for MockStreamWriter<S> {
            fn drop(this: Pin<&mut Self>) {
                println!("Dropping MockStreamWriter({})", this.stream_id);
            }
        }
    }

    pub enum Packet {
        Stream(Bytes),
        Reset(VarInt),
    }

    impl<S: ?Sized> GetStreamId for MockStreamWriter<S> {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Ok(self.stream_id).into()
        }
    }

    impl<S: Sink<Packet> + ?Sized> CancelStream for MockStreamWriter<S>
    where
        StreamError: From<S::Error>,
    {
        fn poll_cancel(
            self: Pin<&mut Self>,
            cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let mut project = self.project();
            ready!(project.stream.as_mut().poll_ready(cx)?);
            project.stream.as_mut().start_send(Packet::Reset(code))?;
            Poll::Ready(Ok(()))
        }
    }

    impl<S: Sink<Packet> + ?Sized> Sink<Bytes> for MockStreamWriter<S>
    where
        StreamError: From<S::Error>,
    {
        type Error = StreamError;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_ready(cx).map_err(From::from)
        }

        fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
            tracing::debug!(
                ?bytes,
                stream_id = self.stream_id.into_inner(),
                "MockStreamWriter send {} bytes",
                bytes.len()
            );
            self.project()
                .stream
                .start_send(Packet::Stream(bytes))
                .map_err(From::from)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_flush(cx).map_err(From::from)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.project().stream.poll_close(cx).map_err(From::from)
        }
    }

    enum ReceiverResetState {
        None,
        ResetReceived(VarInt),
    }

    pin_project_lite::pin_project! {
        pub struct MockStreamReader<S: ?Sized> {
            stream_id: VarInt,
            stop_sending_tx: Option<oneshot::Sender<VarInt>>,
            reset: ReceiverResetState,
            #[pin]
            stream: S,
        }

        impl<S:? Sized> PinnedDrop for MockStreamReader<S> {
            fn drop(this: Pin<&mut Self>) {
                println!("Dropping MockStreamReader({})", this.stream_id);
            }
        }
    }

    impl<S: ?Sized> GetStreamId for MockStreamReader<S> {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl<S: ?Sized> StopStream for MockStreamReader<S> {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            let project = self.project();
            if let Some(tx) = project.stop_sending_tx.take() {
                let _ = tx.send(code);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl<S: Stream<Item = Result<Packet, StreamError>> + ?Sized> Stream for MockStreamReader<S> {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let mut project = self.project();
            loop {
                if let ReceiverResetState::ResetReceived(code) = *project.reset {
                    return Poll::Ready(Some(Err(StreamError::Reset { code })));
                }
                match ready!(project.stream.as_mut().poll_next(cx)?) {
                    Some(Packet::Stream(bytes)) => {
                        tracing::debug!(
                            ?bytes,
                            stream_id = project.stream_id.into_inner(),
                            "MockStreamReader received {} bytes",
                            bytes.len()
                        );
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                    Some(Packet::Reset(code)) => {
                        *project.reset = ReceiverResetState::ResetReceived(code);
                    }
                    None => return Poll::Ready(None),
                }
            }
        }
    }

    pub fn mock_stream_pair(
        stream_id: VarInt,
    ) -> (
        MockStreamReader<impl Stream<Item = Result<Packet, StreamError>>>,
        MockStreamWriter<impl Sink<Packet, Error = StreamError>>,
    ) {
        mock_stream_pair_with_capacity(stream_id, 8)
    }

    pub fn mock_stream_pair_with_capacity(
        stream_id: VarInt,
        capacity: usize,
    ) -> (
        MockStreamReader<impl Stream<Item = Result<Packet, StreamError>>>,
        MockStreamWriter<impl Sink<Packet, Error = StreamError>>,
    ) {
        let (stop_sending_tx, stop_sending_rx) = oneshot::channel();
        let (packet_tx, packet_rx) = futures::channel::mpsc::channel(capacity);

        let writer = MockStreamWriter {
            stream_id,
            stop_sending: stop_sending_rx,
            stream: packet_tx.sink_map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            }),
        };

        let reader = MockStreamReader {
            stream_id,
            stop_sending_tx: Some(stop_sending_tx),
            reset: ReceiverResetState::None,
            stream: packet_rx.map(Ok),
        };

        (reader, writer)
    }

    #[tokio::test]
    async fn pair() {
        let (mut reader, mut writer) = mock_stream_pair(VarInt::from_u32(37));

        let file = include_bytes!("./quic.rs");
        let send = async {
            for part in file.chunks(100) {
                writer.feed(Bytes::copy_from_slice(part)).await.unwrap();
            }
            writer.close().await.unwrap();
        };
        let recv = async {
            let mut received = Vec::new();
            while let Some(chunk) = reader.next().await {
                let chunk = chunk.unwrap();
                received.extend_from_slice(&chunk);
            }
            assert!(received == file);
        };
        tokio::join!(send, recv);
    }
}
