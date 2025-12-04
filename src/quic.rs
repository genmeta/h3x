pub mod identity;

use std::{
    borrow::Cow,
    convert::Infallible,
    error::Error,
    io,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture};
use snafu::Snafu;

use crate::{
    error::Code,
    quic::identity::{WithLocalIdentity, WithPeerIdentity},
    varint::VarInt,
};

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum StreamError {
    #[snafu(transparent)]
    Connection {
        source: ConnectionError,
    },
    Reset {
        code: VarInt,
    },
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

impl From<io::Error> for StreamError {
    fn from(value: io::Error) -> Self {
        value
            .downcast::<Self>()
            .expect("io::Error is not StreamError")
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub struct TransportError {
    pub kind: VarInt,
    pub frame_type: VarInt,
    pub reason: Cow<'static, str>,
}

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub struct ApplicationError {
    pub code: Code,
    pub reason: Cow<'static, str>,
}

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

pub trait Connect {
    type Connection: Connection;
    type Error: Error + 'static;

    fn connect(&self, host: &str) -> BoxFuture<'static, Result<Self::Connection, Self::Error>>;
}

pub trait Listen {
    type Connection: Connection;
    type Error: Error + 'static;

    fn accept(&self) -> BoxFuture<'static, Result<Self::Connection, Self::Error>>;
}

pub trait Connection:
    ManageStream + WithLocalIdentity + WithPeerIdentity + Close + Unpin + Send + 'static
{
}

impl<C: ManageStream + WithLocalIdentity + WithPeerIdentity + Close + Unpin + Send + 'static>
    Connection for C
{
}

pub trait ManageStream {
    type StreamWriter: WriteStream;
    type StreamReader: ReadStream;

    fn open_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>;

    fn open_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamWriter, ConnectionError>>;

    fn accept_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>>;

    fn accept_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamReader, ConnectionError>>;
}

impl<P: DerefMut<Target: ManageStream>> ManageStream for Pin<P> {
    type StreamWriter = <P::Target as ManageStream>::StreamWriter;

    type StreamReader = <P::Target as ManageStream>::StreamReader;

    fn open_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        <P::Target as ManageStream>::open_bi(self.as_deref_mut())
    }

    fn open_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamWriter, ConnectionError>> {
        <P::Target as ManageStream>::open_uni(self.as_deref_mut())
    }

    fn accept_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        <P::Target as ManageStream>::accept_bi(self.as_deref_mut())
    }

    fn accept_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamReader, ConnectionError>> {
        <P::Target as ManageStream>::accept_uni(self.as_deref_mut())
    }
}

impl<M: ManageStream + Unpin + ?Sized> ManageStream for &mut M {
    type StreamWriter = M::StreamWriter;

    type StreamReader = M::StreamReader;

    fn open_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        M::open_bi(Pin::new(self.get_mut()))
    }

    fn open_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamWriter, ConnectionError>> {
        M::open_uni(Pin::new(self.get_mut()))
    }

    fn accept_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        M::accept_bi(Pin::new(self.get_mut()))
    }

    fn accept_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamReader, ConnectionError>> {
        M::accept_uni(Pin::new(self.get_mut()))
    }
}

pub trait Close {
    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>);
}

impl<P: DerefMut<Target: Close>> Close for Pin<P> {
    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>) {
        <P::Target as Close>::close(self.as_deref_mut(), code, reason)
    }
}

impl<P: Close + Unpin + ?Sized> Close for &mut P {
    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>) {
        P::close(Pin::new(self.get_mut()), code, reason)
    }
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
    StopStream + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + Send + 'static
{
}

impl<
    S: StopStream + GetStreamId + Stream<Item = Result<Bytes, StreamError>> + Send + ?Sized + 'static,
> ReadStream for S
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
    CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + Send + 'static
{
}

impl<S: CancelStream + GetStreamId + Sink<Bytes, Error = StreamError> + Send + ?Sized + 'static>
    WriteStream for S
{
}

#[cfg(test)]
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
        let (stop_sending_tx, stop_sending_rx) = oneshot::channel();
        let (packet_tx, packet_rx) = futures::channel::mpsc::channel(8);

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
