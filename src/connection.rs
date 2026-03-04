use std::{
    any::Any, error::Error as StdError, fmt::Debug, io, marker::PhantomData, ops, sync::Arc,
};

pub mod stream;

use futures::FutureExt;
use snafu::Snafu;
use tracing::Instrument;

use crate::{
    codec::{PeekableStreamReader, SinkWriter, StreamReader},
    dhttp::{protocol::DHttpProtocolFactory, settings::Settings},
    error::{Code, HasErrorCode},
    protocol::{InitProtocols, ProductProtocol, Protocols, StreamVerdict},
    qpack::protocol::QPackProtocolFactory,
    quic::{self, CancelStreamExt, StopStreamExt, agent},
    util::set_once::SetOnce,
    varint::VarInt,
};

#[derive(Debug, Snafu, Clone)]
pub enum StreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Code {
        source: Arc<dyn HasErrorCode + Send + Sync>,
    },
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl StreamError {
    pub fn map_stream_reset(self, map: impl FnOnce(VarInt) -> Self) -> Self {
        match self {
            StreamError::Quic {
                source: quic::StreamError::Reset { code },
            } => map(code),
            error => error,
        }
    }
}

impl<E: HasErrorCode + StdError + Send + Sync + 'static> From<E> for StreamError {
    fn from(value: E) -> Self {
        StreamError::Code {
            source: Arc::new(value),
        }
    }
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        io::Error::other(value)
    }
}

impl From<io::Error> for StreamError {
    fn from(source: io::Error) -> Self {
        let error = match source.downcast::<StreamError>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match quic::StreamError::try_from(error) {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        match error.downcast::<Arc<dyn HasErrorCode + Send + Sync + 'static>>() {
            Ok(error) => error.into(),
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to connection::StreamError, this is a bug"
            ),
        }
    }
}

#[derive(Debug)]
pub struct QuicConnection<C: ?Sized> {
    error: SetOnce<quic::ConnectionError>,
    inner: C,
}

impl<C: ?Sized> QuicConnection<C> {
    fn new(quic: C) -> Self
    where
        C: Sized,
    {
        Self {
            inner: quic,
            error: SetOnce::new(),
        }
    }
}

impl<C: quic::ManageStream + ?Sized> QuicConnection<C> {
    pub async fn open_bi(
        &self,
    ) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        { self.inner.open_bi() }.await
    }

    pub async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        { self.inner.open_uni() }.await
    }

    pub async fn accept_bi(
        &self,
    ) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        { self.inner.accept_bi() }.await
    }

    pub async fn accept_uni(&self) -> Result<C::StreamReader, quic::ConnectionError> {
        { self.inner.accept_uni() }.await
    }
}

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionGoaway {
    #[snafu(display("local goaway"))]
    Local,
    #[snafu(display("peer goaway"))]
    Peer,
}

impl<C: quic::Close + ?Sized> QuicConnection<C> {
    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        if self.error.peek().is_some() {
            return;
        }
        self.inner.close(error.code(), error.to_string().into())
    }

    pub async fn handle_connection_error(
        &self,
        error: quic::ConnectionError,
    ) -> quic::ConnectionError {
        _ = self.error.set_with(|| error);
        self.error().await
    }

    pub async fn handle_stream_error(&self, error: StreamError) -> quic::StreamError {
        match error {
            StreamError::Quic { source } => match source {
                quic::StreamError::Connection { source } => {
                    self.handle_connection_error(source).await.into()
                }
                quic::StreamError::Reset { .. } => source,
            },
            StreamError::Code { source } => {
                self.close(source.as_ref());
                self.error().await.into()
            }
        }
    }

    pub fn error(&self) -> impl Future<Output = quic::ConnectionError> + Send + use<C> {
        self.error
            .get()
            .map(|option| option.unwrap_or_else(|| unreachable!("connection closed without error")))
    }
}

pub struct ConnectionBuilder<C: Any + ?Sized> {
    protocols_initializers: Vec<Box<dyn InitProtocols<C>>>,
    _connection: PhantomData<C>,
}

impl<C: quic::Connection + ?Sized> ConnectionBuilder<C> {
    pub fn new(settings: Arc<Settings>) -> Self {
        let builder = Self {
            protocols_initializers: Vec::new(),
            _connection: PhantomData,
        };
        builder.protocol(DHttpProtocolFactory::new(settings))
    }

    pub fn protocol<F: ProductProtocol<C>>(mut self, facroty: F) -> Self {
        self.protocols_initializers.push(Box::new(facroty));
        self
    }

    pub async fn build(&self, quic: C) -> Result<Connection<C>, quic::ConnectionError>
    where
        C: Sized,
    {
        let quic = Arc::new(QuicConnection::new(quic));
        let mut protocols = Protocols::new();

        for initializer in &self.protocols_initializers {
            initializer.init_protocols(&quic, &mut protocols).await?;
        }

        let protocols = Arc::new(protocols);
        let state = ConnectionState { quic, protocols };
        tokio::spawn(ConnectionState::accept_uni_stream_task(state.clone()).in_current_span());
        tokio::spawn(ConnectionState::accept_bi_stream_task(state.clone()).in_current_span());

        Ok(Connection(state))
    }
}

#[derive(Debug)]
pub struct ConnectionState<C: ?Sized> {
    quic: Arc<QuicConnection<C>>,
    protocols: Arc<Protocols<C>>,
}

impl<C: ?Sized> ConnectionState<C> {
    pub fn quic_connection(&self) -> &Arc<QuicConnection<C>> {
        &self.quic
    }

    pub fn protocol<P: Any>(&self) -> Option<&P> {
        self.protocols.get::<P>()
    }
}

impl<C: quic::Close + ?Sized> ConnectionState<C> {
    pub fn closed(&self) -> impl Future<Output = quic::ConnectionError> + Send + use<C> {
        self.quic.error()
    }

    // TODO: close with handy way(code + reason)
    pub fn close(&self, error: &(impl HasErrorCode + ?Sized)) {
        self.quic.close(error);
    }
}

impl<C: quic::WithLocalAgent + ?Sized> ConnectionState<C> {
    pub async fn local_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::LocalAgent>>, quic::ConnectionError> {
        self.quic
            .inner
            .local_agent()
            .await
            .map(|option| option.map(|a| Arc::new(a) as Arc<dyn agent::LocalAgent>))
    }
}

impl<C: quic::WithRemoteAgent + ?Sized> ConnectionState<C> {
    pub async fn remote_agent(
        &self,
    ) -> Result<Option<Arc<dyn agent::RemoteAgent>>, quic::ConnectionError> {
        self.quic
            .inner
            .remote_agent()
            .await
            .map(|option| option.map(|a| Arc::new(a) as Arc<dyn agent::RemoteAgent>))
    }
}

impl<C: quic::Connection + ?Sized> ConnectionState<C> {
    async fn accept_bi_stream_task(state: Self) {
        let task = async {
            loop {
                let (stream_reader, stream_writer) = match state.quic.accept_bi().await {
                    Ok(bi_stream) => bi_stream,
                    Err(error) => {
                        state.quic.handle_connection_error(error).await;
                        return;
                    }
                };
                let stream_reader = StreamReader::new(Box::pin(stream_reader));
                let stream_writer = SinkWriter::new(Box::pin(stream_writer));
                let peekable_bi_stream = (PeekableStreamReader::new(stream_reader), stream_writer);

                match state
                    .protocols
                    .accept_bi(&state.quic, peekable_bi_stream)
                    .await
                {
                    Ok(StreamVerdict::Accepted) => continue,
                    // If the stream header indicates a stream type that is not supported by
                    // the recipient, the remainder of the stream cannot be consumed as the
                    // semantics are unknown. Recipients of unknown stream types MUST
                    // either abort reading of the stream or discard incoming data without
                    // further processing. If reading is aborted, the recipient SHOULD use
                    // the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    // (Section 8.1). The recipient MUST NOT consider unknown stream types
                    // to be a connection error of any kind.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-9-4
                    Ok(StreamVerdict::Passed((mut stream_reader, mut stream_writer))) => {
                        let code = Code::H3_STREAM_CREATION_ERROR.into_inner();
                        _ = tokio::join!(stream_reader.stop(code), stream_writer.cancel(code))
                    }
                    Err(stream_error) => {
                        state.quic.handle_stream_error(stream_error).await;
                        continue;
                    }
                };
            }
        };
        tokio::select! {
            _ = task => {},
            _ = state.quic.error() => {},
        }
    }

    async fn accept_uni_stream_task(state: Self) {
        let task = async {
            loop {
                let stream_reader = match state.quic.accept_uni().await {
                    Ok(uni_stream) => uni_stream,
                    Err(error) => {
                        state.quic.handle_connection_error(error).await;
                        return;
                    }
                };
                let stream_reader = StreamReader::new(Box::pin(stream_reader));
                let peekable_uni_stream = PeekableStreamReader::new(stream_reader);

                match state
                    .protocols
                    .accept_uni(&state.quic, peekable_uni_stream)
                    .await
                {
                    Ok(StreamVerdict::Accepted) => continue,
                    // If the stream header indicates a stream type that is not supported by
                    // the recipient, the remainder of the stream cannot be consumed as the
                    // semantics are unknown. Recipients of unknown stream types MUST
                    // either abort reading of the stream or discard incoming data without
                    // further processing. If reading is aborted, the recipient SHOULD use
                    // the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    // (Section 8.1). The recipient MUST NOT consider unknown stream types
                    // to be a connection error of any kind.
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#section-9-4
                    Ok(StreamVerdict::Passed(mut stream_reader)) => {
                        let code = Code::H3_STREAM_CREATION_ERROR.into_inner();
                        let _ = stream_reader.stop(code).await;
                    }
                    Err(stream_error) => {
                        state.quic.handle_stream_error(stream_error).await;
                        continue;
                    }
                };
            }
        };
        tokio::select! {
            _ = task => {},
            _ = state.quic.error() => {},
        }
    }
}

impl<C: ?Sized> Clone for ConnectionState<C> {
    fn clone(&self) -> Self {
        Self {
            quic: self.quic.clone(),
            protocols: self.protocols.clone(),
        }
    }
}

#[derive(Debug)]
pub struct Connection<C: quic::Connection + ?Sized>(ConnectionState<C>);

impl<C: quic::Connection + ?Sized> ops::Deref for Connection<C> {
    type Target = ConnectionState<C>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: quic::Connection + ?Sized> Connection<C> {
    pub async fn new(settings: Arc<Settings>, quic: C) -> Result<Self, quic::ConnectionError>
    where
        C: Sized,
    {
        let quic = Arc::new(QuicConnection::new(quic));
        let mut protocols = Protocols::new();

        DHttpProtocolFactory::new(settings)
            .init_protocols(&quic, &mut protocols)
            .await?;
        QPackProtocolFactory::new()
            .init_protocols(&quic, &mut protocols)
            .await?;

        let protocols = Arc::new(protocols);
        let state = ConnectionState { quic, protocols };
        tokio::spawn(ConnectionState::accept_uni_stream_task(state.clone()).in_current_span());
        tokio::spawn(ConnectionState::accept_bi_stream_task(state.clone()).in_current_span());

        Ok(Connection(state))
    }
}

impl<C: quic::Connection + ?Sized> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(&Code::H3_NO_ERROR);
    }
}
