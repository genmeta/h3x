use std::{
    any::Any,
    collections::hash_map::DefaultHasher,
    error::Error as StdError,
    fmt::{self, Debug},
    hash::{Hash, Hasher},
    io,
    marker::PhantomData,
    ops,
    sync::Arc,
};

use futures::FutureExt;
use snafu::Snafu;
use tracing::Instrument;

use crate::{
    codec::{PeekableStreamReader, SinkWriter, StreamReader},
    dhttp::{protocol::DHttpProtocolFactory, settings::Settings},
    error::{Code, HasErrorCode},
    protocol::{InitProtocols, ProductProtocol, Protocols, StreamVerdict, type_id_as_u128},
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

    /// Returns `true` if a connection error has been recorded.
    ///
    /// This is a cheap, non-blocking check used by the connection pool to
    /// detect dead connections before attempting to reuse them.
    pub fn is_closed(&self) -> bool {
        self.error.is_set()
    }
}

impl<C: quic::Check + ?Sized> QuicConnection<C> {
    /// Actively probe the underlying QUIC connection to check if it is still usable.
    ///
    /// Unlike [`is_closed`](Self::is_closed), this queries the QUIC layer directly
    /// and can detect silently-closed connections (e.g. idle timeout).
    /// If a dead connection is detected, the error is recorded so that
    /// [`is_closed`](Self::is_closed) and [`error`](Self::error) also reflect it.
    pub fn check(&self) -> Result<(), quic::ConnectionError> {
        let result = self.inner.check();
        if let Err(ref error) = result {
            _ = self.error.set_with(|| error.clone());
        }
        result
    }
}

impl<C: quic::ManageStream + quic::Close + ?Sized> QuicConnection<C> {
    pub async fn open_bi(
        &self,
    ) -> Result<(C::StreamReader, C::StreamWriter), quic::ConnectionError> {
        match { self.inner.open_bi() }.await {
            Ok(streams) => Ok(streams),
            Err(error) => Err(self.handle_connection_error(error).await),
        }
    }

    pub async fn open_uni(&self) -> Result<C::StreamWriter, quic::ConnectionError> {
        match { self.inner.open_uni() }.await {
            Ok(stream) => Ok(stream),
            Err(error) => Err(self.handle_connection_error(error).await),
        }
    }
}

impl<C: quic::ManageStream + ?Sized> QuicConnection<C> {
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

impl<C: Any + ?Sized> fmt::Debug for ConnectionBuilder<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionBuilder")
            .field("protocols_count", &self.protocols_initializers.len())
            .finish()
    }
}

impl<C: quic::Connection + ?Sized> ConnectionBuilder<C> {
    pub fn new(settings: Arc<Settings>) -> Self {
        let builder = Self {
            protocols_initializers: Vec::new(),
            _connection: PhantomData,
        };
        builder
            .protocol(DHttpProtocolFactory::new(settings))
            .protocol(QPackProtocolFactory::new())
    }

    pub fn protocol<F: ProductProtocol<C>>(mut self, factory: F) -> Self {
        self.protocols_initializers.push(Box::new(factory));
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

impl<C: quic::Connection + ?Sized> Hash for ConnectionBuilder<C> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut hashes: Vec<(u128, u64)> = self
            .protocols_initializers
            .iter()
            .map(|f| {
                let mut hasher = DefaultHasher::new();
                f.identity_hash(&mut hasher);
                (type_id_as_u128(f.identity_type_id()), hasher.finish())
            })
            .collect();
        hashes.sort_by_key(|(tid, _)| *tid);
        for (tid, h) in &hashes {
            tid.hash(state);
            h.hash(state);
        }
    }
}

impl<C: quic::Connection + ?Sized> PartialEq for ConnectionBuilder<C> {
    fn eq(&self, other: &Self) -> bool {
        if self.protocols_initializers.len() != other.protocols_initializers.len() {
            return false;
        }
        let sort_key = |f: &dyn InitProtocols<C>| type_id_as_u128(f.identity_type_id());
        let mut self_sorted: Vec<_> = self
            .protocols_initializers
            .iter()
            .map(|f| f.as_ref())
            .collect();
        let mut other_sorted: Vec<_> = other
            .protocols_initializers
            .iter()
            .map(|f| f.as_ref())
            .collect();
        self_sorted.sort_by_key(|f| sort_key(*f));
        other_sorted.sort_by_key(|f| sort_key(*f));
        self_sorted
            .iter()
            .zip(other_sorted.iter())
            .all(|(a, b)| a.identity_eq(b.as_any()))
    }
}

impl<C: quic::Connection + ?Sized> Eq for ConnectionBuilder<C> {}

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

    /// Returns `true` if the underlying QUIC connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.quic.is_closed()
    }
}

impl<C: quic::Check + ?Sized> ConnectionState<C> {
    /// Actively probe the underlying QUIC connection to check if it is still usable.
    pub fn check(&self) -> Result<(), quic::ConnectionError> {
        self.quic.check()
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
        ConnectionBuilder::new(settings).build(quic).await
    }
}

impl<C: quic::Connection + ?Sized> Drop for Connection<C> {
    fn drop(&mut self) {
        self.close(&Code::H3_NO_ERROR);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        sync::Arc,
    };

    use futures::future::BoxFuture;

    use super::ConnectionBuilder;
    use crate::{
        codec::{BoxPeekableBiStream, BoxPeekableUniStream},
        connection::{QuicConnection, StreamError},
        dhttp::settings::{Setting, Settings},
        protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
        quic::{self, ConnectionError},
        varint::VarInt,
    };

    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    /// Local mock protocol for builder tests.
    #[derive(Debug)]
    struct MockProtocol;

    impl<C: quic::Connection + ?Sized> Protocol<C> for MockProtocol {
        fn accept_uni<'a>(
            &'a self,
            _: &'a Arc<QuicConnection<C>>,
            stream: BoxPeekableUniStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }

        fn accept_bi<'a>(
            &'a self,
            _: &'a Arc<QuicConnection<C>>,
            stream: BoxPeekableBiStream<C>,
        ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
            Box::pin(async move { Ok(StreamVerdict::Passed(stream)) })
        }
    }

    /// Local mock factory for builder tests.
    #[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
    struct MockFactory(u64);

    impl<C: quic::Connection + ?Sized> ProductProtocol<C> for MockFactory {
        type Protocol = MockProtocol;

        fn init<'a>(
            &'a self,
            _: &'a Arc<QuicConnection<C>>,
            _: &'a Protocols<C>,
        ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
            unimplemented!("not used in builder identity tests")
        }
    }

    #[cfg(feature = "gm-quic")]
    type C = gm_quic::prelude::Connection;

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_same_settings_equal_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s);
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_different_settings_different_hash() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(Setting::max_field_section_size(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_extra_protocol_different_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_order_independent_hash() {
        let s = Arc::new(Settings::default());
        // a: DHttpProtocolFactory, QPackProtocolFactory, MockFactory (from new + protocol)
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(7));
        // b: MockFactory first, then DHttpProtocolFactory, QPackProtocolFactory
        let b = {
            let builder = ConnectionBuilder::<C> {
                protocols_initializers: Vec::new(),
                _connection: std::marker::PhantomData,
            };
            builder
                .protocol(MockFactory(7))
                .protocol(crate::dhttp::protocol::DHttpProtocolFactory::new(s))
                .protocol(crate::qpack::protocol::QPackProtocolFactory::new())
        };
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_same_settings_eq() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone());
        let b = ConnectionBuilder::<C>::new(s);
        assert_eq!(a, b);
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_different_settings_not_eq() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(Setting::max_field_section_size(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);
        let a = ConnectionBuilder::<C>::new(s1);
        let b = ConnectionBuilder::<C>::new(s2);
        assert_ne!(a, b);
    }

    /// Simulates pool key distinction: two builders with different protocol stacks
    /// produce different hashes, so the pool stores them under separate keys.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_different_builders_different_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(1));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(2));
        // Pool computes hash via DefaultHasher the same way hash_of does.
        // Different protocol stacks must yield different keys.
        assert_ne!(hash_of(&a), hash_of(&b));
    }

    /// Simulates pool key reuse: two identical builders produce the same hash,
    /// so the pool correctly groups them under one key for connection reuse.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_same_builders_same_hash() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(42));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_eq!(hash_of(&a), hash_of(&b));
    }

    /// Verifies hash determinism: hashing the same builder twice yields the same
    /// value, and an identically-constructed builder also matches.
    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_hash_determinism() {
        let s = Arc::new(Settings::default());
        let builder = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(99));
        let h1 = hash_of(&builder);
        let h2 = hash_of(&builder);
        assert_eq!(
            h1, h2,
            "hashing the same builder twice must be deterministic"
        );

        // A second, identically-constructed builder must produce the same hash.
        let builder2 = ConnectionBuilder::<C>::new(s).protocol(MockFactory(99));
        assert_eq!(
            h1,
            hash_of(&builder2),
            "identical builders must hash equally"
        );
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_clone_like_rebuild_hash_determinism() {
        let s = Arc::new(Settings::default());
        let a = ConnectionBuilder::<C>::new(s.clone()).protocol(MockFactory(100));
        let b = ConnectionBuilder::<C>::new(s).protocol(MockFactory(100));
        assert_eq!(
            hash_of(&a),
            hash_of(&b),
            "builders built via same steps must hash identically"
        );
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn builder_mock_factory_included_in_hash() {
        let s = Arc::new(Settings::default());
        let base = ConnectionBuilder::<C>::new(s.clone());
        let with_mock = ConnectionBuilder::<C>::new(s).protocol(MockFactory(42));
        assert_ne!(
            hash_of(&base),
            hash_of(&with_mock),
            "adding MockFactory must change the hash"
        );
    }
}
