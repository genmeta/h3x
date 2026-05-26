//! Generic HTTP/3 endpoint.
//!
//! [`H3Endpoint`] combines a QUIC transport `Q` with a selected connection
//! type `C`, providing raw HTTP/3 connection pooling and request serving.
//! Client connection access requires `Q: quic::Connect<Connection = C>`;
//! server request serving requires `Q: quic::Listen<Connection = C>`.
//!
//! [`ConnectionBuilder`]: crate::connection::ConnectionBuilder

use std::{any::Any, error::Error, sync::Arc};

use bon::bon;
use http::uri::Authority;
use snafu::ResultExt;
use tower_service::Service;
use tracing::Instrument;

use crate::{
    connection::{Connection as H3Connection, ConnectionBuilder},
    endpoint::server::UnresolvedRequest,
    message::stream::{ReadStream, WriteStream},
    pool::{self, Pool},
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

pub mod server;

/// Generic HTTP/3 endpoint parameterized over a QUIC transport `Q` and a
/// connection type `C`.
///
/// `Q` carries no struct-level constraint — abilities are encoded at the
/// method level:
///
/// | Capability | Bound |
/// |---|---|
/// | Client connection access (connect)    | `Q: quic::Connect<Connection = C>` |
/// | Server (serve, serve_owned)            | `Q: quic::Listen<Connection = C>`  |
pub struct H3Endpoint<Q, C: quic::Connection> {
    pub(crate) quic: Q,
    pub(crate) builder: Arc<ConnectionBuilder<C>>,
    pub(crate) pool: Pool<C>,
}

/// RAII guard for mutable access to [`H3Endpoint`]'s QUIC transport.
///
/// On drop, clears the endpoint's connection pool via [`Pool::clear`],
/// ensuring no stale connections remain after QUIC configuration changes.
pub struct QuicMutGuard<'a, Q, C: quic::Connection> {
    quic: &'a mut Q,
    pool: &'a Pool<C>,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module)]
pub enum AcceptError<E: Error + 'static> {
    #[snafu(display("failed to accept QUIC connection"))]
    Accept { source: E },
    #[snafu(display("failed to initialize H3 connection"))]
    Build { source: quic::ConnectionError },
}

impl<Q, C: quic::Connection> std::ops::Deref for QuicMutGuard<'_, Q, C> {
    type Target = Q;
    fn deref(&self) -> &Self::Target {
        self.quic
    }
}

impl<Q, C: quic::Connection> std::ops::DerefMut for QuicMutGuard<'_, Q, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.quic
    }
}

impl<Q, C: quic::Connection> Drop for QuicMutGuard<'_, Q, C> {
    fn drop(&mut self) {
        self.pool.clear();
    }
}

#[bon]
impl<Q, C: quic::Connection> H3Endpoint<Q, C> {
    /// Construct a new HTTP/3 endpoint.
    #[builder]
    pub fn new(quic: Q, #[builder(default)] builder: Arc<ConnectionBuilder<C>>) -> Self {
        Self {
            quic,
            builder,
            pool: Pool::empty(),
        }
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
{
    /// Construct a new HTTP/3 endpoint with default pool and builder.
    pub fn new(quic: Q) -> Self {
        H3Endpoint::builder().quic(quic).build()
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C> {
    /// Obtain a mutable guard for the QUIC transport.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting `Q`.
    /// On drop, the connection pool is cleared via [`Pool::clear`].
    pub fn quic_mut(&mut self) -> QuicMutGuard<'_, Q, C> {
        QuicMutGuard {
            quic: &mut self.quic,
            pool: &self.pool,
        }
    }

    /// Shared reference to the underlying QUIC transport.
    pub fn quic(&self) -> &Q {
        &self.quic
    }

    /// Clear all cached client connections.
    ///
    /// This is useful when an external network transition invalidates paths
    /// without mutating the QUIC transport configuration itself.
    pub fn clear_pool(&self) {
        self.pool.clear();
    }

    /// Number of cached client connection entries.
    pub fn pool_len(&self) -> usize {
        self.pool.len()
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
{
    /// Obtain (or reuse) an HTTP/3 connection to `server` from the pool.
    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<H3Connection<C>>, pool::ConnectError<Q::Error>> {
        self.pool
            .reuse_or_connect_with(&self.quic, self.builder.clone(), server)
            .await
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Listen<Connection = C>,
{
    /// Accept one QUIC connection and initialize it as an HTTP/3 connection.
    pub async fn accept(&mut self) -> Result<Arc<H3Connection<C>>, AcceptError<Q::Error>> {
        let quic_conn = self
            .quic
            .accept()
            .await
            .context(accept_error::AcceptSnafu)?;
        let h3_conn = self
            .builder
            .build(quic_conn)
            .await
            .context(accept_error::BuildSnafu)?;
        Ok(Arc::new(h3_conn))
    }

    /// Accept one HTTP/3 connection from a shared endpoint handle.
    ///
    /// Rust does not support overloading inherent methods by receiver type, so
    /// the shared-handle variant uses the same `*_owned` convention as
    /// [`H3Endpoint::serve_owned`].
    pub fn accept_owned<E>(
        self: &Arc<Self>,
    ) -> impl Future<Output = Result<Arc<H3Connection<C>>, AcceptError<E>>> + use<E, Q, C>
    where
        E: Error + Any,
        for<'a> &'a Q: quic::Listen<Connection = C, Error = E>,
    {
        let this = Arc::clone(self);
        let builder = this.builder.clone();
        let pool = this.pool.clone();
        async move {
            let mut ref_ep = H3Endpoint {
                quic: &this.quic,
                builder,
                pool,
            };
            ref_ep.accept().await
        }
    }
}

impl<Q, C> quic::Connect for H3Endpoint<Q, C>
where
    Q: quic::Connect<Connection = C>,
    C: quic::Connection,
{
    type Connection = C;
    type Error = Q::Error;

    fn connect<'a>(
        &'a self,
        server: &'a Authority,
    ) -> impl Future<Output = Result<Arc<Self::Connection>, Self::Error>> + Send + 'a {
        self.quic.connect(server)
    }
}

impl<Q, C> quic::Listen for H3Endpoint<Q, C>
where
    Q: quic::Listen<Connection = C>,
    C: quic::Connection,
{
    type Connection = C;
    type Error = Q::Error;

    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<Arc<Self::Connection>, Self::Error>> + Send + '_ {
        self.quic.accept()
    }

    fn shutdown(&self) -> impl Future<Output = Result<(), Self::Error>> + Send + '_ {
        self.quic.shutdown()
    }
}

impl<Q, C: quic::Connection> H3Endpoint<Q, C>
where
    Q: quic::Listen<Connection = C>,
{
    /// Accept and serve HTTP/3 connections in a loop.
    pub async fn serve<S>(&mut self, service: S) -> Result<(), <Q as quic::Listen>::Error>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        loop {
            let quic_conn = self.quic.accept().await?;
            let h3_conn = match self.builder.build(quic_conn).await {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    let report = snafu::Report::from_error(&e);
                    tracing::debug!(error = %report, "failed to build H3 connection");
                    continue;
                }
            };
            // Inherent termination: spawned task exits when accept_raw_message_stream
            // returns an error (connection closed) or qpack is no longer available.
            tokio::spawn(serve_connection(h3_conn, service.clone()).in_current_span());
        }
    }

    /// Serve HTTP/3 requests on an `Arc<H3Endpoint<Q, C>>`.
    ///
    /// The returned future does not capture `&self`, so it can be spawned:
    ///
    /// ```ignore
    /// let h3: Arc<H3Endpoint<QuicEndpoint, Connection>> = ...;
    /// tokio::spawn(h3.serve(router));
    /// ```
    pub fn serve_owned<S>(
        self: &Arc<Self>,
        service: S,
    ) -> impl Future<Output = Result<(), <Q as quic::Listen>::Error>> + use<S, Q, C>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
        for<'a> &'a Q: quic::Listen<Connection = C, Error = <Q as quic::Listen>::Error>,
    {
        let this = Arc::clone(self);
        let pool = this.pool.clone();
        let builder = this.builder.clone();
        async move {
            let mut ref_ep = H3Endpoint {
                quic: &this.quic,
                builder,
                pool,
            };
            ref_ep.serve(service).await
        }
    }
}

/// Serve requests from a single accepted H3 connection.
///
/// Inherent termination: returns when [`H3Connection::accept_raw_message_stream`]
/// produces an error (connection closed) or when the QPACK module is no longer
/// available.
async fn serve_connection<C, S>(h3_conn: Arc<H3Connection<C>>, mut service: S)
where
    C: quic::Connection,
    S: Service<UnresolvedRequest, Response = ()> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let erased = Arc::new(h3_conn.erase());

    loop {
        let (mut reader, writer) = match h3_conn.accept_raw_message_stream().await {
            Ok(s) => s,
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "stopping request handler for connection");
                return;
            }
        };
        let stream_id = match GetStreamIdExt::stream_id(&mut reader).await {
            Ok(id) => StreamId(id),
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "failed to get stream id, skipping request");
                continue;
            }
        };
        let qpack = match h3_conn.qpack() {
            Ok(q) => q,
            Err(e) => {
                let report = snafu::Report::from_error(&e);
                tracing::debug!(error = %report, "qpack unavailable, stopping handler");
                return;
            }
        };
        let read_stream = ReadStream::new(reader, qpack.decoder.clone(), (*erased).clone());
        let write_stream = WriteStream::new(writer, qpack.encoder.clone(), (*erased).clone());

        let request = UnresolvedRequest {
            stream_id,
            read_stream,
            write_stream,
            connection: erased.clone(),
        };

        // Inherent termination: the spawned task exits when the service future resolves.
        tokio::spawn(serve_request(&mut service, request).in_current_span());
    }
}

/// Spawn a task to process a single request through `service`.
///
/// Inherent termination: the spawned task exits when the service future resolves.
fn serve_request<S>(
    service: &mut S,
    request: UnresolvedRequest,
) -> impl Future<Output = ()> + use<S>
where
    S: Service<UnresolvedRequest, Response = ()> + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let fut = service.call(request);
    async move {
        if let Err(error) = fut.await {
            let boxed: Box<dyn Error + Send + Sync> = error.into();
            let report = snafu::Report::from_error(boxed.as_ref());
            tracing::debug!(error = %report, "request handler returned error");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::{Ready, pending, ready},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use dhttp_identity::identity;
    use http::uri::Authority;
    use tower_service::Service;

    use super::*;
    use crate::{
        connection::tests::{
            MockConnection, TestLocalAgent, TestReadStream, TestRemoteAgent, TestWriteStream,
        },
        pool::ReuseableConnection,
        varint::VarInt,
    };

    /// Minimal quic::Connect implementation for testing QuicMutGuard.
    struct MockConnect;

    impl quic::Connect for MockConnect {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn connect<'a>(
            &'a self,
            _server: &'a Authority,
        ) -> Result<Arc<Self::Connection>, Self::Error> {
            unreachable!("connect is not called in guard tests")
        }
    }

    #[derive(Debug)]
    struct BuildableConnection;

    impl quic::ManageStream for BuildableConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(TestWriteStream)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAgent for BuildableConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for BuildableConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for BuildableConnection {
        fn close(&self, _code: crate::error::Code, _reason: std::borrow::Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    #[derive(Debug, Clone)]
    struct NamedRemoteAgent {
        name: &'static str,
    }

    impl identity::RemoteAgent for NamedRemoteAgent {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug)]
    struct IdentifiedConnection {
        remote_name: &'static str,
    }

    impl IdentifiedConnection {
        fn new(remote_name: &'static str) -> Self {
            Self { remote_name }
        }
    }

    impl quic::ManageStream for IdentifiedConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(TestWriteStream)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAgent for IdentifiedConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for IdentifiedConnection {
        type RemoteAgent = NamedRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, quic::ConnectionError> {
            Ok(Some(NamedRemoteAgent {
                name: self.remote_name,
            }))
        }
    }

    impl quic::Lifecycle for IdentifiedConnection {
        fn close(&self, _code: crate::error::Code, _reason: std::borrow::Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    fn test_connection_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    #[derive(Clone)]
    struct CountingConnect<C: quic::Connection> {
        calls: Arc<AtomicUsize>,
        servers: Arc<Mutex<Vec<Authority>>>,
        result: Arc<Mutex<Result<Arc<C>, quic::ConnectionError>>>,
    }

    impl<C: quic::Connection> CountingConnect<C> {
        fn succeed(connection: C) -> Self {
            Self {
                calls: Arc::default(),
                servers: Arc::default(),
                result: Arc::new(Mutex::new(Ok(Arc::new(connection)))),
            }
        }

        fn fail(error: quic::ConnectionError) -> Self {
            Self {
                calls: Arc::default(),
                servers: Arc::default(),
                result: Arc::new(Mutex::new(Err(error))),
            }
        }
    }

    impl<C: quic::Connection> quic::Connect for CountingConnect<C> {
        type Connection = C;
        type Error = quic::ConnectionError;

        async fn connect<'a>(
            &'a self,
            server: &'a Authority,
        ) -> Result<Arc<Self::Connection>, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.servers
                .lock()
                .expect("server log mutex should not be poisoned")
                .push(server.clone());
            self.result
                .lock()
                .expect("result mutex should not be poisoned")
                .clone()
        }
    }

    #[derive(Default)]
    struct MockListen {
        accepted: Arc<AtomicUsize>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl quic::Listen for MockListen {
        type Connection = BuildableConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            self.accepted.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(BuildableConnection))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    impl quic::Listen for &MockListen {
        type Connection = BuildableConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            self.accepted.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(BuildableConnection))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    struct FailingListen;

    impl quic::Listen for FailingListen {
        type Connection = BuildableConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            Err(test_connection_error("accept failed"))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            Err(test_connection_error("shutdown failed"))
        }
    }

    impl quic::Listen for &FailingListen {
        type Connection = BuildableConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            Err(test_connection_error("shared accept failed"))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            Err(test_connection_error("shared shutdown failed"))
        }
    }

    struct UnbuildableListen;

    impl quic::Listen for UnbuildableListen {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            Ok(Arc::new(MockConnection::new()))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl quic::Listen for &UnbuildableListen {
        type Connection = MockConnection;
        type Error = quic::ConnectionError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            Ok(Arc::new(MockConnection::new()))
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct NoopService;

    impl Service<UnresolvedRequest> for NoopService {
        type Response = ();
        type Error = quic::ConnectionError;
        type Future = Ready<Result<(), Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: UnresolvedRequest) -> Self::Future {
            ready(Ok(()))
        }
    }

    #[test]
    fn h3_endpoint_implements_quic_connect_when_transport_connects() {
        fn assert_connect<T: quic::Connect<Connection = MockConnection>>() {}

        assert_connect::<H3Endpoint<MockConnect, MockConnection>>();
        assert_connect::<Arc<H3Endpoint<MockConnect, MockConnection>>>();
    }

    #[test]
    fn h3_endpoint_implements_quic_listen_when_transport_listens() {
        fn assert_listen<T: quic::Listen<Connection = BuildableConnection>>() {}

        assert_listen::<H3Endpoint<MockListen, BuildableConnection>>();
    }

    #[test]
    fn builder_preserves_custom_builder_and_quic_accessor_returns_transport() {
        let listen = MockListen::default();
        let accepted = listen.accepted.clone();
        let builder: Arc<ConnectionBuilder<BuildableConnection>> =
            Arc::new(ConnectionBuilder::new(Arc::default()));
        let endpoint = H3Endpoint::builder()
            .quic(listen)
            .builder(builder.clone())
            .build();

        assert!(Arc::ptr_eq(&builder, &endpoint.builder));
        assert!(Arc::ptr_eq(&accepted, &endpoint.quic().accepted));
        assert_eq!(endpoint.pool_len(), 0);
    }

    #[tokio::test]
    async fn inherent_connect_builds_and_reuses_pooled_h3_connection() {
        let connector = CountingConnect::succeed(IdentifiedConnection::new("test-remote"));
        let calls = connector.calls.clone();
        let servers = connector.servers.clone();
        let endpoint = H3Endpoint::new(connector);
        let server: Authority = "test-remote:443".parse().unwrap();

        let first = endpoint
            .connect(server.clone())
            .await
            .expect("first connect should build H3");
        let second = endpoint
            .connect(server.clone())
            .await
            .expect("second connect should reuse H3");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            servers
                .lock()
                .expect("server log mutex should not be poisoned")
                .as_slice(),
            &[server],
        );
        assert_eq!(endpoint.pool_len(), 1);
    }

    #[tokio::test]
    async fn inherent_connect_returns_connector_error() {
        let endpoint = H3Endpoint::<_, IdentifiedConnection>::new(CountingConnect::fail(
            test_connection_error("connector failed"),
        ));
        let server: Authority = "test-remote:443".parse().unwrap();

        let error = endpoint
            .connect(server)
            .await
            .expect_err("connector error should be returned");

        assert!(matches!(error, pool::ConnectError::Connector { source } if source.is_transport()));
    }

    #[tokio::test]
    async fn inherent_connect_rejects_peer_identity_mismatch() {
        let connector = CountingConnect::succeed(IdentifiedConnection::new("actual.example"));
        let endpoint = H3Endpoint::new(connector);
        let server: Authority = "expected.example:443".parse().unwrap();

        let error = endpoint
            .connect(server)
            .await
            .expect_err("identity mismatch should be returned");

        assert!(matches!(
            error,
            pool::ConnectError::IncorrectIdentity { expected, actual }
                if expected == "expected.example" && actual.as_deref() == Some("actual.example")
        ));
    }

    #[tokio::test]
    async fn quic_connect_impl_delegates_to_inner_transport() {
        let connector = CountingConnect::succeed(IdentifiedConnection::new("delegated.example"));
        let calls = connector.calls.clone();
        let endpoint = H3Endpoint::new(connector);
        let server: Authority = "delegated.example:443".parse().unwrap();

        let connection = quic::Connect::connect(&endpoint, &server)
            .await
            .expect("delegated connect should return raw QUIC connection");

        assert_eq!(connection.remote_name, "delegated.example");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(endpoint.pool_len(), 0);
    }

    #[tokio::test]
    async fn accept_builds_h3_connection_from_accepted_quic_connection() {
        let listen = MockListen::default();
        let accepted = listen.accepted.clone();
        let mut endpoint = H3Endpoint::builder().quic(listen).build();

        let connection = endpoint.accept().await.expect("accept should build H3");

        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        connection.qpack().expect("qpack should be initialized");
    }

    #[tokio::test]
    async fn accept_returns_quic_accept_error() {
        let mut endpoint = H3Endpoint::builder().quic(FailingListen).build();

        let error = endpoint
            .accept()
            .await
            .expect_err("accept error should be returned");

        assert!(matches!(error, AcceptError::Accept { source } if source.is_transport()));
    }

    #[tokio::test]
    async fn accept_returns_h3_build_error() {
        let mut endpoint = H3Endpoint::builder().quic(UnbuildableListen).build();

        let error = endpoint
            .accept()
            .await
            .expect_err("build error should be returned");

        assert!(matches!(error, AcceptError::Build { source } if source.is_transport()));
    }

    #[tokio::test]
    async fn accept_owned_builds_h3_connection_from_shared_endpoint() {
        let listen = MockListen::default();
        let accepted = listen.accepted.clone();
        let endpoint = Arc::new(H3Endpoint::builder().quic(listen).build());

        let connection = endpoint
            .accept_owned()
            .await
            .expect("accept_owned should build H3");

        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        connection.qpack().expect("qpack should be initialized");
    }

    #[tokio::test]
    async fn accept_owned_returns_h3_build_error_from_shared_endpoint() {
        let endpoint = Arc::new(H3Endpoint::builder().quic(UnbuildableListen).build());

        let error = endpoint
            .accept_owned()
            .await
            .expect_err("shared build error should be returned");

        assert!(matches!(error, AcceptError::Build { source } if source.is_transport()));
    }

    #[tokio::test]
    async fn quic_listen_impl_delegates_accept_and_shutdown_to_inner_transport() {
        let listen = MockListen::default();
        let accepted = listen.accepted.clone();
        let shutdowns = listen.shutdowns.clone();
        let mut endpoint = H3Endpoint::builder().quic(listen).build();

        let _connection = quic::Listen::accept(&mut endpoint)
            .await
            .expect("listen impl should return raw QUIC connection");
        quic::Listen::shutdown(&endpoint)
            .await
            .expect("listen impl should delegate shutdown");

        assert_eq!(accepted.load(Ordering::Relaxed), 1);
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn serve_returns_quic_accept_error() {
        let mut endpoint = H3Endpoint::builder().quic(FailingListen).build();

        let error = endpoint
            .serve(NoopService)
            .await
            .expect_err("serve should return listener accept error");

        assert!(error.is_transport());
    }

    #[tokio::test]
    async fn serve_owned_returns_quic_accept_error_from_shared_endpoint() {
        let endpoint = Arc::new(H3Endpoint::builder().quic(FailingListen).build());

        let error = endpoint
            .serve_owned(NoopService)
            .await
            .expect_err("serve_owned should return shared listener accept error");

        assert!(error.is_transport());
    }

    /// Verify that QuicMutGuard provides mutable access to the inner QUIC transport.
    #[test]
    fn test_quic_mut_guard_deref_mut() {
        let mut quic = MockConnect;
        let pool = Pool::<MockConnection>::empty();
        let mut guard = QuicMutGuard {
            quic: &mut quic,
            pool: &pool,
        };

        // Verify Deref produces &MockConnect
        let _reference: &MockConnect = &guard;
        let _ = _reference;

        // Verify DerefMut produces &mut MockConnect
        let _mut_reference: &mut MockConnect = &mut guard;
        let _ = _mut_reference;

        drop(guard);
    }

    /// Verify that dropping QuicMutGuard clears the connection pool.
    #[test]
    fn test_quic_mut_guard_drop_clears_pool() {
        let mut quic = MockConnect;
        let pool = Pool::<MockConnection>::empty();

        // Insert an entry into the pool to verify clearing
        let auth: Authority = "example.com:443".parse().unwrap();
        pool.connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.len(), 1);

        {
            let guard = QuicMutGuard {
                quic: &mut quic,
                pool: &pool,
            };
            // Guard holds reference; pool still has entries
            assert_eq!(pool.len(), 1);
            drop(guard);
        } // guard dropped, pool.clear() called

        assert_eq!(pool.len(), 0);
    }

    /// Verify that H3Endpoint::quic_mut provides mutable access to the inner
    /// QUIC transport.
    #[test]
    fn test_quic_mut_access() {
        let mut h3 = H3Endpoint::new(MockConnect);

        let guard = h3.quic_mut();
        let _: &MockConnect = &guard; // verify Deref works
        drop(guard);
    }

    /// Verify that dropping the guard from H3Endpoint::quic_mut clears the
    /// connection pool.
    #[test]
    fn test_quic_mut_drop_clears_pool() {
        let mut h3 = H3Endpoint::new(MockConnect);

        // Insert an entry into the pool
        let auth: Authority = "example.com:443".parse().unwrap();
        h3.pool
            .connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(h3.pool.len(), 1);

        {
            let _guard = h3.quic_mut();
        } // guard dropped, pool.clear() called

        assert_eq!(h3.pool.len(), 0);
    }

    #[test]
    fn test_clear_pool_clears_endpoint_connections() {
        let h3 = H3Endpoint::new(MockConnect);

        let auth: Authority = "example.com:443".parse().unwrap();
        h3.pool
            .connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(h3.pool_len(), 1);

        h3.clear_pool();

        assert_eq!(h3.pool_len(), 0);
    }
}
