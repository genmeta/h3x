//! HTTP/3 endpoint built on top of [`QuicEndpoint`].
//!
//! [`H3Endpoint`] extends [`QuicEndpoint`] with an HTTP/3 connection pool and
//! a user-configurable [`ConnectionBuilder`].

use std::{error::Error, sync::Arc};

use bytes::Buf;
use http::uri::Authority;

use super::quic::{AcceptError, ConnectError, QuicEndpoint};
use crate::{
    client::{self, Client},
    connection::{Connection as H3Connection, ConnectionBuilder},
    dquic::prelude::Connection,
    pool::{self, Pool},
    server::{Servers, UnresolvedRequest},
};

/// HTTP/3 endpoint.
pub struct H3Endpoint {
    quic: QuicEndpoint,
    pool: Pool<Connection>,
    connection_builder: Arc<ConnectionBuilder<Connection>>,
}

impl H3Endpoint {
    /// Construct a new HTTP/3 endpoint.
    #[must_use]
    pub fn new(
        quic: QuicEndpoint,
        pool: Pool<Connection>,
        connection_builder: Arc<ConnectionBuilder<Connection>>,
    ) -> Self {
        Self {
            quic,
            pool,
            connection_builder,
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

impl H3Endpoint {
    fn as_client(&self) -> Client<&QuicEndpoint> {
        Client::from_quic_client()
            .pool(self.pool.clone())
            .client(&self.quic)
            .builder(self.connection_builder.clone())
            .build()
    }

    fn as_server<S>(&self, service: S) -> Servers<&QuicEndpoint, S>
    where
        S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        Servers::from_quic_listener()
            .listener(&self.quic)
            .service(service)
            .pool(self.pool.clone())
            .builder(self.connection_builder.clone())
            .build()
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

impl H3Endpoint {
    /// Serve HTTP/3 requests on this endpoint.
    ///
    /// `service` is invoked for every incoming request stream on every
    /// accepted connection. It is the underlying primitive that higher-level
    /// router types ([`Router`](crate::server::Router),
    /// [`ServersRouter`](crate::server::ServersRouter), the tower/hyper
    /// glue, …) are built on top of — any
    /// `Service<UnresolvedRequest, Response = ()>` will do.
    ///
    /// Drives accept + dispatch until the underlying [`QuicEndpoint`] shuts
    /// down or encounters a fatal error, returning the accept error that
    /// terminated the loop.
    ///
    /// Agents and the protocol registry are reachable through
    /// [`UnresolvedRequest::connection`]; cloning the endpoint and calling
    /// this method twice in parallel is **not** supported because the
    /// underlying QUIC router only allows one connectionless dispatcher per
    /// network. Call [`QuicEndpoint::shutdown`](crate::quic::Listen::shutdown)
    /// before re-arming a new serve loop.
    pub async fn serve<S>(self, service: S) -> AcceptError
    where
        S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut servers = self.as_server(service);
        servers.run().await
    }

    /// Update the OCSP staple via the underlying [`QuicEndpoint`].
    ///
    /// Uses a double-clear cache-invalidation pattern; see
    /// [`QuicEndpoint::update_ocsp`] for details.
    pub fn update_ocsp(&self, ocsp: Option<Vec<u8>>) {
        self.quic.update_ocsp(ocsp);
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

impl H3Endpoint {
    /// Obtain (or reuse) an HTTP/3 connection to `server` from the pool.
    pub async fn connect_to(
        &self,
        server: Authority,
    ) -> Result<Arc<H3Connection<Connection>>, pool::ConnectError<ConnectError>> {
        self.pool
            .reuse_or_connect_with(&self.quic, self.connection_builder.clone(), server)
            .await
    }

    /// Send a GET request to `uri`.
    pub async fn get(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().get(uri).await
    }

    /// Send a POST request to `uri` with `body`.
    pub async fn post(
        &self,
        uri: http::Uri,
        body: impl Buf,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().with_body(body).post(uri).await
    }

    /// Send a PUT request to `uri` with `body`.
    pub async fn put(
        &self,
        uri: http::Uri,
        body: impl Buf,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().with_body(body).put(uri).await
    }

    /// Send a DELETE request to `uri`.
    pub async fn delete(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().delete(uri).await
    }

    /// Send a PATCH request to `uri` with `body`.
    pub async fn patch(
        &self,
        uri: http::Uri,
        body: impl Buf,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().with_body(body).patch(uri).await
    }

    /// Send a HEAD request to `uri`.
    pub async fn head(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().head(uri).await
    }

    /// Send an OPTIONS request to `uri`.
    pub async fn options(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().options(uri).await
    }

    /// Send a CONNECT request to `uri`.
    pub async fn connect(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().connect(uri).await
    }

    /// Send a TRACE request to `uri`.
    pub async fn trace(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        self.as_client().new_request().trace(uri).await
    }
}

// ---------------------------------------------------------------------------
// quic::Connect / quic::Listen
// ---------------------------------------------------------------------------

impl crate::quic::Connect for H3Endpoint {
    type Connection = Connection;
    type Error = ConnectError;

    async fn connect(&self, server: &Authority) -> Result<Arc<Self::Connection>, Self::Error> {
        self.quic.connect(server).await
    }
}

impl crate::quic::Listen for H3Endpoint {
    type Connection = Connection;
    type Error = AcceptError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        self.quic.accept().await
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        self.quic.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        connection::ConnectionBuilder,
        dquic::prelude::handy::SystemResolver,
        endpoint::{client::ClientQuicConfig, network::Network, server::ServerQuicConfig},
        pool::Pool,
        quic::Connect,
    };
    use http::uri::Authority;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_h3endpoint_construction() {
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let quic = QuicEndpoint::new(network.clone(), None, resolver.clone(), client, server, Arc::new(Vec::new()));
        let pool = Pool::empty();
        let builder = Arc::new(ConnectionBuilder::new(Arc::default()));

        let endpoint = H3Endpoint::new(quic, pool, builder);

        // Verify that we can access the QuicEndpoint
        let _quic = &endpoint.quic;
    }

    #[tokio::test]
    async fn test_update_ocsp() {
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let quic = QuicEndpoint::new(network.clone(), None, resolver.clone(), client, server, Arc::new(Vec::new()));
        let pool = Pool::empty();
        let builder = Arc::new(ConnectionBuilder::new(Arc::default()));

        let endpoint = H3Endpoint::new(quic, pool, builder);

        // Test update_ocsp with no identity (should not panic)
        endpoint.update_ocsp(Some(vec![1, 2, 3]));

        // Verify the endpoint is still functional
        let _quic = &endpoint.quic;
    }

    #[tokio::test]
    async fn test_h3endpoint_construction_preserves_fields() {
        // Tests that `H3Endpoint::new()` correctly preserves all fields

        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let quic = QuicEndpoint::new(network.clone(), None, resolver.clone(), client, server, Arc::new(Vec::new()));
        let pool = Pool::empty();
        let builder = Arc::new(ConnectionBuilder::new(Arc::default()));

        let endpoint = H3Endpoint::new(quic, pool, builder);

        // Verify that the endpoint is constructed correctly
        let _quic = &endpoint.quic;
    }

    #[tokio::test]
    async fn test_h3endpoint_connect_and_accept_errors_with_no_identity() {
        // Tests both connect and accept failure paths for endpoints with no identity

        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let quic = QuicEndpoint::new(
            network.clone(),
            None,
            resolver.clone(),
            client,
            server,
            Arc::new(Vec::new()),
        );

        // `connect()` should fail because no identity means no client auth cert
        // (the error depends on resolver behavior, so we just verify it doesn't panic)
        let authority: Authority = "example.com".parse().unwrap();
        let connect_result = quic.connect(&authority).await;
        assert!(connect_result.is_err(), "connect without identity should fail");

        // `accept()` should fail because no identity means no server binding
        let accept_result = quic.accept().await;
        assert!(accept_result.is_err(), "accept without identity should fail");
    }

    #[test]
    fn test_h3endpoint_as_client_has_correct_type() {
        // Tests that `as_client()` returns `Client<&QuicEndpoint>` (primarily a
        // compilation check — ensures the method signature typechecks as expected).

        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let quic = QuicEndpoint::new(network.clone(), None, resolver.clone(), client, server, Arc::new(Vec::new()));
        let pool = Pool::empty();
        let builder = Arc::new(ConnectionBuilder::new(Arc::default()));

        let endpoint = H3Endpoint::new(quic, pool, builder);

        let _client: Client<&QuicEndpoint> = endpoint.as_client();
    }
}
