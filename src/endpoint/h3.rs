//! HTTP/3 endpoint built on top of [`QuicEndpoint`].
//!
//! [`H3Endpoint`] extends [`QuicEndpoint`] with an HTTP/3 connection pool and
//! a user-configurable [`ConnectionBuilder`]. It transparently derefs to the
//! underlying [`QuicEndpoint`] so it inherits the [`Connect`](crate::quic::Connect)
//! and [`Listen`](crate::quic::Listen) trait impls.

use std::{error::Error, ops::Deref, sync::Arc};

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
    /// Underlying QUIC endpoint.
    pub quic: Arc<QuicEndpoint>,
    /// Connection pool shared across HTTP/3 requests.
    pub pool: Pool<Connection>,
    /// Builder used to construct HTTP/3 connections on top of raw QUIC.
    pub connection_builder: Arc<ConnectionBuilder<Connection>>,
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
            quic: Arc::new(quic),
            pool,
            connection_builder,
        }
    }

    /// Get a mutable reference to the QUIC endpoint, cloning if shared.
    pub fn quic_mut(&mut self) -> &mut QuicEndpoint {
        Arc::make_mut(&mut self.quic)
    }
}

impl Clone for H3Endpoint {
    fn clone(&self) -> Self {
        // Reset the pool on Clone: each endpoint owns its own connection
        // pool so parallel clients do not stomp on one another.
        Self {
            quic: self.quic.clone(),
            pool: Pool::empty(),
            connection_builder: self.connection_builder.clone(),
        }
    }
}

impl Deref for H3Endpoint {
    type Target = QuicEndpoint;

    fn deref(&self) -> &Self::Target {
        &self.quic
    }
}

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
        let mut servers = Servers::from_quic_listener()
            .listener(Arc::unwrap_or_clone(self.quic))
            .service(service)
            .pool(self.pool)
            .builder(self.connection_builder)
            .build();
        servers.run().await
    }
}

// ---------------------------------------------------------------------------
// Convenience client methods
// ---------------------------------------------------------------------------

impl H3Endpoint {
    /// Obtain (or reuse) an HTTP/3 connection to `server` from the pool.
    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<H3Connection<Connection>>, pool::ConnectError<ConnectError>> {
        self.pool
            .reuse_or_connect_with(&*self.quic, self.connection_builder.clone(), server)
            .await
    }

    /// Build a temporary [`Client`] that shares this endpoint's pool and
    /// configuration. Cheap — only Arc clones.
    fn as_client(&self) -> Client<QuicEndpoint> {
        Client::from_quic_client()
            .pool(self.pool.clone())
            .client((*self.quic).clone())
            .builder(self.connection_builder.clone())
            .build()
    }

    /// Send a GET request to `uri`.
    pub async fn get(
        &self,
        uri: http::Uri,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        let client = self.as_client();
        client.new_request().get(uri).await
    }

    /// Send a POST request to `uri` with `body`.
    pub async fn post(
        &self,
        uri: http::Uri,
        body: impl Buf,
    ) -> Result<(client::Request, client::Response), client::RequestError<ConnectError>> {
        let client = self.as_client();
        client.new_request().with_body(body).post(uri).await
    }
}
