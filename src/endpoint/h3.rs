//! HTTP/3 endpoint built on top of [`QuicEndpoint`].
//!
//! [`H3Endpoint`] extends [`QuicEndpoint`] with an HTTP/3 connection pool and
//! a user-configurable [`ConnectionBuilder`]. It transparently derefs to the
//! underlying [`QuicEndpoint`] so it inherits the [`Connect`](crate::quic::Connect)
//! and [`Listen`](crate::quic::Listen) trait impls.

use std::{error::Error, ops::Deref, sync::Arc};

use super::quic::{AcceptError, QuicEndpoint};
use crate::{
    connection::ConnectionBuilder,
    dquic::prelude::Connection,
    pool::Pool,
    server::{Servers, UnresolvedRequest},
};

/// HTTP/3 endpoint.
pub struct H3Endpoint {
    /// Underlying QUIC endpoint.
    pub quic: QuicEndpoint,
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
            quic,
            pool,
            connection_builder,
        }
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
            .listener(self.quic)
            .service(service)
            .pool(self.pool)
            .builder(self.connection_builder)
            .build();
        servers.run().await
    }
}
