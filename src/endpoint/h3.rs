//! HTTP/3 endpoint built on top of [`QuicEndpoint`].
//!
//! [`H3Endpoint`] extends [`QuicEndpoint`] with an HTTP/3 connection pool and
//! a user-configurable [`ConnectionBuilder`]. It transparently derefs to the
//! underlying [`QuicEndpoint`] so it inherits the [`Connect`](crate::quic::Connect)
//! and [`Listen`](crate::quic::Listen) trait impls.

use std::{ops::Deref, sync::Arc};

use super::quic::QuicEndpoint;
use crate::{connection::ConnectionBuilder, dquic::prelude::Connection, pool::Pool};

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
