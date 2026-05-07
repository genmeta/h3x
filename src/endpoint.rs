//! Shared QUIC / DHTTP/3 endpoint infrastructure.
//!
//! This module groups three layers that collaborate to allow many logical
//! clients and servers to share one set of physical network resources:
//!
//! - [`Network`] — process-shared infrastructure: interface manager, QUIC
//!   router, STUN agent, SNI registry, and a reconcile task that keeps the
//!   interface set in sync with user-supplied [`BindPattern`]s.
//! - [`QuicEndpoint`] — a QUIC-only endpoint with fully public, per-field
//!   cloneable configuration (identity, resolver, per-role configs). Holds
//!   private caches that are invalidated lazily via `Arc::ptr_eq`.
//! - [`H3Endpoint`] — [`QuicEndpoint`] plus an HTTP/3 connection pool and a
//!   user-configurable [`ConnectionBuilder`].
//!
//! [`ConnectionBuilder`]: crate::connection::ConnectionBuilder

pub mod binds;
pub mod client;
pub mod h3;
pub mod identity;
pub mod network;
pub mod quic;
pub mod server;
mod sni;

pub use binds::{BindHost, BindPattern};
pub use client::{ClientSpecificConfig, ClientQuicConfig, CommonQuicConfig, ServerCertVerifierChoice};
pub use h3::H3Endpoint;
pub use identity::{Identity, ServerName};
pub use network::{BindServerError, Network, ServerBinding};
pub use quic::{AcceptError, ConnectError, EndpointError, QuicEndpoint};
pub use server::{ServerSpecificConfig, ServerQuicConfig};
