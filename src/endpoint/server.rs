//! Server-side QUIC configuration for [`QuicEndpoint`](super::QuicEndpoint).
//!
//! Configuration is split between [`CommonQuicConfig`] (shared by both roles)
//! and [`ServerOnlyConfig`] (server-specific).
//!
//! [`ServerQuicConfig`] is a cheap-to-clone wrapper composed from
//! `Arc<Common>` + `Arc<Own>`, so an endpoint clone shares these sub-trees
//! efficiently and the endpoint's private TLS caches can reuse them across
//! clones via `Arc::ptr_eq`.
//!
//! All types implement [`Default`] so that endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::sync::Arc;

use rustls::server::{NoClientAuth, danger::ClientCertVerifier};

use super::client::CommonQuicConfig;
use crate::dquic::{
    prelude::{AuthClient, handy::server_parameters},
    qbase::{
        param::ServerParameters,
        token::{TokenProvider, handy::NoopTokenRegistry},
    },
    qconnection::tls::AcceptAllClientAuther,
};

// ---------------------------------------------------------------------------
// Server-only
// ---------------------------------------------------------------------------

/// Server-only configuration values.
#[derive(Clone)]
pub struct ServerOnlyConfig {
    /// Transport parameters advertised by the server.
    pub parameters: ServerParameters,
    /// ALPN protocol identifiers. Empty means no ALPN.
    pub alpns: Vec<Vec<u8>>,
    /// Address validation token provider.
    pub token_provider: Arc<dyn TokenProvider>,
    /// Maximum number of pending inbound connections before packets start
    /// being dropped at the network level.
    pub backlog: usize,
    /// Custom client authenticator; runs on top of rustls's certificate
    /// verification. Defaults to [`AcceptAllClientAuther`].
    pub client_auther: Arc<dyn AuthClient>,
    /// How rustls should verify client certificates. Defaults to
    /// [`NoClientAuth`](rustls::server::NoClientAuth).
    pub client_cert_verifier: Arc<dyn ClientCertVerifier>,
    /// When enabled, failed connections are silently dropped instead of
    /// answered with an error packet.
    pub anti_port_scan: bool,
}

impl Default for ServerOnlyConfig {
    fn default() -> Self {
        Self {
            parameters: server_parameters(),
            alpns: Vec::new(),
            token_provider: Arc::new(NoopTokenRegistry),
            backlog: 128,
            client_auther: Arc::new(AcceptAllClientAuther),
            client_cert_verifier: Arc::new(NoClientAuth),
            anti_port_scan: false,
        }
    }
}

impl std::fmt::Debug for ServerOnlyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOnlyConfig")
            .field("alpns", &self.alpns.len())
            .field("backlog", &self.backlog)
            .field("anti_port_scan", &self.anti_port_scan)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Composite (common + own)
// ---------------------------------------------------------------------------

/// Server-side QUIC configuration = common + server-only.
#[derive(Debug, Clone, Default)]
pub struct ServerQuicConfig {
    /// Values shared by both roles.
    pub common: Arc<CommonQuicConfig>,
    /// Server-specific values.
    pub own: Arc<ServerOnlyConfig>,
}

impl ServerQuicConfig {
    /// Get a mutable reference to the common config, cloning if shared.
    pub fn common_mut(&mut self) -> &mut CommonQuicConfig {
        Arc::make_mut(&mut self.common)
    }

    /// Get a mutable reference to the server-only config, cloning if shared.
    pub fn own_mut(&mut self) -> &mut ServerOnlyConfig {
        Arc::make_mut(&mut self.own)
    }
}
