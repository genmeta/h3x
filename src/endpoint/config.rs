//! Per-role QUIC configuration values for [`QuicEndpoint`](super::QuicEndpoint).
//!
//! Configuration is split between [`CommonQuicConfig`] (shared by both roles)
//! and [`ClientOnlyConfig`] / [`ServerOnlyConfig`] (role-specific).
//!
//! [`ClientQuicConfig`] and [`ServerQuicConfig`] are cheap-to-clone wrappers
//! composed from `Arc<Common>` + `Arc<Own>`, so an endpoint Clone shares these
//! sub-trees efficiently and the endpoint's private TLS caches can reuse them
//! across clones via `Arc::ptr_eq`.
//!
//! All types implement [`Default`] so that endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::{sync::Arc, time::Duration};

use rustls::{
    client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    server::{NoClientAuth, danger::ClientCertVerifier},
};

use crate::dquic::{
    prelude::{
        AuthClient, ProductStreamsConcurrencyController,
        handy::{ConsistentConcurrency, NoopLogger, client_parameters, server_parameters},
    },
    qbase::{
        param::{ClientParameters, ServerParameters},
        token::{TokenProvider, TokenSink, handy::NoopTokenRegistry},
    },
    qconnection::tls::AcceptAllClientAuther,
    qevent::telemetry::QLog,
};

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

/// Configuration values that apply to both client and server roles.
#[derive(Clone)]
pub struct CommonQuicConfig {
    /// How long the connection should keep sending probe packets after going
    /// idle. `Duration::ZERO` (the default) disables deferred idle timeouts.
    pub defer_idle_timeout: Duration,
    /// Factory producing per-connection streams concurrency controllers.
    pub stream_strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    /// QUIC-events logger (qlog). Defaults to a no-op logger.
    pub qlogger: Arc<dyn QLog + Send + Sync>,
    /// Whether 0-RTT should be enabled if the crypto context permits it.
    pub enable_0rtt: bool,
    /// Enable SSL key logging via `SSLKEYLOGFILE` for debugging captures.
    pub enable_sslkeylog: bool,
}

impl Default for CommonQuicConfig {
    fn default() -> Self {
        Self {
            defer_idle_timeout: Duration::ZERO,
            stream_strategy_factory: Arc::new(ConsistentConcurrency::new),
            qlogger: Arc::new(NoopLogger),
            enable_0rtt: false,
            enable_sslkeylog: false,
        }
    }
}

impl std::fmt::Debug for CommonQuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonQuicConfig")
            .field("defer_idle_timeout", &self.defer_idle_timeout)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_sslkeylog", &self.enable_sslkeylog)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Client-only
// ---------------------------------------------------------------------------

/// Strategy for verifying the server's TLS certificate.
///
/// Kept as a small enum rather than a trait object so that
/// [`ClientOnlyConfig::verifier`] composes cheaply. The `WebPki` and `Custom`
/// variants wrap their verifier in an [`Arc`] for cheap cloning.
#[derive(Clone, Default)]
pub enum ServerCertVerifierChoice {
    /// Accept any certificate. Intended for local testing only.
    #[default]
    Dangerous,
    /// Verify against a compiled webpki verifier.
    WebPki(Arc<WebPkiServerVerifier>),
    /// Delegate to a caller-supplied verifier.
    Custom(Arc<dyn ServerCertVerifier>),
}

impl std::fmt::Debug for ServerCertVerifierChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dangerous => f.write_str("Dangerous"),
            Self::WebPki(_) => f.write_str("WebPki"),
            Self::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// Client-only configuration values.
#[derive(Clone)]
pub struct ClientOnlyConfig {
    /// Transport parameters advertised by the client.
    pub parameters: ClientParameters,
    /// ALPN protocol identifiers to offer. Empty means no ALPN.
    pub alpns: Vec<Vec<u8>>,
    /// Address validation token sink.
    pub token_sink: Arc<dyn TokenSink>,
    /// How the server's certificate should be verified.
    pub verifier: ServerCertVerifierChoice,
}

impl Default for ClientOnlyConfig {
    fn default() -> Self {
        Self {
            parameters: client_parameters(),
            alpns: Vec::new(),
            token_sink: Arc::new(NoopTokenRegistry),
            verifier: ServerCertVerifierChoice::default(),
        }
    }
}

impl std::fmt::Debug for ClientOnlyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOnlyConfig")
            .field("alpns", &self.alpns.len())
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

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

/// Client-side QUIC configuration = common + client-only.
#[derive(Debug, Clone, Default)]
pub struct ClientQuicConfig {
    /// Values shared by both roles.
    pub common: Arc<CommonQuicConfig>,
    /// Client-specific values.
    pub own: Arc<ClientOnlyConfig>,
}

/// Server-side QUIC configuration = common + server-only.
#[derive(Debug, Clone, Default)]
pub struct ServerQuicConfig {
    /// Values shared by both roles.
    pub common: Arc<CommonQuicConfig>,
    /// Server-specific values.
    pub own: Arc<ServerOnlyConfig>,
}
