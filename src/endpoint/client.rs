//! Client-side QUIC configuration for [`QuicEndpoint`](super::QuicEndpoint).
//!
//! Configuration is split between [`CommonQuicConfig`] (shared by both roles)
//! and [`ClientSpecificConfig`] (client-specific).
//!
//! [`ClientQuicConfig`] is a cheap-to-clone wrapper composed from
//! `Arc<Common>` + `Arc<Own>`, so an endpoint clone shares these sub-trees
//! efficiently and the endpoint's private TLS caches can reuse them across
//! clones via `Arc::ptr_eq`.
//!
//! All types implement [`Default`] so that endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::{sync::Arc, time::Duration};

use rustls::client::{WebPkiServerVerifier, danger::ServerCertVerifier};

use crate::dquic::{
    prelude::{
        ProductStreamsConcurrencyController,
        handy::{ConsistentConcurrency, NoopLogger, client_parameters},
    },
    qbase::{
        param::ClientParameters,
        token::{TokenSink, handy::NoopTokenRegistry},
    },
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

impl PartialEq for CommonQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.defer_idle_timeout == other.defer_idle_timeout
            && self.enable_0rtt == other.enable_0rtt
            && self.enable_sslkeylog == other.enable_sslkeylog
            && Arc::ptr_eq(
                &self.stream_strategy_factory,
                &other.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.qlogger, &other.qlogger)
    }
}

// ---------------------------------------------------------------------------
// Client-only
// ---------------------------------------------------------------------------

/// Strategy for verifying the server's TLS certificate.
///
/// Kept as a small enum rather than a trait object so that
/// [`ClientSpecificConfig::verifier`] composes cheaply. The `WebPki` and `Custom`
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

impl PartialEq for ServerCertVerifierChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Dangerous, Self::Dangerous) => true,
            (Self::WebPki(a), Self::WebPki(b)) => Arc::ptr_eq(a, b),
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// Client-only configuration values.
#[derive(Clone)]
pub struct ClientSpecificConfig {
    /// Transport parameters advertised by the client.
    pub parameters: ClientParameters,
    /// ALPN protocol identifiers to offer. Empty means no ALPN.
    pub alpns: Vec<Vec<u8>>,
    /// Address validation token sink.
    pub token_sink: Arc<dyn TokenSink>,
    /// How the server's certificate should be verified.
    pub verifier: ServerCertVerifierChoice,
}

impl Default for ClientSpecificConfig {
    fn default() -> Self {
        Self {
            parameters: client_parameters(),
            alpns: Vec::new(),
            token_sink: Arc::new(NoopTokenRegistry),
            verifier: ServerCertVerifierChoice::default(),
        }
    }
}

impl std::fmt::Debug for ClientSpecificConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSpecificConfig")
            .field("alpns", &self.alpns.len())
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ClientSpecificConfig {
    fn eq(&self, other: &Self) -> bool {
        self.parameters == other.parameters
            && self.alpns == other.alpns
            && Arc::ptr_eq(&self.token_sink, &other.token_sink)
            && self.verifier == other.verifier
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
    pub own: Arc<ClientSpecificConfig>,
}

impl ClientQuicConfig {
    /// Get a mutable reference to the common config, cloning if shared.
    pub fn common_mut(&mut self) -> &mut CommonQuicConfig {
        Arc::make_mut(&mut self.common)
    }

    /// Get a mutable reference to the client-only config, cloning if shared.
    pub fn own_mut(&mut self) -> &mut ClientSpecificConfig {
        Arc::make_mut(&mut self.own)
    }
}
