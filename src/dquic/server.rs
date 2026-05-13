//! Server-side QUIC configuration types.
//!
//! [`ServerQuicConfig`] holds all server-side QUIC configuration — both the
//! common (role-independent) and server-specific values — directly, without
//! indirection through sub-configuration types.
//!
//! Trait-object fields (`stream_strategy_factory`, `qlogger`,
//! `token_provider`, `client_auther`, `client_cert_verifier`) are stored as
//! `Arc<dyn Trait>` so that clones share the same allocation and endpoint
//! clones can reuse cached TLS configs across clones via `Arc::ptr_eq`.
//!
//! All types implement [`Default`] so that server endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::{sync::Arc, time::Duration};

use rustls::server::{NoClientAuth, danger::ClientCertVerifier};

use crate::dquic::{
    log::{QLog, handy::NoopLogger},
    param::{ServerParameters, handy::server_parameters},
    stream::{ProductStreamsConcurrencyController, handy::ConsistentConcurrency},
    tls::{AuthClient, handy::AcceptAllClientAuther},
    token::{TokenProvider, handy::NoopTokenRegistry},
};

// --- legacy ServerSpecificConfig fields (flattened into ServerQuicConfig) ---
// #[derive(Clone)]
// pub struct ServerSpecificConfig {
//     pub parameters: ServerParameters,
//     pub alpns: Vec<Vec<u8>>,
//     pub token_provider: Arc<dyn TokenProvider>,
//     pub backlog: usize,
//     pub client_auther: Arc<dyn AuthClient>,
//     pub client_cert_verifier: Arc<dyn ClientCertVerifier>,
//     pub anti_port_scan: bool,
// }
//
// impl Default for ServerSpecificConfig { ... }
// impl Debug for ServerSpecificConfig { ... }
// impl PartialEq for ServerSpecificConfig { ... }

// ---------------------------------------------------------------------------
// ServerQuicConfig — all fields inlined
// ---------------------------------------------------------------------------

/// Server-side QUIC configuration with all fields inlined.
#[derive(Clone)]
pub struct ServerQuicConfig {
    // ---- from CommonQuicConfig ----
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

    // ---- from ServerSpecificConfig ----
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

impl Default for ServerQuicConfig {
    fn default() -> Self {
        Self {
            defer_idle_timeout: Duration::ZERO,
            stream_strategy_factory: Arc::new(ConsistentConcurrency::new),
            qlogger: Arc::new(NoopLogger),
            enable_0rtt: false,
            enable_sslkeylog: false,
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

impl std::fmt::Debug for ServerQuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerQuicConfig")
            .field("defer_idle_timeout", &self.defer_idle_timeout)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_sslkeylog", &self.enable_sslkeylog)
            .field("alpns", &self.alpns.len())
            .field("backlog", &self.backlog)
            .field("anti_port_scan", &self.anti_port_scan)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ServerQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.defer_idle_timeout == other.defer_idle_timeout
            && self.enable_0rtt == other.enable_0rtt
            && self.enable_sslkeylog == other.enable_sslkeylog
            && Arc::ptr_eq(
                &self.stream_strategy_factory,
                &other.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.qlogger, &other.qlogger)
            && self.parameters == other.parameters
            && self.alpns == other.alpns
            && Arc::ptr_eq(&self.token_provider, &other.token_provider)
            && self.backlog == other.backlog
            && Arc::ptr_eq(&self.client_auther, &other.client_auther)
            && Arc::ptr_eq(&self.client_cert_verifier, &other.client_cert_verifier)
            && self.anti_port_scan == other.anti_port_scan
    }
}

impl ServerQuicConfig {
    /// Returns `true` when `self` and `other` describe the same server configuration.
    ///
    /// Compares every field individually. Trait-object fields use
    /// [`Arc::ptr_eq`](std::sync::Arc::ptr_eq); plain-value fields use `==`.
    pub(crate) fn is_compatible_with(&self, other: &Self) -> bool {
        self == other
    }

    /// Build the rustls server config shared across all SNIs registered on a
    /// network. The resolver selects a [`CertifiedKey`] based on ClientHello SNI.
    pub(crate) fn build_rustls_server_config(
        &self,
        resolver: crate::dquic::sni::SniCertResolver,
    ) -> Result<rustls::ServerConfig, crate::dquic::network::BindServerError> {
        use snafu::ResultExt;

        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = rustls::ServerConfig::builder().crypto_provider().clone();
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13)
            .context(crate::dquic::network::bind_server_error::VersionSnafu)?;

        let mut tls = builder
            .with_client_cert_verifier(self.client_cert_verifier.clone())
            .with_cert_resolver(std::sync::Arc::new(resolver));
        tls.alpn_protocols.clone_from(&self.alpns);
        if self.enable_0rtt {
            tls.max_early_data_size = 0xffff_ffff;
        }
        Ok(tls)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod server_tests {
    use std::{sync::Arc, time::Duration};

    use crate::dquic::server::*;

    #[test]
    fn test_server_quic_config_default() {
        let cfg = ServerQuicConfig::default();
        assert_eq!(cfg.defer_idle_timeout, Duration::ZERO);
        assert!(!cfg.enable_0rtt);
        assert!(!cfg.enable_sslkeylog);
        assert!(cfg.alpns.is_empty());
        assert_eq!(cfg.backlog, 128);
        assert!(!cfg.anti_port_scan);
        assert_eq!(Arc::strong_count(&cfg.stream_strategy_factory), 1);
        assert_eq!(Arc::strong_count(&cfg.qlogger), 1);
        assert_eq!(Arc::strong_count(&cfg.token_provider), 1);
        assert_eq!(Arc::strong_count(&cfg.client_auther), 1);
        assert_eq!(Arc::strong_count(&cfg.client_cert_verifier), 1);
    }

    #[test]
    fn test_server_quic_config_partial_eq_same() {
        let a = ServerQuicConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_server_quic_config_partial_eq_different_alpns() {
        let a = ServerQuicConfig::default();
        let mut b = a.clone();
        b.alpns = vec![b"h3".to_vec()];
        assert_ne!(a, b);
    }

    #[test]
    fn test_server_quic_config_partial_eq_different_backlog() {
        let a = ServerQuicConfig::default();
        let mut b = a.clone();
        b.backlog = 256;
        assert_ne!(a, b);
    }

    #[test]
    fn test_server_quic_config_partial_eq_different_anti_port_scan() {
        let a = ServerQuicConfig::default();
        let mut b = a.clone();
        b.anti_port_scan = true;
        assert_ne!(a, b);
    }

    #[test]
    fn test_server_quic_config_clone() {
        let a = ServerQuicConfig::default();
        let b = a.clone();
        // Plain-value fields clone independently
        assert_eq!(a.defer_idle_timeout, b.defer_idle_timeout);
        assert_eq!(a.enable_0rtt, b.enable_0rtt);
        assert_eq!(a.enable_sslkeylog, b.enable_sslkeylog);
        assert_eq!(a.alpns, b.alpns);
        assert_eq!(a.backlog, b.backlog);
        assert_eq!(a.anti_port_scan, b.anti_port_scan);
        // Trait-object Arcs are shared after clone
        assert!(Arc::ptr_eq(
            &a.stream_strategy_factory,
            &b.stream_strategy_factory,
        ));
        assert!(Arc::ptr_eq(&a.qlogger, &b.qlogger));
        assert!(Arc::ptr_eq(&a.token_provider, &b.token_provider));
        assert!(Arc::ptr_eq(&a.client_auther, &b.client_auther));
        assert!(Arc::ptr_eq(
            &a.client_cert_verifier,
            &b.client_cert_verifier,
        ));
        assert_eq!(a, b);
    }

    #[test]
    fn test_server_quic_config_mutate_independent_after_clone() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();

        a.defer_idle_timeout = Duration::from_secs(42);
        a.backlog = 256;

        assert_eq!(b.defer_idle_timeout, Duration::ZERO);
        assert_eq!(b.backlog, 128);
        assert_eq!(a.defer_idle_timeout, Duration::from_secs(42));
        assert_eq!(a.backlog, 256);
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_same_arc() {
        let a = ServerQuicConfig::default();
        let b = a.clone();
        // Trait-object Arcs are shared, so PartialEq (ptr_eq) returns true quickly
        assert!(a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_same_values() {
        // Mutate then restore values — the fields end up equal.
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.defer_idle_timeout = Duration::from_secs(1);
        a.defer_idle_timeout = Duration::ZERO;
        assert_eq!(a.defer_idle_timeout, b.defer_idle_timeout);
        assert!(a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_alpns() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.alpns = vec![b"h3".to_vec()];
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_backlog() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.backlog = 256;
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_anti_port_scan() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.anti_port_scan = true;
        assert!(!a.is_compatible_with(&b));
    }
}
