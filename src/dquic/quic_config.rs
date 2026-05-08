//! QUIC configuration types shared by [`QuicEndpoint`](crate::dquic::endpoint::QuicEndpoint).
//!
//! Configuration is split between [`CommonQuicConfig`] (shared by both roles),
//! [`ClientSpecificConfig`] (client-only), and [`ServerSpecificConfig`] (server-only).
//!
//! [`ClientQuicConfig`] and [`ServerQuicConfig`] are cheap-to-clone wrappers composed
//! from `Arc<Common>` + `Arc<Own>`, so an endpoint clone shares these sub-trees
//! efficiently and the endpoint's private TLS caches can reuse them across
//! clones via `Arc::ptr_eq`.
//!
//! All types implement [`Default`] so that endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::{sync::Arc, time::Duration};

use rustls::client::{WebPkiServerVerifier, danger::ServerCertVerifier};
use rustls::server::{NoClientAuth, danger::ClientCertVerifier};

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
            Self::Dangerous => f.debug_tuple("Dangerous").finish(),
            Self::WebPki(_) => f.debug_tuple("WebPki").finish(),
            Self::Custom(_) => f.debug_tuple("Custom").finish(),
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
// Client composite (common + own)
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

// ---------------------------------------------------------------------------
// Server-only
// ---------------------------------------------------------------------------

/// Server-only configuration values.
#[derive(Clone)]
pub struct ServerSpecificConfig {
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

impl Default for ServerSpecificConfig {
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

impl std::fmt::Debug for ServerSpecificConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSpecificConfig")
            .field("alpns", &self.alpns.len())
            .field("backlog", &self.backlog)
            .field("anti_port_scan", &self.anti_port_scan)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ServerSpecificConfig {
    fn eq(&self, other: &Self) -> bool {
        self.alpns == other.alpns
            && self.backlog == other.backlog
            && self.anti_port_scan == other.anti_port_scan
            && self.parameters == other.parameters
            && Arc::ptr_eq(&self.token_provider, &other.token_provider)
            && Arc::ptr_eq(&self.client_auther, &other.client_auther)
            && Arc::ptr_eq(&self.client_cert_verifier, &other.client_cert_verifier)
    }
}

// ---------------------------------------------------------------------------
// Server composite (common + own)
// ---------------------------------------------------------------------------

/// Server-side QUIC configuration = common + server-only.
#[derive(Debug, Clone, Default)]
pub struct ServerQuicConfig {
    /// Values shared by both roles.
    pub common: Arc<CommonQuicConfig>,
    /// Server-specific values.
    pub own: Arc<ServerSpecificConfig>,
}

impl ServerQuicConfig {
    /// Get a mutable reference to the common config, cloning if shared.
    pub fn common_mut(&mut self) -> &mut CommonQuicConfig {
        Arc::make_mut(&mut self.common)
    }

    /// Get a mutable reference to the server-only config, cloning if shared.
    pub fn own_mut(&mut self) -> &mut ServerSpecificConfig {
        Arc::make_mut(&mut self.own)
    }

    /// Returns `true` when `self` and `other` describe the same server configuration.
    ///
    /// Fast path: whole-[`Arc`] pointer equality for `common` and `own`.
    /// Slow path: delegates to [`PartialEq`] on each sub-config.
    pub(crate) fn is_compatible_with(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.common, &other.common) && Arc::ptr_eq(&self.own, &other.own) {
            return true;
        }
        *self.common == *other.common && *self.own == *other.own
    }

    /// Build the rustls server config shared across all SNIs registered on a
    /// network. The resolver selects a [`CertifiedKey`] based on ClientHello SNI.
    pub(crate) fn build_rustls_server_config(
        &self,
        resolver: crate::dquic::sni::SniCertResolver,
    ) -> Result<rustls::ServerConfig, crate::dquic::network::BindServerError> {
        use snafu::ResultExt;

        use crate::dquic::network::bind_server_error::VersionSnafu;

        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = rustls::ServerConfig::builder().crypto_provider().clone();
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13)
            .context(VersionSnafu)?;

        let mut tls = builder
            .with_client_cert_verifier(self.own.client_cert_verifier.clone())
            .with_cert_resolver(std::sync::Arc::new(resolver));
        tls.alpn_protocols.clone_from(&self.own.alpns);
        if self.common.enable_0rtt {
            tls.max_early_data_size = 0xffff_ffff;
        }
        Ok(tls)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod client_tests {
    use rustls::RootCertStore;

    use super::*;
    use crate::{dquic::prelude::handy::ToCertificate, util::tls::DangerousServerCertVerifier};

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");

    fn root_store_with_ca() -> RootCertStore {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(CA_CERT.to_certificate());
        store
    }

    // -- CommonQuicConfig ---------------------------------------------------

    #[test]
    fn test_common_quic_config_default() {
        let cfg = CommonQuicConfig::default();
        assert_eq!(cfg.defer_idle_timeout, Duration::ZERO);
        assert!(!cfg.enable_0rtt);
        assert!(!cfg.enable_sslkeylog);
    }

    #[test]
    fn test_common_quic_config_partial_eq_same() {
        let a = CommonQuicConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_common_quic_config_partial_eq_different_timeout() {
        let a = CommonQuicConfig::default();
        let mut b = a.clone();
        b.defer_idle_timeout = Duration::from_secs(30);
        assert_ne!(a, b);
    }

    #[test]
    fn test_common_quic_config_clone() {
        let a = CommonQuicConfig::default();
        let b = a.clone();
        // Clone shares the same Arcs
        assert!(Arc::ptr_eq(
            &a.stream_strategy_factory,
            &b.stream_strategy_factory
        ));
        assert!(Arc::ptr_eq(&a.qlogger, &b.qlogger));
        // Scalar values are copied
        assert_eq!(a.defer_idle_timeout, b.defer_idle_timeout);
        assert_eq!(a.enable_0rtt, b.enable_0rtt);
        assert_eq!(a.enable_sslkeylog, b.enable_sslkeylog);
    }

    // -- ClientSpecificConfig -----------------------------------------------

    #[test]
    fn test_client_specific_config_default() {
        let cfg = ClientSpecificConfig::default();
        assert!(
            matches!(cfg.verifier, ServerCertVerifierChoice::Dangerous),
            "default verifier should be Dangerous"
        );
        assert!(cfg.alpns.is_empty(), "default alpns should be empty");
    }

    #[test]
    fn test_client_specific_config_partial_eq() {
        let a = ClientSpecificConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_client_specific_config_clone() {
        let a = ClientSpecificConfig::default();
        let b = a.clone();
        // Clone shares the same Arc for token_sink
        assert!(Arc::ptr_eq(&a.token_sink, &b.token_sink));
        // Vec is cloned, not shared
        assert_eq!(a.alpns, b.alpns);
        // Parameters are value-equal
        assert_eq!(a.parameters, b.parameters);
        // Verifier is equal (same variant/ptr)
        assert_eq!(a.verifier, b.verifier);
    }

    // -- ServerCertVerifierChoice -------------------------------------------

    #[test]
    fn test_verifier_choice_dangerous_eq() {
        assert_eq!(
            ServerCertVerifierChoice::Dangerous,
            ServerCertVerifierChoice::Dangerous
        );
    }

    #[test]
    fn test_verifier_choice_dangerous_ne_webpki() {
        let store = root_store_with_ca();
        let webpki = WebPkiServerVerifier::builder(Arc::new(store))
            .build()
            .unwrap();
        assert_ne!(
            ServerCertVerifierChoice::Dangerous,
            ServerCertVerifierChoice::WebPki(webpki)
        );
    }

    #[test]
    fn test_verifier_choice_webpki_same_arc_eq() {
        let store = root_store_with_ca();
        let webpki = WebPkiServerVerifier::builder(Arc::new(store))
            .build()
            .unwrap();
        // webpki is already Arc<WebPkiServerVerifier>
        // Two clones of the same Arc should be equal (ptr_eq)
        let a = ServerCertVerifierChoice::WebPki(webpki.clone());
        let b = ServerCertVerifierChoice::WebPki(webpki.clone());
        assert_eq!(a, b);
    }

    #[test]
    fn test_verifier_choice_webpki_different_arc_ne() {
        let store1 = root_store_with_ca();
        let store2 = root_store_with_ca();
        let webpki1 = WebPkiServerVerifier::builder(Arc::new(store1))
            .build()
            .unwrap();
        let webpki2 = WebPkiServerVerifier::builder(Arc::new(store2))
            .build()
            .unwrap();
        assert_ne!(
            ServerCertVerifierChoice::WebPki(webpki1),
            ServerCertVerifierChoice::WebPki(webpki2)
        );
    }

    #[test]
    fn test_verifier_choice_custom_same_arc_eq() {
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(DangerousServerCertVerifier);
        let a = ServerCertVerifierChoice::Custom(verifier.clone());
        let b = ServerCertVerifierChoice::Custom(verifier.clone());
        assert_eq!(a, b);
    }

    #[test]
    fn test_verifier_choice_default_is_dangerous() {
        assert_eq!(
            ServerCertVerifierChoice::default(),
            ServerCertVerifierChoice::Dangerous
        );
    }

    // -- ClientQuicConfig ---------------------------------------------------

    #[test]
    fn test_client_quic_config_default() {
        let cfg = ClientQuicConfig::default();
        // Both Arcs are accessible
        assert_eq!(cfg.common.defer_idle_timeout, Duration::ZERO);
        assert!(
            matches!(&cfg.own.verifier, ServerCertVerifierChoice::Dangerous),
            "default own verifier should be Dangerous"
        );
    }

    #[test]
    fn test_client_quic_config_common_mut_clones_unique() {
        let a = ClientQuicConfig::default();
        let mut b = a.clone();
        // Before mutation, both share the same Arc
        assert!(Arc::ptr_eq(&a.common, &b.common));

        // Mutate b via common_mut — should clone-on-write
        b.common_mut().defer_idle_timeout = Duration::from_secs(99);

        // Original is unchanged
        assert_eq!(a.common.defer_idle_timeout, Duration::ZERO);
        // b has the new value
        assert_eq!(b.common.defer_idle_timeout, Duration::from_secs(99));
        // Pointers are now different
        assert_ne!(Arc::as_ptr(&a.common), Arc::as_ptr(&b.common));
    }

    #[test]
    fn test_client_quic_config_own_mut_clones_unique() {
        let a = ClientQuicConfig::default();
        let mut b = a.clone();
        // Before mutation, both share the same Arc
        assert!(Arc::ptr_eq(&a.own, &b.own));

        // Mutate b via own_mut — should clone-on-write
        b.own_mut().alpns.push(b"h3".to_vec());

        // Original is unchanged
        assert!(a.own.alpns.is_empty());
        // b has the new alpns
        assert!(!b.own.alpns.is_empty());
        // Pointers are now different
        assert_ne!(Arc::as_ptr(&a.own), Arc::as_ptr(&b.own));
    }

    #[test]
    fn test_client_quic_config_clone_shares_arcs() {
        let a = ClientQuicConfig::default();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.common, &b.common));
        assert!(Arc::ptr_eq(&a.own, &b.own));
    }
}

#[cfg(test)]
mod server_tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_server_specific_config_default() {
        let cfg = ServerSpecificConfig::default();
        assert!(cfg.alpns.is_empty());
        assert_eq!(cfg.backlog, 128);
        assert!(!cfg.anti_port_scan);
        assert_eq!(Arc::strong_count(&cfg.token_provider), 1);
        assert_eq!(Arc::strong_count(&cfg.client_auther), 1);
        assert_eq!(Arc::strong_count(&cfg.client_cert_verifier), 1);
    }

    #[test]
    fn test_server_specific_config_partial_eq() {
        let a = ServerSpecificConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_server_specific_config_partial_eq_different_alpns() {
        let a = ServerSpecificConfig::default();
        let mut b = a.clone();
        b.alpns = vec![b"h3".to_vec()];
        assert_ne!(a, b);
    }

    #[test]
    fn test_server_specific_config_clone() {
        let a = ServerSpecificConfig::default();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.token_provider, &b.token_provider,));
        assert!(Arc::ptr_eq(&a.client_auther, &b.client_auther,));
        assert!(Arc::ptr_eq(
            &a.client_cert_verifier,
            &b.client_cert_verifier,
        ));
        assert_eq!(a.alpns, b.alpns);
        assert_eq!(a.backlog, b.backlog);
        assert_eq!(a.anti_port_scan, b.anti_port_scan);
        assert_eq!(a, b);
    }

    #[test]
    fn test_server_quic_config_default() {
        let cfg = ServerQuicConfig::default();
        assert_eq!(Arc::strong_count(&cfg.common), 1);
        assert_eq!(Arc::strong_count(&cfg.own), 1);
        let _defer: Duration = cfg.common.defer_idle_timeout;
        let _backlog: usize = cfg.own.backlog;
    }

    #[test]
    fn test_server_quic_config_common_mut_clones_unique() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();

        a.common_mut().defer_idle_timeout = Duration::from_secs(42);

        assert_eq!(b.common.defer_idle_timeout, Duration::ZERO);
        assert_eq!(a.common.defer_idle_timeout, Duration::from_secs(42),);
        assert!(!Arc::ptr_eq(&a.common, &b.common));
    }

    #[test]
    fn test_server_quic_config_own_mut_clones_unique() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();

        a.own_mut().backlog = 256;

        assert_eq!(b.own.backlog, 128);
        assert_eq!(a.own.backlog, 256);
        assert!(!Arc::ptr_eq(&a.own, &b.own));
    }

    #[test]
    fn test_server_quic_config_clone_shares_arcs() {
        let a = ServerQuicConfig::default();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.common, &b.common));
        assert!(Arc::ptr_eq(&a.own, &b.own));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_same_arc() {
        let a = ServerQuicConfig::default();
        let b = a.clone();
        assert!(a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_same_values() {
        // After Arc::make_mut the outer Arcs differ, but the inner trait-object
        // Arcs inside CommonQuicConfig retain pointer-equality because
        // Arc<dyn Trait>::clone shares the allocation.  This means the
        // slow-path PartialEq succeeds and the method still returns true.
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.common_mut().defer_idle_timeout = Duration::from_secs(1);
        a.common_mut().defer_idle_timeout = Duration::ZERO;

        assert!(!Arc::ptr_eq(&a.common, &b.common));
        assert!(a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_alpns() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.own_mut().alpns = vec![b"h3".to_vec()];
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_backlog() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.own_mut().backlog = 256;
        assert!(!a.is_compatible_with(&b));
    }

    #[test]
    fn test_server_quic_config_is_compatible_with_different_anti_port_scan() {
        let mut a = ServerQuicConfig::default();
        let b = a.clone();
        a.own_mut().anti_port_scan = true;
        assert!(!a.is_compatible_with(&b));
    }
}
