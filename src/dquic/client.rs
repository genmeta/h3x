//! Client-side QUIC configuration types.
//!
//! [`ClientQuicConfig`] is the primary client-side configuration struct.
//! All fields are inlined directly — the former `CommonQuicConfig` and
//! `ClientSpecificConfig` wrappers have been flattened into this single type.
//!
//! All types provide [`Default`] so that client endpoints can be constructed
//! without the caller having to hand-roll configuration values.

use std::{sync::Arc, time::Duration};

use rustls::client::{WebPkiServerVerifier, danger::ServerCertVerifier};

use crate::dquic::{
    log::{QLog, handy::NoopLogger},
    param::{ClientParameters, handy::client_parameters},
    stream::{ProductStreamsConcurrencyController, handy::ConsistentConcurrency},
    token::{TokenSink, handy::NoopTokenRegistry},
};

// ---------------------------------------------------------------------------
// Client-only
// ---------------------------------------------------------------------------

/// Strategy for verifying the server's TLS certificate.
///
/// Kept as a small enum rather than a trait object so that
/// [`ClientQuicConfig::verifier`] composes cheaply. The `WebPki` and `Custom`
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

// --- legacy ClientSpecificConfig fields (flattened into ClientQuicConfig) ---
//
// /// Client-only configuration values.
// #[derive(Clone)]
// pub struct ClientSpecificConfig {
//     /// Transport parameters advertised by the client.
//     pub parameters: ClientParameters,
//     /// ALPN protocol identifiers to offer. Empty means no ALPN.
//     pub alpns: Vec<Vec<u8>>,
//     /// Address validation token sink.
//     pub token_sink: Arc<dyn TokenSink>,
//     /// How the server's certificate should be verified.
//     pub verifier: ServerCertVerifierChoice,
// }
//
// impl Default for ClientSpecificConfig { ... }
// impl Debug for ClientSpecificConfig { ... }
// impl PartialEq for ClientSpecificConfig { ... }

// ---------------------------------------------------------------------------
// Client composite (common + own)
// ---------------------------------------------------------------------------

/// Client-side QUIC configuration — common + client-only fields flattened.
#[derive(Clone)]
pub struct ClientQuicConfig {
    // --- common fields (from CommonQuicConfig) ---
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

    // --- client-specific fields (from ClientSpecificConfig) ---
    /// Transport parameters advertised by the client.
    pub parameters: ClientParameters,
    /// ALPN protocol identifiers to offer. Empty means no ALPN.
    pub alpns: Vec<Vec<u8>>,
    /// Address validation token sink.
    pub token_sink: Arc<dyn TokenSink>,
    /// How the server's certificate should be verified.
    pub verifier: ServerCertVerifierChoice,
}

impl Default for ClientQuicConfig {
    fn default() -> Self {
        Self {
            // CommonQuicConfig::default() values
            defer_idle_timeout: Duration::ZERO,
            stream_strategy_factory: Arc::new(ConsistentConcurrency::new),
            qlogger: Arc::new(NoopLogger),
            enable_0rtt: false,
            enable_sslkeylog: false,
            // ClientSpecificConfig::default() values
            parameters: client_parameters(),
            alpns: Vec::new(),
            token_sink: Arc::new(NoopTokenRegistry),
            verifier: ServerCertVerifierChoice::default(),
        }
    }
}

impl std::fmt::Debug for ClientQuicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientQuicConfig")
            .field("defer_idle_timeout", &self.defer_idle_timeout)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_sslkeylog", &self.enable_sslkeylog)
            .field("alpns", &self.alpns.len())
            .field("verifier", &self.verifier)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ClientQuicConfig {
    fn eq(&self, other: &Self) -> bool {
        self.defer_idle_timeout == other.defer_idle_timeout
            && self.enable_0rtt == other.enable_0rtt
            && self.enable_sslkeylog == other.enable_sslkeylog
            && self.parameters == other.parameters
            && self.alpns == other.alpns
            && self.verifier == other.verifier
            && Arc::ptr_eq(
                &self.stream_strategy_factory,
                &other.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.qlogger, &other.qlogger)
            && Arc::ptr_eq(&self.token_sink, &other.token_sink)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod client_tests {
    use std::{sync::Arc, time::Duration};

    use rustls::{
        RootCertStore,
        client::{WebPkiServerVerifier, danger::ServerCertVerifier},
    };

    use crate::{
        dquic::{client::*, common::*, prelude::handy::ToCertificate},
        util::tls::DangerousServerCertVerifier,
    };

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
        // Common fields
        assert_eq!(cfg.defer_idle_timeout, Duration::ZERO);
        assert!(!cfg.enable_0rtt);
        assert!(!cfg.enable_sslkeylog);
        // Client-specific fields
        assert!(
            matches!(&cfg.verifier, ServerCertVerifierChoice::Dangerous),
            "default verifier should be Dangerous"
        );
        assert!(cfg.alpns.is_empty(), "default alpns should be empty");
    }

    #[test]
    fn test_client_quic_config_partial_eq_same() {
        let a = ClientQuicConfig::default();
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_client_quic_config_partial_eq_different_timeout() {
        let a = ClientQuicConfig::default();
        let mut b = a.clone();
        b.defer_idle_timeout = Duration::from_secs(99);
        assert_ne!(a, b);
    }

    #[test]
    fn test_client_quic_config_clone() {
        let a = ClientQuicConfig::default();
        let b = a.clone();
        // Trait-object Arcs are shared by pointer after clone
        assert!(Arc::ptr_eq(
            &a.stream_strategy_factory,
            &b.stream_strategy_factory
        ));
        assert!(Arc::ptr_eq(&a.qlogger, &b.qlogger));
        assert!(Arc::ptr_eq(&a.token_sink, &b.token_sink));
        // Scalar / owned values are equal by value
        assert_eq!(a.defer_idle_timeout, b.defer_idle_timeout);
        assert_eq!(a.enable_0rtt, b.enable_0rtt);
        assert_eq!(a.enable_sslkeylog, b.enable_sslkeylog);
        assert_eq!(a.parameters, b.parameters);
        assert_eq!(a.alpns, b.alpns);
        assert_eq!(a.verifier, b.verifier);
    }

    #[test]
    fn test_client_quic_config_clone_shares_arcs() {
        let a = ClientQuicConfig::default();
        let b = a.clone();
        // Trait-object Arcs are pointer-shared
        assert!(Arc::ptr_eq(
            &a.stream_strategy_factory,
            &b.stream_strategy_factory
        ));
        assert!(Arc::ptr_eq(&a.qlogger, &b.qlogger));
        assert!(Arc::ptr_eq(&a.token_sink, &b.token_sink));
    }

    #[test]
    fn test_client_quic_config_mutate_does_not_affect_clone() {
        let a = ClientQuicConfig::default();
        let mut b = a.clone();

        // Mutate b — should not affect a since fields are copied/cloned
        b.defer_idle_timeout = Duration::from_secs(99);
        b.alpns.push(b"h3".to_vec());

        // Original is unchanged
        assert_eq!(a.defer_idle_timeout, Duration::ZERO);
        assert!(a.alpns.is_empty());
        // b has the new values
        assert_eq!(b.defer_idle_timeout, Duration::from_secs(99));
        assert!(!b.alpns.is_empty());
    }
}
