//! Server-side QUIC configuration for [`QuicEndpoint`](super::QuicEndpoint).
//!
//! Configuration is split between [`CommonQuicConfig`] (shared by both roles)
//! and [`ServerSpecificConfig`] (server-specific).
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
// Composite (common + own)
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
        resolver: crate::endpoint::sni::SniCertResolver,
    ) -> Result<rustls::ServerConfig, crate::endpoint::network::BindServerError> {
        use snafu::ResultExt;

        use crate::endpoint::network::bind_server_error::VersionSnafu;

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
mod tests {
    use std::{sync::Arc, time::Duration};

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
