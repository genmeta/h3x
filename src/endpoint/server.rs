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
    /// Slow path: field-by-field comparison, using [`PartialEq`] where available
    /// and [`Arc::ptr_eq`] for the trait-object members.
    pub(crate) fn is_compatible_with(&self, other: &Self) -> bool {
        if Arc::ptr_eq(&self.common, &other.common) && Arc::ptr_eq(&self.own, &other.own) {
            return true;
        }
        let common_eq = self.common.defer_idle_timeout == other.common.defer_idle_timeout
            && self.common.enable_0rtt == other.common.enable_0rtt
            && self.common.enable_sslkeylog == other.common.enable_sslkeylog
            && Arc::ptr_eq(
                &self.common.stream_strategy_factory,
                &other.common.stream_strategy_factory,
            )
            && Arc::ptr_eq(&self.common.qlogger, &other.common.qlogger);
        let own_eq = self.own.alpns == other.own.alpns
            && self.own.backlog == other.own.backlog
            && self.own.anti_port_scan == other.own.anti_port_scan
            && self.own.parameters == other.own.parameters
            && Arc::ptr_eq(&self.own.token_provider, &other.own.token_provider)
            && Arc::ptr_eq(&self.own.client_auther, &other.own.client_auther)
            && Arc::ptr_eq(
                &self.own.client_cert_verifier,
                &other.own.client_cert_verifier,
            );
        common_eq && own_eq
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
