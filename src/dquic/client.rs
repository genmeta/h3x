use std::{sync::Arc, time::Duration};

use ::dquic::{
    builder::QuicClientBuilder,
    prelude::{
        BindUri, Connection, ProductStreamsConcurrencyController, QuicClient, Resolve,
        handy::{ToCertificate, ToPrivateKey},
    },
    qbase::{param::ClientParameters, token::TokenSink},
    qevent::telemetry::QLog,
    qinterface::{
        component::route::QuicRouter, device::Devices, io::ProductIO, manager::InterfaceManager,
    },
};
use rustls::{
    ClientConfig, RootCertStore,
    client::WebPkiServerVerifier,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use snafu::{ResultExt, Snafu};

use crate::{
    client::Client,
    connection::ConnectionBuilder,
    pool::Pool,
    util::tls::{DangerousServerCertVerifier, InvalidIdentity, verify_certificate_for_name},
};

enum ServerCertVerifier {
    WebPki(Arc<WebPkiServerVerifier>),
    Roots(Arc<RootCertStore>),
    None,
}

impl Default for ServerCertVerifier {
    fn default() -> Self {
        Self::Roots(Arc::new(RootCertStore::empty()))
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum BuildClientError {
    #[snafu(display("provided crypto provider cannot be used"))]
    InvalidCryptoProvider { source: rustls::Error },
    #[snafu(display("provided client identity cannot be used for `{name}`"))]
    InvalidIdentity {
        name: String,
        source: InvalidIdentity,
    },
}

pub struct H3ClientTlsBuilder {
    server_cert_verifier: ServerCertVerifier,
    client_identity: Option<(String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    crypto_provider: Option<Arc<CryptoProvider>>,
    resolver: Option<Arc<dyn Resolve + Send + Sync>>,
}

pub type H3Client = Client<Arc<QuicClient>>;

impl H3Client {
    pub fn builder() -> H3ClientTlsBuilder {
        H3ClientTlsBuilder {
            server_cert_verifier: ServerCertVerifier::default(),
            client_identity: None,
            crypto_provider: None,
            resolver: None,
        }
    }
}

impl H3ClientTlsBuilder {
    pub fn with_crypto_provider(mut self, crypto_provider: impl Into<Arc<CryptoProvider>>) -> Self {
        self.crypto_provider = Some(crypto_provider.into());
        self
    }

    pub fn with_root_certificates(mut self, root_store: impl Into<Arc<RootCertStore>>) -> Self {
        self.server_cert_verifier = ServerCertVerifier::Roots(root_store.into());
        self
    }

    pub fn with_webpki_verifier(mut self, verifier: Arc<WebPkiServerVerifier>) -> Self {
        self.server_cert_verifier = ServerCertVerifier::WebPki(verifier);
        self
    }

    pub fn without_server_cert_verification(mut self) -> Self {
        self.server_cert_verifier = ServerCertVerifier::None;
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<dyn Resolve + Send + Sync>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_identity(
        mut self,
        name: impl Into<String>,
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
    ) -> Result<H3ClientBuilder, BuildClientError> {
        self.client_identity = Some((
            name.into(),
            cert_chain.to_certificate(),
            private_key.to_private_key(),
        ));
        self.try_into()
    }

    pub fn without_identity(mut self) -> Result<H3ClientBuilder, BuildClientError> {
        self.client_identity = None;
        self.try_into()
    }
}

impl TryFrom<H3ClientTlsBuilder> for H3ClientBuilder {
    type Error = BuildClientError;

    fn try_from(builder: H3ClientTlsBuilder) -> Result<Self, Self::Error> {
        const REQUIRED_TLS_VERSIONS: &[&rustls::SupportedProtocolVersion; 1] =
            &[&rustls::version::TLS13];
        let crypto_provider = builder
            .crypto_provider
            .unwrap_or_else(|| ClientConfig::builder().crypto_provider().clone());
        let tls_config_buider = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(REQUIRED_TLS_VERSIONS)
            .context(build_client_error::InvalidCryptoProviderSnafu)?;

        let tls_config_buider = match builder.server_cert_verifier {
            ServerCertVerifier::WebPki(web_pki_server_verifier) => {
                tls_config_buider.with_webpki_verifier(web_pki_server_verifier)
            }
            ServerCertVerifier::Roots(root_cert_store) => {
                tls_config_buider.with_root_certificates(root_cert_store)
            }
            ServerCertVerifier::None => tls_config_buider
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier)),
        };

        let (tls_config, client_name) = match builder.client_identity {
            Some((name, cert, key)) => {
                verify_certificate_for_name(&cert[0], &name)
                    .context(build_client_error::InvalidIdentitySnafu { name: &name })?;
                let tls_config = tls_config_buider
                    .with_client_auth_cert(cert, key)
                    .map_err(InvalidIdentity::from)
                    .context(build_client_error::InvalidIdentitySnafu { name: &name })?;
                (tls_config, Some(name))
            }
            None => (tls_config_buider.with_no_client_auth(), None),
        };

        let mut quic_builder = QuicClient::builder_with_tls(tls_config).with_alpns(vec!["h3"]);
        if let Some(resolver) = builder.resolver {
            quic_builder = quic_builder.with_resolver(resolver);
        }

        Ok(H3ClientBuilder {
            quic_builder,
            client_name,
            pool: Pool::empty(),
            builder: Arc::new(ConnectionBuilder::new(Arc::default())),
        })
    }
}

pub struct H3ClientBuilder {
    quic_builder: QuicClientBuilder<rustls::ClientConfig>,
    client_name: Option<String>,
    pool: Pool<Connection>,
    builder: Arc<ConnectionBuilder<Connection>>,
}

impl H3ClientBuilder {
    pub fn physical_ifaces(mut self, physical_ifaces: &'static Devices) -> Self {
        self.quic_builder = self.quic_builder.physical_ifaces(physical_ifaces);
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.quic_builder = self.quic_builder.with_resolver(resolver);
        self
    }

    pub fn with_iface_factory(mut self, factory: Arc<dyn ProductIO + 'static>) -> Self {
        self.quic_builder = self.quic_builder.with_iface_factory(factory);
        self
    }

    /// Specify the interfaces manager for the client.
    pub fn with_iface_manager(mut self, iface_manager: Arc<InterfaceManager>) -> Self {
        self.quic_builder = self.quic_builder.with_iface_manager(iface_manager);
        self
    }

    pub fn with_router(mut self, router: Arc<QuicRouter>) -> Self {
        self.quic_builder = self.quic_builder.with_router(router);
        self
    }

    pub fn with_stun(mut self, server: impl Into<Arc<str>>) -> Self {
        self.quic_builder = self.quic_builder.with_stun(server);
        self
    }

    pub async fn bind(mut self, uri: impl IntoIterator<Item = impl Into<BindUri>>) -> Self {
        self.quic_builder = self.quic_builder.bind(uri).await;
        self
    }

    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.quic_builder = self.quic_builder.defer_idle_timeout(duration);
        self
    }

    pub fn with_quic_parameters(mut self, parameters: ClientParameters) -> Self {
        self.quic_builder = self.quic_builder.with_parameters(parameters);
        self
    }

    pub fn with_streams_concurrency_strategy(
        mut self,
        strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
    ) -> Self {
        self.quic_builder = self
            .quic_builder
            .with_streams_concurrency_strategy(strategy_factory);
        self
    }

    pub fn with_qlog(mut self, logger: Arc<dyn QLog + Send + Sync>) -> Self {
        self.quic_builder = self.quic_builder.with_qlog(logger);
        self
    }

    pub fn with_token_sink(mut self, sink: Arc<dyn TokenSink>) -> Self {
        self.quic_builder = self.quic_builder.with_token_sink(sink);
        self
    }

    pub fn enable_sslkeylog(mut self) -> Self {
        self.quic_builder = self.quic_builder.enable_sslkeylog();
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        self.quic_builder = self.quic_builder.enable_0rtt();
        self
    }

    pub fn with_connection_pool(mut self, pool: Pool<Connection>) -> Self {
        self.pool = pool;
        self
    }
    pub fn with_builder(mut self, builder: Arc<ConnectionBuilder<Connection>>) -> Self {
        self.builder = builder;
        self
    }

    pub fn build(self) -> H3Client {
        let client = match self.client_name {
            Some(client_name) => self.quic_builder.with_name(client_name).build(),
            None => self.quic_builder.build(),
        };
        Client::from_quic_client()
            .pool(self.pool.clone())
            .client(Arc::new(client))
            .builder(self.builder.clone())
            .build()
    }
}
