use std::{sync::LazyLock, time::Duration};

use ::gm_quic::{
    builder::QuicClientBuilder,
    prelude::{
        BindUri, Connection, ProductStreamsConcurrencyController, QuicClient,
        handy::{ToCertificate, ToPrivateKey},
    },
    qbase::{param::ClientParameters, token::TokenSink},
    qevent::telemetry::Log,
    qinterface::factory::ProductQuicIO,
};
use rustls::{
    ClientConfig, RootCertStore,
    client::WebPkiServerVerifier,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use snafu::{ResultExt, Snafu};

use super::*;
use crate::util::tls::{DangerousServerCertVerifier, verify_certficate_for_name};

fn default_root_cert_store() -> &'static Arc<RootCertStore> {
    static GENMETA_ROOT_CERT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store
            .add_parsable_certificates(include_bytes!("../../genmeta-root.crt").to_certificate());
        Arc::new(root_cert_store)
    });
    &GENMETA_ROOT_CERT_STORE
}

enum ServerCertVerifier {
    WebPki(Arc<WebPkiServerVerifier>),
    Roots(Arc<RootCertStore>),
    None,
}

impl Default for ServerCertVerifier {
    fn default() -> Self {
        Self::Roots(default_root_cert_store().clone())
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

pub struct GmQuicClientTlsBuilder {
    server_cert_verifier: ServerCertVerifier,
    client_identity: Option<(String, Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    crypto_provider: Option<Arc<CryptoProvider>>,
}

impl Client<QuicClient> {
    pub fn builder() -> GmQuicClientTlsBuilder {
        GmQuicClientTlsBuilder {
            server_cert_verifier: ServerCertVerifier::default(),
            client_identity: None,
            crypto_provider: None,
        }
    }
}

impl GmQuicClientTlsBuilder {
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

    pub fn with_identity(
        mut self,
        name: impl Into<String>,
        cert_chain: impl ToCertificate,
        private_key: impl ToPrivateKey,
    ) -> Result<GmQuicClientBuilder, BuildClientError> {
        self.client_identity = Some((
            name.into(),
            cert_chain.to_certificate(),
            private_key.to_private_key(),
        ));
        self.try_into()
    }

    pub fn without_identity(mut self) -> Result<GmQuicClientBuilder, BuildClientError> {
        self.client_identity = None;
        self.try_into()
    }
}

impl TryFrom<GmQuicClientTlsBuilder> for GmQuicClientBuilder {
    type Error = BuildClientError;

    fn try_from(builder: GmQuicClientTlsBuilder) -> Result<Self, Self::Error> {
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
                verify_certficate_for_name(&cert[0], &name)
                    .context(build_client_error::InvalidIdentitySnafu { name: &name })?;
                let tls_config = tls_config_buider
                    .with_client_auth_cert(cert, key)
                    .map_err(InvalidIdentity::from)
                    .context(build_client_error::InvalidIdentitySnafu { name: &name })?;
                (tls_config, Some(name))
            }
            None => (tls_config_buider.with_no_client_auth(), None),
        };

        Ok(GmQuicClientBuilder {
            builder: QuicClient::builder_with_tls(tls_config).with_alpns(vec!["h3"]),
            client_name,
            pool: Pool::global().clone(),
            settings: Arc::default(),
        })
    }
}

pub struct GmQuicClientBuilder {
    builder: QuicClientBuilder<rustls::ClientConfig>,
    client_name: Option<String>,
    pool: Pool<Connection>,
    settings: Arc<Settings>,
}

impl GmQuicClientBuilder {
    pub fn with_iface_factory(mut self, factory: impl ProductQuicIO + 'static) -> Self {
        self.builder = self.builder.with_iface_factory(factory);
        self
    }

    pub fn bind(mut self, uri: impl IntoIterator<Item = impl Into<BindUri>>) -> Self {
        self.builder = self.builder.bind(uri);
        self
    }

    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.builder = self.builder.defer_idle_timeout(duration);
        self
    }

    pub fn with_quic_parameters(mut self, parameters: ClientParameters) -> Self {
        self.builder = self.builder.with_parameters(parameters);
        self
    }

    pub fn with_streams_concurrency_strategy(
        mut self,
        strategy_factory: impl ProductStreamsConcurrencyController + 'static,
    ) -> Self {
        self.builder = self
            .builder
            .with_streams_concurrency_strategy(strategy_factory);
        self
    }

    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.builder = self.builder.with_qlog(logger);
        self
    }

    pub fn with_token_sink(mut self, sink: Arc<dyn TokenSink>) -> Self {
        self.builder = self.builder.with_token_sink(sink);
        self
    }

    pub fn enable_sslkeylog(mut self) -> Self {
        self.builder = self.builder.enable_sslkeylog();
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        self.builder = self.builder.enable_0rtt();
        self
    }

    pub fn with_conenction_pool(mut self, pool: Pool<Connection>) -> Self {
        self.pool = pool;
        self
    }

    pub fn with_settings(mut self, settings: Arc<Settings>) -> Self {
        self.settings = settings;
        self
    }

    pub fn build(self) -> Client<QuicClient> {
        let client = match self.client_name {
            Some(client_name) => self.builder.with_name(client_name).build(),
            None => self.builder.build(),
        };
        Client {
            pool: self.pool,
            client,
            settings: self.settings,
        }
    }
}
