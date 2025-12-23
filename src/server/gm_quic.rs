use std::time::Duration;

pub use ::gm_quic::prelude::BuildListenersError;
use ::gm_quic::{
    builder::QuicListenersBuilder,
    prelude::{
        AuthClient, BindUri, Connection, ProductStreamsConcurrencyController, QuicListeners,
        ServerError, handy,
    },
    qbase::{param::ServerParameters, token::TokenProvider},
    qevent::telemetry::Log,
    qinterface::factory::ProductQuicIO,
};
use rustls::{crypto::CryptoProvider, server::danger::ClientCertVerifier};

use super::*;

pub struct GmQuicServersTlsBuilder {
    crypto_provider: Option<Arc<CryptoProvider>>,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl Servers<QuicListeners> {
    pub fn builder() -> GmQuicServersTlsBuilder {
        GmQuicServersTlsBuilder {
            crypto_provider: None,
            client_cert_verifier: None,
        }
    }
}

impl GmQuicServersTlsBuilder {
    pub fn with_crypto_provider(mut self, crypto_provider: impl Into<Arc<CryptoProvider>>) -> Self {
        self.crypto_provider = Some(crypto_provider.into());
        self
    }

    pub fn with_client_cert_verifier(
        mut self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<GmQuicServersBuilder, BuildListenersError> {
        self.client_cert_verifier = Some(client_cert_verifier);
        self.try_into()
    }

    pub fn without_client_cert_verifier(
        mut self,
    ) -> Result<GmQuicServersBuilder, BuildListenersError> {
        self.client_cert_verifier = None;
        self.try_into()
    }
}

impl TryFrom<GmQuicServersTlsBuilder> for GmQuicServersBuilder {
    type Error = BuildListenersError;

    fn try_from(builder: GmQuicServersTlsBuilder) -> Result<Self, Self::Error> {
        let listeners_builder = match builder.crypto_provider {
            Some(crypto_provider) => QuicListeners::builder_with_crypto_provider(crypto_provider),
            None => QuicListeners::builder(),
        }?;
        let listeners_builder = match builder.client_cert_verifier {
            Some(client_cert_verifier) => {
                listeners_builder.with_client_cert_verifier(client_cert_verifier)
            }
            None => listeners_builder.without_client_cert_verifier(),
        }
        .with_alpns(vec!["h3"]);
        Ok(GmQuicServersBuilder {
            builder: listeners_builder,
            backlog: 1024,
            pool: Pool::global().clone(),
            settings: Default::default(),
        })
    }
}

pub struct GmQuicServersBuilder {
    builder: QuicListenersBuilder<rustls::ServerConfig>,
    backlog: usize,
    pool: Pool<Connection>,
    settings: Arc<Settings>,
}

impl GmQuicServersBuilder {
    pub fn with_token_provider(mut self, token_provider: Arc<dyn TokenProvider>) -> Self {
        self.builder = self.builder.with_token_provider(token_provider);
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

    pub fn defer_idle_timeout(mut self, duration: Duration) -> Self {
        self.builder = self.builder.defer_idle_timeout(duration);
        self
    }

    pub fn with_quic_parameters(mut self, parameters: ServerParameters) -> Self {
        self.builder = self.builder.with_parameters(parameters);
        self
    }

    pub fn with_iface_factory(mut self, factory: impl ProductQuicIO + 'static) -> Self {
        self.builder = self.builder.with_iface_factory(factory);
        self
    }

    pub fn with_qlog(mut self, logger: Arc<dyn Log + Send + Sync>) -> Self {
        self.builder = self.builder.with_qlog(logger);
        self
    }

    pub fn enable_anti_port_scan(mut self) -> Self {
        self.builder = self.builder.enable_anti_port_scan();
        self
    }

    pub fn with_client_auther(mut self, client_auther: impl AuthClient + 'static) -> Self {
        self.builder = self.builder.with_client_auther(client_auther);
        self
    }

    pub fn enable_0rtt(mut self) -> Self {
        self.builder = self.builder.enable_0rtt();
        self
    }

    pub fn with_backlog(mut self, backlog: usize) -> Self {
        self.backlog = backlog;
        self
    }

    pub fn build(self) -> Servers<Arc<QuicListeners>> {
        Servers::from_quic_listener()
            .listener(self.builder.listen(self.backlog))
            .pool(self.pool)
            .settings(self.settings)
            .build()
    }
}

impl Servers<Arc<QuicListeners>> {
    pub fn add_server(
        &mut self,
        server_name: impl Into<String>,
        cert_chain: impl handy::ToCertificate,
        private_key: impl handy::ToPrivateKey,
        ocsp: impl Into<Option<Vec<u8>>>,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
        router: impl IntoBoxService,
    ) -> Result<&mut Self, ServerError> {
        let server_name = server_name.into();
        self.listener
            .add_server(&server_name, cert_chain, private_key, bind_uris, ocsp)?;
        Ok(self.serve(server_name, router))
    }
}
