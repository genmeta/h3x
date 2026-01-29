use std::{error::Error, sync::Arc, time::Duration};

use ::gm_quic::{
    builder::QuicListenersBuilder,
    prelude::{
        AuthClient, BindUri, Connection, ListenError, ProductStreamsConcurrencyController,
        QuicListeners, ServerError, handy,
    },
    qbase::{param::ServerParameters, token::TokenProvider},
    qevent::telemetry::QLog,
    qinterface::io::ProductIO,
};
use rustls::{crypto::CryptoProvider, server::danger::ClientCertVerifier};

use crate::{
    connection::settings::Settings,
    pool::Pool,
    server::{Servers, UnresolvedRequest},
};

pub struct H3ServersTlsBuilder {
    crypto_provider: Option<Arc<CryptoProvider>>,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

pub type H3Servers<S> = Servers<Arc<QuicListeners>, S>;

impl H3Servers<()> {
    pub fn builder() -> H3ServersTlsBuilder {
        H3ServersTlsBuilder {
            crypto_provider: None,
            client_cert_verifier: None,
        }
    }
}

impl H3ServersTlsBuilder {
    pub fn with_crypto_provider(mut self, crypto_provider: impl Into<Arc<CryptoProvider>>) -> Self {
        self.crypto_provider = Some(crypto_provider.into());
        self
    }

    pub fn with_client_cert_verifier(
        mut self,
        client_cert_verifier: Arc<dyn ClientCertVerifier>,
    ) -> Result<H3ServersBuilder, rustls::Error> {
        self.client_cert_verifier = Some(client_cert_verifier);
        self.try_into()
    }

    pub fn without_client_cert_verifier(mut self) -> Result<H3ServersBuilder, rustls::Error> {
        self.client_cert_verifier = None;
        self.try_into()
    }
}

impl TryFrom<H3ServersTlsBuilder> for H3ServersBuilder {
    type Error = rustls::Error;

    fn try_from(builder: H3ServersTlsBuilder) -> Result<Self, Self::Error> {
        let listeners_builder = match builder.crypto_provider {
            Some(crypto_provider) => QuicListeners::builder_with_crypto_provider(crypto_provider),
            None => Ok(QuicListeners::builder()),
        }?;
        let listeners_builder = match builder.client_cert_verifier {
            Some(client_cert_verifier) => {
                listeners_builder.with_client_cert_verifier(client_cert_verifier)
            }
            None => listeners_builder.without_client_cert_verifier(),
        }
        .with_alpns(vec!["h3"]);
        Ok(H3ServersBuilder {
            builder: listeners_builder,
            backlog: 1024,
            pool: Pool::global().clone(),
            settings: Default::default(),
        })
    }
}

pub struct H3ServersBuilder {
    builder: QuicListenersBuilder<rustls::ServerConfig>,
    backlog: usize,
    pool: Pool<Connection>,
    settings: Arc<Settings>,
}

impl H3ServersBuilder {
    pub fn with_token_provider(mut self, token_provider: Arc<dyn TokenProvider>) -> Self {
        self.builder = self.builder.with_token_provider(token_provider);
        self
    }

    pub fn with_streams_concurrency_strategy(
        mut self,
        strategy_factory: Arc<dyn ProductStreamsConcurrencyController>,
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

    pub fn with_iface_factory(mut self, factory: Arc<dyn ProductIO + 'static>) -> Self {
        self.builder = self.builder.with_iface_factory(factory);
        self
    }

    pub fn with_qlog(mut self, logger: Arc<dyn QLog + Send + Sync>) -> Self {
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

    pub fn build<S>(self) -> Result<H3Servers<S>, ListenError> {
        let listener = self.builder.listen(self.backlog)?;
        Ok(Servers::from_quic_listener()
            .listener(listener)
            .pool(self.pool)
            .settings(self.settings)
            .build())
    }
}

impl<S> Servers<Arc<QuicListeners>, S>
where
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    pub async fn add_server(
        &mut self,
        server_name: impl Into<String>,
        cert_chain: impl handy::ToCertificate,
        private_key: impl handy::ToPrivateKey,
        ocsp: impl Into<Option<Vec<u8>>>,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
        router: S,
    ) -> Result<&mut Self, ServerError> {
        let server_name = server_name.into();
        self.quic_listener()
            .add_server(&server_name, cert_chain, private_key, bind_uris, ocsp)
            .await?;
        Ok(self.serve(server_name, router))
    }
}
