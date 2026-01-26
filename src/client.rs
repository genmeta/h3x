use std::sync::Arc;

use http::uri::Authority;

pub use crate::message::stream::{ReadToStringError, StreamError};
use crate::{
    connection::{Connection, settings::Settings},
    pool::{self, Pool},
    quic,
};

mod message;
pub use message::{PendingRequest, Request, RequestError, Response};

#[cfg(feature = "gm-quic")]
mod gm_quic;
#[cfg(feature = "gm-quic")]
pub use crate::{
    client::gm_quic::{BuildClientError, GmQuicClientBuilder, GmQuicClientTlsBuilder},
    util::tls::InvalidIdentity,
};

#[derive(Debug, Clone)]
pub struct Client<C: quic::Connect> {
    pool: Pool<C::Connection>,
    client: C,
    settings: Arc<Settings>,
}

#[bon::bon]
impl<C: quic::Connect> Client<C> {
    #[builder(
        builder_type(vis = "pub"),
        start_fn(name = from_quic_client, vis = "pub")
    )]
    fn new(
        #[builder(default = Pool::global().clone())] pool: Pool<C::Connection>,
        client: C,
        #[builder(default)] settings: Arc<Settings>,
    ) -> Self {
        Self {
            pool,
            client,
            settings,
        }
    }

    pub fn quic_clinet(&self) -> &C {
        &self.client
    }

    pub fn quic_client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<Connection<C::Connection>>, pool::ConnectError<C::Error>> {
        let connect = async || self.client.connect(&server).await;
        self.pool
            .reuse_or_connect_with(server.clone(), self.settings.clone(), connect)
            .await
    }
}

#[cfg(feature = "gm-quic")]
pub fn builder() -> gm_quic::GmQuicClientTlsBuilder {
    Client::builder()
}
