use std::sync::Arc;

use http::uri::Authority;

use crate::{
    connection::{Connection, settings::Settings},
    endpoint::pool::{self, Pool},
    quic,
};

mod entity;

pub use entity::{PendingRequest, Request, RequestError, Response};

#[derive(Debug, Clone)]
pub struct Client<C: quic::Connect> {
    pool: Pool<C::Connection>,
    connector: C,
    settings: Arc<Settings>,
}

#[bon::bon]
impl<C: quic::Connect> Client<C> {
    #[builder(state_mod(vis = "pub(crate)"))]
    pub fn new(
        #[builder(default = Pool::global().clone())] pool: Pool<C::Connection>,
        connector: C,
        #[builder(default)] settings: Arc<Settings>,
    ) -> Self {
        Self {
            pool,
            connector,
            settings,
        }
    }

    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<Connection<C::Connection>>, pool::ConnectError<C::Error>> {
        let host_port = server
            .as_str()
            .rsplit('@')
            .next()
            .expect("split always has at least 1 item");
        let connect = async || self.connector.connect(host_port).await;
        self.pool
            .reuse_or_connect_with(server.host(), self.settings.clone(), connect)
            .await
    }
}
