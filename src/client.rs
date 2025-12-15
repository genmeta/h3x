use std::sync::Arc;

use http::uri::Authority;

use crate::{
    connection::{Connection, settings::Settings},
    pool::{self, Pool},
    quic,
};

mod message;

pub use message::{PendingRequest, Request, RequestError, Response};

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
            .rsplit_once('@')
            .map(|(_username_password, host_port)| host_port)
            .unwrap_or(server.as_str());
        let connect = async || self.connector.connect(host_port).await;
        self.pool
            .reuse_or_connect_with(server.clone(), self.settings.clone(), connect)
            .await
    }
}
