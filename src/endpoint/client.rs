use std::sync::Arc;

use crate::{
    connection::{Connection, settings::Settings},
    endpoint::pool::{self, Pool},
    quic,
};

mod entity;

#[derive(Debug, Clone)]
pub struct Client<C: quic::Connect> {
    pool: Pool<C::Connection>,
    connector: C,
    settings: Arc<Settings>,
}

#[bon::bon]
impl<C: quic::Connect> Client<C> {
    #[builder]
    pub fn new(
        #[builder(default)] pool: Pool<C::Connection>,
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
        name: &str,
    ) -> Result<Arc<Connection<C::Connection>>, pool::ConnectError<C::Error>> {
        self.pool
            .reuse_or_connect_with(name, self.settings.clone(), async |name| {
                self.connector.connect(name).await
            })
            .await
    }
}
