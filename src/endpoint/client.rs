use std::sync::Arc;

use crate::{
    connection::Connection,
    endpoint::pool::{ConnectError, Pool},
    quic,
};

mod entity;

pub struct Client<C: quic::Connect> {
    connector: C,
    pool: Arc<Pool<C::Connection>>,
}

impl<C: quic::Connect + std::fmt::Debug> std::fmt::Debug for Client<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("connector", &self.connector)
            .field("pool", &self.pool)
            .finish()
    }
}

#[bon::bon]
impl<C: quic::Connect> Client<C>
where
    C::Connection: Send + 'static,
    <C::Connection as quic::ManageStream>::StreamReader: Send,
    <C::Connection as quic::ManageStream>::StreamWriter: Send,
{
    #[builder]
    pub fn new(pool: Arc<Pool<C::Connection>>, connector: C) -> Self {
        Self { connector, pool }
    }

    pub async fn connect(
        &self,
        name: &str,
    ) -> Result<Arc<Connection<C::Connection>>, ConnectError<C::Error>> {
        self.pool.reuse_or_connect(&self.connector, name).await
    }
}
