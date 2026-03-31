use std::sync::Arc;

use http::uri::Authority;

pub use crate::message::{stream::MessageStreamError, unify::ReadToStringError};
use crate::{
    connection::{Connection, ConnectionBuilder},
    pool::{self, Pool},
    quic,
};

mod message;
pub use message::{PendingRequest, Request, RequestError, Response};

#[derive(Debug, Clone)]
pub struct Client<C: quic::Connect> {
    pool: Pool<C::Connection>,
    client: C,
    builder: Arc<ConnectionBuilder<C::Connection>>,
}

#[bon::bon]
impl<C: quic::Connect> Client<C> {
    #[builder(
        builder_type(vis = "pub"),
        start_fn(name = from_quic_client, vis = "pub")
    )]
    fn new(
        #[builder(default = Pool::empty())] pool: Pool<C::Connection>,
        client: C,
        #[builder(default = Arc::new(ConnectionBuilder::new(Arc::default())))] builder: Arc<
            ConnectionBuilder<C::Connection>,
        >,
    ) -> Self {
        Self {
            pool,
            client,
            builder,
        }
    }

    pub fn quic_client(&self) -> &C {
        &self.client
    }

    pub fn quic_client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    pub async fn connect(
        &self,
        server: Authority,
    ) -> Result<Arc<Connection<C::Connection>>, pool::ConnectError<C::Error>> {
        self.pool
            .reuse_or_connect_with(&self.client, self.builder.clone(), server)
            .await
    }
}
