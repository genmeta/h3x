use std::{collections::HashMap, sync::Arc};

use tokio::task::JoinSet;

use crate::{
    connection::{Connection, settings::Settings},
    endpoint::{pool::Pool, server::entity::UnresolvedRequest},
    quic,
};

mod entity;
mod route;
mod service;

#[derive(Debug, Clone)]
pub struct Servers<L: quic::Listen> {
    pool: Pool<L::Connection>,
    acceptor: L,
    settings: Arc<Settings>,
    router: HashMap<String, route::Router>,
}

#[bon::bon]
impl<L: quic::Listen> Servers<L> {
    #[builder]
    pub fn new(
        #[builder(default)] pool: Pool<L::Connection>,
        acceptor: L,
        #[builder(default)] settings: Arc<Settings>,
    ) -> Self {
        Self {
            pool,
            acceptor,
            settings,
            router: HashMap::new(),
        }
    }

    pub fn serve(mut self, domain: impl Into<String>, router: route::Router) -> Self {
        self.router.insert(domain.into(), router);
        self
    }

    pub async fn run(&self) -> L::Error {
        let mut tasks = JoinSet::default();
        let router = Arc::new(self.router.clone());

        loop {
            let connection = match self.acceptor.accept().await {
                Ok(connection) => connection,
                Err(error) => break error,
            };

            let settings = self.settings.clone();
            let router = router.clone();
            tasks.spawn(async move {
                let Ok(connection) = Connection::new(settings, connection).await else {
                    // failed to initial h3 connection
                    return;
                };
                let Ok(connected_server) = connection.local_name() else {
                    // connection already closed
                    return;
                };
                let Some(router) = router.get(&connected_server) else {
                    todo!("fallback: connected server not exist");
                };
                while let Ok((rs, ws)) = connection.accept_request_stream().await
                    && let Ok((req, rsp)) = UnresolvedRequest::new(rs, ws).resolve().await
                {
                    router.handle(req, rsp).await;
                }
            });
        }
    }
}
