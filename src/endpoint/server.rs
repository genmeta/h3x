use std::{collections::HashMap, sync::Arc};

use snafu::Report;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    connection::{Connection, settings::Settings},
    endpoint::pool::Pool,
    error::Code,
    quic::{self, GetStreamIdExt},
};

mod entity;
mod method;
mod route;
mod service;

pub use entity::{Request, Response, UnresolvedRequest};
pub use method::MethodRouter;
pub use route::Router;
pub use service::{
    BoxService, BoxServiceFuture, ErasedService, IntoBoxService, Service, box_service,
};

#[derive(Debug, Clone)]
pub struct Servers<L: quic::Listen> {
    pool: Pool<L::Connection>,
    acceptor: L,
    settings: Arc<Settings>,
    router: HashMap<String, BoxService>,
}

#[bon::bon]
impl<L: quic::Listen> Servers<L> {
    #[builder]
    pub fn new(
        #[builder(default = Pool::global().clone())] pool: Pool<L::Connection>,
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

    pub fn serve(mut self, domain: impl Into<String>, router: impl IntoBoxService) -> Self {
        self.router.insert(domain.into(), router.into_box_service());
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

            let pool = self.pool.clone();
            let settings = self.settings.clone();
            let router = router.clone();
            let span =
                tracing::info_span!("handle_connection", server_name = tracing::field::Empty);
            let handle_connection = async move {
                tracing::debug!("Accepted new QUIC connection");
                let Ok(connection) = Connection::new(settings, connection).await else {
                    // failed to initial h3 connection
                    return;
                };
                tracing::debug!("Accepted new H3 connection");
                let Ok(local_agent) = connection.local_agent().await else {
                    // connection already closed
                    return;
                };
                let Some(local_agent) = local_agent else {
                    tracing::debug!("Close incoming connection due to missing SNI");
                    // no SNI
                    connection.close(&Code::H3_INTERNAL_ERROR);
                    return;
                };
                tracing::Span::current().record("server_name", local_agent.name());

                let connection = Arc::new(connection);
                _ = pool.try_insert(connection.clone());
                let Some(router) = router.get(local_agent.name()) else {
                    tracing::debug!("fallback");
                    todo!("fallback: connected server not exist");
                };

                let mut connection_tasks = JoinSet::new();

                loop {
                    let (mut rs, ws) = match connection.accept_request_stream().await {
                        Ok(pair) => {
                            tracing::debug!("Accepted incoming request stream");
                            pair
                        }
                        Err(error) => {
                            tracing::debug!(
                                error = %Report::from_error(error),
                                "Failed to accept incoming request"
                            );
                            break;
                        }
                    };

                    let stream_id = match rs.stream_id().await {
                        Ok(stream_id) => stream_id,
                        Err(error) => {
                            tracing::debug!(
                                error = %Report::from_error(error),
                                "Failed to get stream ID for incoming request"
                            );
                            continue;
                        }
                    };

                    let router = router.clone();
                    let span = tracing::info_span!("handle_request", stream_id = %stream_id);
                    let handle_request = async move {
                        tracing::debug!("Resolving incoming request");
                        let (req, rsp) = match UnresolvedRequest::new(rs, ws).resolve().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::debug!(
                                    error = %Report::from_error(error),
                                    "Failed to resolve incoming request"
                                );
                                return;
                            }
                        };
                        tracing::debug!(request=?req.headers(), "Resolved new request");
                        // FIXME: downcast into Router to avoid cloning
                        router.clone().handle(req, rsp).await;
                    };
                    connection_tasks.spawn(handle_request.instrument(span));
                }
            };
            tasks.spawn(handle_connection.instrument(span));
        }
    }
}
