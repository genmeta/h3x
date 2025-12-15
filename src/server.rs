use std::{collections::HashMap, sync::Arc};

use snafu::Report;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    connection::{Connection, settings::Settings},
    error::Code,
    pool::Pool,
    quic::{self, GetStreamIdExt},
};

mod message;
mod route;
mod service;

pub use message::{Request, Response, UnresolvedRequest};
pub use route::{MethodRouter, Router};
pub use service::{BoxService, BoxServiceFuture, IntoBoxService, Service, box_service};

pub use crate::message::stream::StreamError;

#[derive(Debug, Clone)]
pub struct Servers<L: quic::Listen> {
    pool: Pool<L::Connection>,
    acceptor: L,
    settings: Arc<Settings>,
    router: Arc<HashMap<String, BoxService>>,
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
            router: Arc::new(HashMap::new()),
        }
    }

    fn router_mut(&mut self) -> &mut HashMap<String, BoxService> {
        Arc::make_mut(&mut self.router)
    }

    pub fn serve(mut self, domain: impl Into<String>, router: impl IntoBoxService) -> Self {
        self.router_mut()
            .insert(domain.into(), router.into_box_service());
        self
    }

    // async fn handle_incoming_connection()

    pub async fn run(&self) -> L::Error {
        let mut tasks = JoinSet::default();
        let router = self.router.clone();

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
                let Ok(remote_agent) = connection.remote_agent().await else {
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
                // TODO: router with authority?
                let Some(service) = router.get(local_agent.name()) else {
                    tracing::debug!(
                        "Close incoming connection due to missing service for {}",
                        local_agent.name()
                    );
                    connection.close(&Code::H3_NO_ERROR);
                    return;
                };

                let mut connection_tasks = JoinSet::new();

                loop {
                    let (mut read_stream, write_stream) =
                        match connection.accept_request_stream().await {
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

                    let stream_id = match read_stream.stream_id().await {
                        Ok(stream_id) => stream_id,
                        Err(error) => {
                            tracing::debug!(
                                error = %Report::from_error(error),
                                "Failed to acquire incoming request stream ID"
                            );
                            continue;
                        }
                    };

                    let mut service = service.clone();
                    let unresolved_request = UnresolvedRequest::new(
                        read_stream,
                        write_stream,
                        local_agent.clone(),
                        remote_agent.clone(),
                    );
                    let span = tracing::info_span!(
                        "handle_request",
                        stream_id = %stream_id,
                        method = tracing::field::Empty,
                        uri = tracing::field::Empty
                    );
                    let handle_request = async move {
                        tracing::debug!("Resolving incoming request");
                        let (mut req, mut rsp) = match unresolved_request.resolve().await {
                            Ok(pair) => pair,
                            Err(error) => {
                                tracing::debug!(
                                    error = %Report::from_error(error),
                                    "Failed to resolve incoming request"
                                );
                                return;
                            }
                        };

                        tracing::Span::current()
                            .record("method", req.method().as_str())
                            .record("uri", req.uri().to_string());
                        tracing::debug!("Resolved new request");
                        match service.downcast_ref::<Router>() {
                            Some(router) => router.serve(&mut req, &mut rsp).await,
                            None => service.serve(&mut req, &mut rsp).await,
                        }
                        // Drop response in place to avoid spawning another tokio task
                        // FIXME: remove this when async drop is stablized (https://github.com/rust-lang/rust/issues/126482)
                        if let Some(drop_future) = rsp.drop() {
                            drop_future.await;
                        }
                    };
                    connection_tasks.spawn(handle_request.instrument(span));
                }
            };
            tasks.spawn(handle_connection.instrument(span));
        }
    }

    pub fn shutdown(&self) {
        self.acceptor.shutdown();
    }
}

#[cfg(feature = "gm-quic")]
mod gm_quic {
    use ::gm_quic::prelude::{BindUri, QuicListeners, ServerError, handy};

    use super::*;

    impl Servers<QuicListeners> {
        pub fn with_server(
            self,
            server_name: impl Into<String>,
            cert_chain: impl handy::ToCertificate,
            private_key: impl handy::ToPrivateKey,
            bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
            ocsp: impl Into<Option<Vec<u8>>>,
            router: impl IntoBoxService,
        ) -> Result<Self, ServerError> {
            let server_name = server_name.into();
            self.acceptor
                .add_server(&server_name, cert_chain, private_key, bind_uris, ocsp)?;
            Ok(self.serve(server_name, router))
        }
    }
}
