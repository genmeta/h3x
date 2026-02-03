use std::{collections::HashMap, error::Error, sync::Arc};

use futures::future::{self};
use snafu::Report;
use tokio::task::JoinSet;
use tracing::Instrument;

pub use crate::message::stream::{ReadStream, ReadToStringError, StreamError, WriteStream};
use crate::{
    connection::{Connection, settings::Settings},
    error::Code,
    pool::Pool,
    quic::{self, GetStreamIdExt},
};

mod message;
pub use message::{Request, Response, UnresolvedRequest};
mod route;
pub use route::{MethodRouter, Router};
mod service;
pub use service::{BoxService, BoxServiceFuture, IntoBoxService, Service, box_service};
#[cfg(feature = "http-body")]
pub mod tower;
#[cfg(feature = "http-body")]
pub use tower::TowerService;

#[derive(Debug)]
pub struct Servers<L: quic::Listen, S> {
    pool: Pool<L::Connection>,
    listener: L,
    settings: Arc<Settings>,
    router: Arc<HashMap<String, S>>,
}

#[bon::bon]
impl<L, S> Servers<L, S>
where
    L: quic::Listen,
{
    #[builder(
        builder_type(vis = "pub"),
        start_fn(name = from_quic_listener, vis = "pub")
    )]
    fn new(
        #[builder(default = Pool::global().clone())] pool: Pool<L::Connection>,
        listener: L,
        #[builder(default)] settings: Arc<Settings>,
    ) -> Self {
        Self {
            pool,
            listener,
            settings,
            router: Arc::new(HashMap::new()),
        }
    }

    pub fn quic_listener(&self) -> &L {
        &self.listener
    }

    pub fn quic_listener_mut(&mut self) -> &mut L {
        &mut self.listener
    }
}

impl<L, S> Servers<L, S>
where
    L: quic::Listen,
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    fn router_mut(&mut self) -> &mut HashMap<String, S> {
        Arc::make_mut(&mut self.router)
    }

    pub fn serve(&mut self, domain: impl Into<String>, router: S) -> &mut Self {
        self.router_mut().insert(domain.into(), router);
        self
    }

    fn handle_incoming_connection(
        &self,
        connection: L::Connection,
    ) -> impl futures::Future<Output = ()> + Send + 'static {
        let pool = self.pool.clone();
        let settings = self.settings.clone();
        let router = self.router.clone();
        let span = tracing::info_span!("handle_connection", server_name = tracing::field::Empty);
        async move {
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
                let (mut read_stream, write_stream) = match connection.accept_request_stream().await
                {
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
                let unresolved_request = UnresolvedRequest {
                    request_stream: read_stream,
                    remote_agent: remote_agent.clone(),
                    response_stream: write_stream,
                    local_agent: local_agent.clone(),
                };

                let handle_request = async move {
                    if let Err(error) = future::poll_fn(|cx| service.poll_ready(cx)).await {
                        let error = error.into();
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "Service not ready to handle incoming request"
                        );
                        return;
                    }

                    if let Err(error) = service.call(unresolved_request).await {
                        let error = error.into();
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "Failed to handle incoming request"
                        );
                    }
                };
                connection_tasks.spawn(handle_request.in_current_span());
            }
        }
        .instrument(span)
    }

    pub async fn run(&self) -> L::Error {
        let mut tasks = JoinSet::default();

        loop {
            match self.listener.accept().await {
                Ok(connection) => tasks.spawn(self.handle_incoming_connection(connection)),
                Err(error) => break error,
            };
        }
    }

    pub fn shutdown(&self) {
        self.listener.shutdown();
    }
}
