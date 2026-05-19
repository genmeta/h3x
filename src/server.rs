//! Compatibility server wrapper over [`crate::endpoint::server`].

use std::{error::Error, sync::Arc};

use futures::future;
use snafu::Report;
use tokio::task::JoinSet;
use tracing::Instrument;

pub use crate::endpoint::server::{
    BoxService, BoxServiceFuture, IntoBoxService, MessageStreamError, MethodRouter, ReadStream,
    ReadToStringError, Request, Response, Router, ServersRouter, ServersRouterDispatchError,
    Service, UnresolvedRequest, WriteStream, box_service,
};
use crate::{
    connection::ConnectionBuilder,
    error::Code,
    pool::Pool,
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

#[derive(Debug)]
pub struct Servers<L: quic::Listen, S> {
    pool: Pool<L::Connection>,
    listener: L,
    builder: Arc<ConnectionBuilder<L::Connection>>,
    service: S,
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
        #[builder(default = Pool::empty())] pool: Pool<L::Connection>,
        listener: L,
        service: S,
        #[builder(default = Arc::new(ConnectionBuilder::new(Arc::default())))] builder: Arc<
            ConnectionBuilder<L::Connection>,
        >,
    ) -> Self {
        Self {
            pool,
            listener,
            builder,
            service,
        }
    }

    pub fn quic_listener(&self) -> &L {
        &self.listener
    }

    pub fn quic_listener_mut(&mut self) -> &mut L {
        &mut self.listener
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut S {
        &mut self.service
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Pool<L::Connection>,
        L,
        S,
        Arc<ConnectionBuilder<L::Connection>>,
    ) {
        (self.pool, self.listener, self.service, self.builder)
    }
}

impl<L, S> Servers<L, S>
where
    L: quic::Listen,
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    fn handle_incoming_connection(
        &self,
        connection: Arc<L::Connection>,
    ) -> impl futures::Future<Output = ()> + Send + 'static {
        let pool = self.pool.clone();
        let builder = self.builder.clone();
        let service = self.service.clone();
        let span = tracing::info_span!("handle_connection", server_name = tracing::field::Empty);
        async move {
            tracing::debug!("accepted new QUIC connection");
            let Ok(connection) = builder.build(connection).await else {
                return;
            };

            tracing::debug!("accepted new H3 connection");
            let Ok(local_agent) = connection.local_agent().await else {
                return;
            };
            let Some(local_agent) = local_agent else {
                tracing::debug!("close incoming connection due to missing SNI");
                connection.close(
                    Code::H3_INTERNAL_ERROR,
                    "missing server name (SNI) on incoming connection",
                );
                return;
            };

            tracing::Span::current().record("server_name", local_agent.name());
            let connection = Arc::new(connection);
            _ = pool.try_insert(connection.clone()).await;
            let mut connection_tasks = JoinSet::new();

            loop {
                let (mut read_stream, write_stream) = match connection.accept_message_stream().await
                {
                    Ok(pair) => {
                        tracing::trace!("accepted incoming request stream");
                        pair
                    }
                    Err(error) => {
                        tracing::debug!(
                            error = %Report::from_error(error),
                            "failed to accept incoming request"
                        );
                        break;
                    }
                };

                let stream_id = match read_stream.stream_id().await {
                    Ok(stream_id) => stream_id,
                    Err(error) => {
                        tracing::debug!(
                            error = %Report::from_error(error),
                            "failed to acquire incoming request stream ID"
                        );
                        continue;
                    }
                };

                let mut service = service.clone();
                let connection = connection.clone();
                let unresolved_request = UnresolvedRequest {
                    stream_id: StreamId(stream_id),
                    read_stream,
                    write_stream,
                    connection: Arc::new(connection.erase()),
                };

                let handle_request = async move {
                    if let Err(error) = future::poll_fn(|cx| service.poll_ready(cx)).await {
                        let error = error.into();
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "service not ready to handle incoming request"
                        );
                        return;
                    }

                    if let Err(error) = service.call(unresolved_request).await {
                        let error = error.into();
                        if error
                            .as_ref()
                            .downcast_ref::<ServersRouterDispatchError>()
                            .is_some()
                        {
                            tracing::debug!(
                                stream_id = %stream_id,
                                error = %Report::from_error(error.as_ref()),
                                "close incoming connection due to missing service"
                            );
                            connection.close(Code::H3_NO_ERROR, "no error");
                            return;
                        }
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "failed to handle incoming request"
                        );
                    }
                };
                connection_tasks.spawn(handle_request.in_current_span());
                while connection_tasks.try_join_next().is_some() {}
            }
        }
        .instrument(span)
    }

    pub async fn run(&mut self) -> L::Error {
        let mut tasks = JoinSet::default();

        loop {
            while tasks.try_join_next().is_some() {}
            match self.listener.accept().await {
                Ok(connection) => tasks.spawn(self.handle_incoming_connection(connection)),
                Err(error) => break error,
            };
        }
    }

    pub async fn shutdown(&self) -> Result<(), L::Error> {
        self.listener.shutdown().await
    }
}
