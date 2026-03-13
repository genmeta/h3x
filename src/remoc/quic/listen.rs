use std::{future::Future, sync::Arc};

use futures::future::BoxFuture;
use remoc::prelude::ServerShared;
use snafu::Snafu;

use super::{
    connection::{ConnectionClient, serve_quic_connection},
    error::StringError,
    task_set::TaskSet,
};
use crate::quic;

#[derive(Debug, Snafu, Clone, serde::Serialize, serde::Deserialize)]
pub enum ListenError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait Listen: Send + Sync {
    async fn accept(&self) -> Result<ConnectionClient, ListenError>;
    async fn shutdown(&self) -> Result<(), ListenError>;
}

pub fn serve_quic_listener<L>(
    listener: L,
) -> (ListenClient, impl Future<Output = ()> + Send + 'static)
where
    L: quic::Listen + Send + Sync + 'static,
    L::Connection: 'static,
    <L::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <L::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    let (server, client) = ListenServerShared::new(Arc::new(ServedListener::new(listener)), 1);
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

impl quic::Listen for ListenClient {
    type Connection = ConnectionClient;
    type Error = ListenError;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        Box::pin(Listen::accept(self))
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(Listen::shutdown(self))
    }
}

struct ServedListener<L> {
    listener: L,
    tasks: TaskSet,
}

impl<L> ServedListener<L> {
    fn new(listener: L) -> Self {
        Self {
            listener,
            tasks: TaskSet::new(),
        }
    }
}

impl<L> Listen for ServedListener<L>
where
    L: quic::Listen + Send + Sync + 'static,
    L::Connection: 'static,
    <L::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <L::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    async fn accept(&self) -> Result<ConnectionClient, ListenError> {
        let connection = self
            .listener
            .accept()
            .await
            .map_err(|error| ListenError::Remote {
                source: StringError::new(error.to_string()),
            })?;
        let (client, fut) = serve_quic_connection(connection);
        self.tasks.spawn(fut);
        Ok(client)
    }

    async fn shutdown(&self) -> Result<(), ListenError> {
        self.listener
            .shutdown()
            .await
            .map_err(|error| ListenError::Remote {
                source: StringError::new(error.to_string()),
            })
    }
}
