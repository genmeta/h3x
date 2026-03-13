use std::{future::Future, sync::Arc};

use futures::future::BoxFuture;
use remoc::prelude::ServerShared;
use snafu::Snafu;

use super::{
    connection::{ConnectionClient, serve_quic_connection},
    error::StringError,
    serde_types::SerdeAuthority,
    task_set::TaskSet,
};
use crate::quic;

#[derive(Debug, Snafu, Clone, serde::Serialize, serde::Deserialize)]
pub enum ConnectError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait RemoteConnect: Send + Sync {
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError>;
}

pub(crate) fn serve_quic_connector<C>(
    connector: C,
) -> (
    RemoteConnectClient,
    impl Future<Output = ()> + Send + 'static,
)
where
    C: quic::Connect + Send + Sync + 'static,
    C::Connection: 'static,
    <C::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <C::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    let (server, client) =
        RemoteConnectServerShared::new(Arc::new(ServedConnector::new(connector)), 1);
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

impl quic::Connect for RemoteConnectClient {
    type Connection = ConnectionClient;
    type Error = ConnectError;

    fn connect<'a>(
        &'a self,
        server: &'a http::uri::Authority,
    ) -> BoxFuture<'a, Result<Self::Connection, Self::Error>> {
        Box::pin(async move { RemoteConnect::connect(self, SerdeAuthority::from(server)).await })
    }
}

struct ServedConnector<C> {
    connector: C,
    tasks: TaskSet,
}

impl<C> ServedConnector<C> {
    fn new(connector: C) -> Self {
        Self {
            connector,
            tasks: TaskSet::new(),
        }
    }
}

impl<C> RemoteConnect for ServedConnector<C>
where
    C: quic::Connect + Send + Sync + 'static,
    C::Connection: 'static,
    <C::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <C::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError> {
        let authority =
            http::uri::Authority::try_from(server).map_err(|error| ConnectError::Remote {
                source: StringError::new(error.to_string()),
            })?;
        let connection =
            self.connector
                .connect(&authority)
                .await
                .map_err(|error| ConnectError::Remote {
                    source: StringError::new(error.to_string()),
                })?;
        let (client, fut) = serve_quic_connection(connection);
        self.tasks.spawn(fut);
        Ok(client)
    }
}
