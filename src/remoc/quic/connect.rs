use std::{future::Future, sync::Arc};

use futures::future::BoxFuture;
use remoc::prelude::ServerShared;
use snafu::Snafu;

use super::{
    connection::{
        ConnectionClient, ConnectionServerShared, LocalQuicConnection, RemoteQuicConnection,
    },
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

/// Remote trait for a QUIC connector that creates connections over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait RemoteConnect: Send + Sync {
    /// Connect to a remote server identified by the given authority.
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError>;
}

/// Wrapper around [`RemoteConnectClient`] that implements [`quic::Connect`],
/// allowing remote connections to be used wherever a local QUIC connector is expected.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RemoteQuicConnector {
    client: RemoteConnectClient,
}

impl RemoteQuicConnector {
    /// Create a new wrapper from a remoc-generated connect client.
    pub fn new(client: RemoteConnectClient) -> Self {
        Self { client }
    }
}

impl quic::Connect for RemoteQuicConnector {
    type Connection = RemoteQuicConnection;
    type Error = ConnectError;

    fn connect<'a>(
        &'a self,
        server: &'a http::uri::Authority,
    ) -> BoxFuture<'a, Result<Self::Connection, Self::Error>> {
        Box::pin(async move {
            let server = SerdeAuthority::from(server);
            let conn_client = self.client.connect(server).await?;
            Ok(RemoteQuicConnection::new(conn_client))
        })
    }
}

/// Server-side wrapper that implements the remoc [`RemoteConnect`] RTC trait
/// for any local [`quic::Connect`] implementation.
///
/// This allows a real QUIC connector to be served over remoc RTC.
/// Each created connection is wrapped in a [`LocalQuicConnection`] and
/// served as an individual RTC server.
pub struct LocalQuicConnector<C> {
    inner: C,
    tasks: TaskSet,
}

impl<C> LocalQuicConnector<C> {
    /// Wrap a local QUIC connector so it can be served over remoc RTC.
    pub fn new(connector: C) -> Self {
        Self {
            inner: connector,
            tasks: TaskSet::new(),
        }
    }
}

impl<C> LocalQuicConnector<C>
where
    C: quic::Connect + Send + Sync + 'static,
    C::Connection: 'static,
{
    /// Convert this local connector into a remote-accessible connector.
    ///
    /// Consumes `self` and returns:
    /// - A [`RemoteQuicClient`] that can be serialized and sent to a remote peer.
    /// - A `Future` that must be polled to drive the RTC server and all spawned tasks.
    ///   When this future is dropped, all associated tasks are cancelled.
    pub fn into_remote(
        self,
    ) -> (
        RemoteQuicConnector,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (server, client) = RemoteConnectServerShared::new(Arc::new(self), 1);
        let remote = RemoteQuicConnector::new(client);
        let fut = async move {
            let _ = server.serve(true).await;
        };
        (remote, fut)
    }
}

impl<C> RemoteConnect for LocalQuicConnector<C>
where
    C: quic::Connect + Send + Sync + 'static,
    C::Connection: 'static,
{
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError> {
        let authority =
            http::uri::Authority::try_from(server).map_err(|e| ConnectError::Remote {
                source: StringError::new(e.to_string()),
            })?;
        let conn = self
            .inner
            .connect(&authority)
            .await
            .map_err(|e| ConnectError::Remote {
                source: StringError::new(e.to_string()),
            })?;
        let local = LocalQuicConnection::new(conn);
        let (server, client) = ConnectionServerShared::new(Arc::new(local), 1);
        self.tasks.spawn(async move {
            let _ = server.serve(true).await;
        });
        Ok(client)
    }
}
