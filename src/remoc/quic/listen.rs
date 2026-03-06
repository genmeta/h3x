use std::{future::Future, sync::Arc};

use futures::future::BoxFuture;
use remoc::prelude::ServerShared;
use snafu::Snafu;

use super::{
    connection::{
        ConnectionClient, ConnectionServerShared, LocalQuicConnection, RemoteQuicConnection,
    },
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

/// Remote trait for a QUIC listener, providing accept and shutdown operations
/// over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait Listen: Send + Sync {
    /// Accept the next incoming connection.
    async fn accept(&self) -> Result<ConnectionClient, ListenError>;

    /// Shutdown the listener.
    ///
    /// The underlying `quic::Listen::shutdown()` returns `()`, but RTC requires
    /// `Result`. The server-side implementation calls `shutdown()` and returns `Ok(())`.
    async fn shutdown(&self) -> Result<(), ListenError>;
}

/// Wrapper around [`RemoteListenClient`] that implements [`quic::Listen`].
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RemoteQuicListener {
    client: ListenClient,
}

impl RemoteQuicListener {
    /// Create a new wrapper from a remoc-generated listen client.
    pub fn new(client: ListenClient) -> Self {
        Self { client }
    }
}

impl quic::Listen for RemoteQuicListener {
    type Connection = RemoteQuicConnection;
    type Error = ListenError;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        Box::pin(async move {
            let conn_client = self.client.accept().await?;
            Ok(RemoteQuicConnection::new(conn_client))
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), Self::Error>> {
        Box::pin(self.client.shutdown())
    }
}

/// Server-side wrapper that implements the remoc [`Listen`] RTC trait
/// for any local [`quic::Listen`] implementation.
///
/// This allows a real QUIC listener to be served over remoc RTC.
/// Each accepted connection is wrapped in a [`LocalQuicConnection`] and
/// served as an individual RTC server.
pub struct LocalQuicListener<L> {
    inner: L,
    tasks: TaskSet,
}

impl<L> LocalQuicListener<L> {
    /// Wrap a local QUIC listener so it can be served over remoc RTC.
    pub fn new(listener: L) -> Self {
        Self {
            inner: listener,
            tasks: TaskSet::new(),
        }
    }
}

impl<L> LocalQuicListener<L>
where
    L: quic::Listen + Send + Sync + 'static,
    L::Connection: 'static,
{
    /// Convert this local listener into a remote-accessible listener.
    ///
    /// Consumes `self` and returns:
    /// - A [`RemoteQuicClient`] that can be serialized and sent to a remote peer.
    /// - A `Future` that must be polled to drive the RTC server and all spawned tasks.
    ///   When this future is dropped, all associated tasks are cancelled.
    pub fn into_remote(
        self,
    ) -> (
        RemoteQuicListener,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (server, client) = ListenServerShared::new(Arc::new(self), 1);
        let remote = RemoteQuicListener::new(client);
        let fut = async move {
            let _ = server.serve(true).await;
        };
        (remote, fut)
    }
}

impl<L> Listen for LocalQuicListener<L>
where
    L: quic::Listen + Send + Sync + 'static,
    L::Connection: 'static,
{
    async fn accept(&self) -> Result<ConnectionClient, ListenError> {
        let conn = self.inner.accept().await.map_err(|e| ListenError::Remote {
            source: StringError::new(e.to_string()),
        })?;
        let local = LocalQuicConnection::new(conn);
        let (server, client) = ConnectionServerShared::new(Arc::new(local), 1);
        self.tasks.spawn(async move {
            let _ = server.serve(true).await;
        });
        Ok(client)
    }

    async fn shutdown(&self) -> Result<(), ListenError> {
        self.inner
            .shutdown()
            .await
            .map_err(|e| ListenError::Remote {
                source: StringError::new(e.to_string()),
            })
    }
}
