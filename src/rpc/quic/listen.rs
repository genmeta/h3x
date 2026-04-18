use std::sync::Arc;

use remoc::prelude::ServerShared;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tracing::Instrument;

use super::connection::{ConnectionClient, ConnectionServerShared, RemoteConnection};
use crate::{quic, rpc::error::StringError};

#[derive(Debug, Snafu, Clone, Serialize, Deserialize)]
pub enum ListenError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait Listen: Send + Sync {
    async fn accept(&mut self) -> Result<ConnectionClient, ListenError>;
    async fn shutdown(&self) -> Result<(), ListenError>;
}

// ---------------------------------------------------------------------------
// Server side: blanket — any quic::Listen implements the RTC trait
// ---------------------------------------------------------------------------

impl<L> Listen for L
where
    L: quic::Listen + 'static,
    <L::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <L::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    async fn accept(&mut self) -> Result<ConnectionClient, ListenError> {
        // lossy: cross-process serialization boundary
        let connection = quic::Listen::accept(self)
            .await
            .map_err(|e| StringError::new(e.to_string()))?;
        let (server, client) = ConnectionServerShared::new(Arc::new(connection), 1);
        tokio::spawn(
            (async move {
                let _ = server.serve(true).await;
            })
            .in_current_span(),
        );
        Ok(client)
    }

    async fn shutdown(&self) -> Result<(), ListenError> {
        // lossy: cross-process serialization boundary
        quic::Listen::shutdown(self)
            .await
            .map_err(|e| StringError::new(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client side: RemoteListener wraps ListenClient → quic::Listen
// ---------------------------------------------------------------------------

/// A wrapper around [`ListenClient`] that implements [`quic::Listen`].
///
/// Transparent serialization allows sending a `RemoteListener` directly
/// across process boundaries without unwrapping.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RemoteListener(ListenClient);

impl RemoteListener {
    pub fn new(client: ListenClient) -> Self {
        Self(client)
    }

    pub fn into_inner(self) -> ListenClient {
        self.0
    }
}

impl ListenClient {
    /// Convert into a [`RemoteListener`] that implements [`quic::Listen`].
    pub fn into_quic(self) -> RemoteListener {
        RemoteListener(self)
    }
}

impl From<ListenClient> for RemoteListener {
    fn from(client: ListenClient) -> Self {
        Self(client)
    }
}

impl From<RemoteListener> for ListenClient {
    fn from(remote: RemoteListener) -> Self {
        remote.0
    }
}

impl quic::Listen for RemoteListener {
    type Connection = RemoteConnection;
    type Error = ListenError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        let client = Listen::accept(&mut self.0).await?;
        Ok(Arc::new(RemoteConnection::from(client)))
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        Listen::shutdown(&self.0).await
    }
}
