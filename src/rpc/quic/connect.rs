use std::sync::Arc;

use http::uri::Authority;
use remoc::prelude::ServerShared;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use tracing::Instrument;

use super::{
    connection::{ConnectionClient, ConnectionServerShared, RemoteConnection},
    serde_types::SerdeAuthority,
};
use crate::{quic, rpc::error::StringError};

#[derive(Debug, Snafu, Clone, Serialize, Deserialize)]
pub enum ConnectError {
    #[snafu(transparent)]
    Remote { source: StringError },
    #[snafu(transparent)]
    Call { source: remoc::rtc::CallError },
}

#[remoc::rtc::remote]
pub trait Connect: Send + Sync {
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError>;
}

// ---------------------------------------------------------------------------
// Server side: blanket — any quic::Connect implements the RTC trait
// ---------------------------------------------------------------------------

impl<C> Connect for C
where
    C: quic::Connect + 'static,
    <C::Connection as quic::WithLocalAgent>::LocalAgent: Send + Sync,
    <C::Connection as quic::WithRemoteAgent>::RemoteAgent: Send + Sync,
{
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError> {
        // lossy: cross-process serialization boundary
        let authority = Authority::try_from(server).map_err(|e| StringError::new(e.to_string()))?;
        let connection = quic::Connect::connect(self, &authority)
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
}

// ---------------------------------------------------------------------------
// Client side: RemoteConnector wraps ConnectClient → quic::Connect
// ---------------------------------------------------------------------------

/// A wrapper around [`ConnectClient`] that implements [`quic::Connect`].
///
/// Transparent serialization allows sending a `RemoteConnector` directly
/// across process boundaries without unwrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RemoteConnector(ConnectClient);

impl RemoteConnector {
    pub fn new(client: ConnectClient) -> Self {
        Self(client)
    }

    pub fn into_inner(self) -> ConnectClient {
        self.0
    }
}

impl ConnectClient {
    /// Convert into a [`RemoteConnector`] that implements [`quic::Connect`].
    pub fn into_quic(self) -> RemoteConnector {
        RemoteConnector(self)
    }
}

impl From<ConnectClient> for RemoteConnector {
    fn from(client: ConnectClient) -> Self {
        Self(client)
    }
}

impl From<RemoteConnector> for ConnectClient {
    fn from(remote: RemoteConnector) -> Self {
        remote.0
    }
}

impl quic::Connect for RemoteConnector {
    type Connection = RemoteConnection;
    type Error = ConnectError;

    async fn connect<'a>(
        &'a self,
        server: &'a Authority,
    ) -> Result<Arc<Self::Connection>, Self::Error> {
        let client = Connect::connect(&self.0, SerdeAuthority::from(server)).await?;
        Ok(Arc::new(RemoteConnection::from(client)))
    }
}
