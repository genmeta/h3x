use futures::future::BoxFuture;
use snafu::Snafu;

use super::{
    connection::{ConnectionClient, RemoteQuicConnection},
    error::StringError,
    serde_types::SerdeAuthority,
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
pub struct RemoteQuicClient {
    client: RemoteConnectClient,
}

impl RemoteQuicClient {
    /// Create a new wrapper from a remoc-generated connect client.
    pub fn new(client: RemoteConnectClient) -> Self {
        Self { client }
    }
}

impl quic::Connect for RemoteQuicClient {
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
