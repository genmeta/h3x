use futures::future::BoxFuture;

use crate::quic;

use super::{RemoteError, SerdeAuthority, connection::{RemoteConnectionClient, RemoteConnectionWrapper}};

/// Remote trait for a QUIC connector that creates connections over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait RemoteConnect: Send + Sync {
    /// Connect to a remote server identified by the given authority.
    async fn connect(&self, server: SerdeAuthority) -> Result<RemoteConnectionClient, RemoteError>;
}

/// Wrapper around [`RemoteConnectClient`] that implements [`quic::Connect`],
/// allowing remote connections to be used wherever a local QUIC connector is expected.
pub struct RemoteConnectWrapper {
    client: RemoteConnectClient,
}

impl RemoteConnectWrapper {
    /// Create a new wrapper from a remoc-generated connect client.
    pub fn new(client: RemoteConnectClient) -> Self {
        Self { client }
    }
}

impl quic::Connect for RemoteConnectWrapper {
    type Connection = RemoteConnectionWrapper;
    type Error = RemoteError;

    fn connect<'a>(
        &'a self,
        server: &'a http::uri::Authority,
    ) -> BoxFuture<'a, Result<Self::Connection, Self::Error>> {
        let serde_server = SerdeAuthority::from(server);
        let client = self.client.clone();
        Box::pin(async move {
            let conn_client = client.connect(serde_server).await?;
            Ok(RemoteConnectionWrapper::new(conn_client))
        })
    }
}
