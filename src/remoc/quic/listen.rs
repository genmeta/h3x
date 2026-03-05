use futures::future::BoxFuture;
use snafu::Snafu;

use super::{
    connection::{ConnectionClient, RemoteQuicConnection},
    error::StringError,
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
pub struct RemoteQuicClient {
    client: ListenClient,
}

impl RemoteQuicClient {
    /// Create a new wrapper from a remoc-generated listen client.
    pub fn new(client: ListenClient) -> Self {
        Self { client }
    }
}

impl quic::Listen for RemoteQuicClient {
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
