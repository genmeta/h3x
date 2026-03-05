use futures::future::BoxFuture;

use crate::quic;

use super::{RemoteError, connection::{RemoteConnectionClient, RemoteConnectionWrapper}};

/// Remote trait for a QUIC listener, providing accept and shutdown operations
/// over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait RemoteListen: Send + Sync {
    /// Accept the next incoming connection.
    async fn accept(&self) -> Result<RemoteConnectionClient, RemoteError>;

    /// Shutdown the listener.
    ///
    /// The underlying `quic::Listen::shutdown()` returns `()`, but RTC requires
    /// `Result`. The server-side implementation calls `shutdown()` and returns `Ok(())`.
    async fn shutdown(&self) -> Result<(), RemoteError>;
}

/// Wrapper around [`RemoteListenClient`] that implements [`quic::Listen`].
pub struct RemoteListenWrapper {
    client: RemoteListenClient,
}

impl RemoteListenWrapper {
    /// Create a new wrapper from a remoc-generated listen client.
    pub fn new(client: RemoteListenClient) -> Self {
        Self { client }
    }
}

impl quic::Listen for RemoteListenWrapper {
    type Connection = RemoteConnectionWrapper;
    type Error = RemoteError;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        let client = self.client.clone();
        Box::pin(async move {
            let conn_client = client.accept().await?;
            Ok(RemoteConnectionWrapper::new(conn_client))
        })
    }

    fn shutdown(&self) {
        let client = self.client.clone();
        // Fire-and-forget: spawn a task to handle the async RPC.
        // The result is intentionally discarded since shutdown is fire-and-forget.
        tokio::spawn(async move {
            let _ = client.shutdown().await;
        });
    }
}
