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
    <C::Connection as quic::WithLocalAuthority>::LocalAuthority: Send + Sync,
    <C::Connection as quic::WithRemoteAuthority>::RemoteAuthority: Send + Sync,
{
    async fn connect(&self, server: SerdeAuthority) -> Result<ConnectionClient, ConnectError> {
        // lossy: cross-process serialization boundary
        let authority = Authority::try_from(server).map_err(|e| StringError::new(e.to_string()))?;
        let connection = quic::Connect::connect(self, &authority)
            .await
            .map_err(|e| StringError::new(e.to_string()))?;
        let (server, client) = ConnectionServerShared::new(connection, 1);
        // Inherent termination: the returned ConnectionClient owns the remoc
        // endpoint; when that client is dropped or the channel closes,
        // server.serve exits.
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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use remoc::prelude::ServerShared;
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::connection::tests::MockConnection;

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("test connector failed"))]
    struct TestConnectError;

    #[derive(Debug, Default)]
    struct TestConnector {
        connections: Mutex<VecDeque<Arc<MockConnection>>>,
        calls: AtomicUsize,
        last_server: Mutex<Option<Authority>>,
    }

    impl TestConnector {
        fn with_connections(connections: impl IntoIterator<Item = Arc<MockConnection>>) -> Self {
            Self {
                connections: Mutex::new(connections.into_iter().collect()),
                calls: AtomicUsize::default(),
                last_server: Mutex::default(),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn last_server(&self) -> Option<Authority> {
            self.last_server
                .lock()
                .expect("last server mutex should not be poisoned")
                .clone()
        }
    }

    impl quic::Connect for TestConnector {
        type Connection = MockConnection;
        type Error = TestConnectError;

        async fn connect<'a>(
            &'a self,
            server: &'a Authority,
        ) -> Result<Arc<Self::Connection>, Self::Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            *self
                .last_server
                .lock()
                .expect("last server mutex should not be poisoned") = Some(server.clone());
            self.connections
                .lock()
                .expect("connection queue mutex should not be poisoned")
                .pop_front()
                .ok_or(TestConnectError)
        }
    }

    #[tokio::test]
    async fn blanket_connect_returns_connection_client() {
        let authority = Authority::from_static("example.test:443");
        let connector = TestConnector::with_connections([Arc::new(MockConnection::new())]);

        let client = Connect::connect(&connector, SerdeAuthority::from(&authority))
            .await
            .expect("blanket connect should return a remote connection client");

        assert_eq!(connector.call_count(), 1);
        assert_eq!(connector.last_server(), Some(authority));

        let remote = RemoteConnection::from(client);
        assert!(quic::Lifecycle::check(&remote).is_ok());
    }

    #[tokio::test]
    async fn blanket_connect_stringifies_transport_errors() {
        let authority = Authority::from_static("example.test:443");
        let connector = TestConnector::default();

        let error = Connect::connect(&connector, SerdeAuthority::from(&authority))
            .await
            .expect_err("empty connector should fail");

        let ConnectError::Remote { source } = error else {
            panic!("connector error should cross RPC boundary as remote error");
        };
        assert_eq!(source.as_str(), "test connector failed");
    }

    #[tokio::test]
    async fn remote_connector_delegates_to_connect_client() {
        let authority = Authority::from_static("example.test:443");
        let connector = Arc::new(TestConnector::with_connections([Arc::new(
            MockConnection::new(),
        )]));
        let (server, client) = ConnectServerShared::new(connector.clone(), 1);
        let _server_task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        let remote = RemoteConnector::new(client);

        let connection = quic::Connect::connect(&remote, &authority)
            .await
            .expect("remote connector should connect through RTC");

        assert_eq!(connector.call_count(), 1);
        assert!(quic::Lifecycle::check(connection.as_ref()).is_ok());
    }

    #[tokio::test]
    async fn remote_connector_conversions_preserve_client_handle() {
        let connector = Arc::new(TestConnector::default());
        let (server, client) = ConnectServerShared::new(connector, 1);
        let _server_task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));

        let remote = RemoteConnector::new(client.clone());
        let inner = remote.into_inner();
        let remote = ConnectClient::into_quic(inner.clone());
        let inner: ConnectClient = remote.into();
        let remote = RemoteConnector::from(inner);
        let _inner = ConnectClient::from(remote);
    }
}
