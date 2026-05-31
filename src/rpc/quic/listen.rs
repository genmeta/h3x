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
    <L::Connection as quic::WithLocalAuthority>::LocalAuthority: Send + Sync,
    <L::Connection as quic::WithRemoteAuthority>::RemoteAuthority: Send + Sync,
{
    async fn accept(&mut self) -> Result<ConnectionClient, ListenError> {
        // lossy: cross-process serialization boundary
        let connection = quic::Listen::accept(self)
            .await
            .map_err(|e| StringError::new(e.to_string()))?;
        let (server, client) = ConnectionServerShared::new(connection, 1);
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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use remoc::prelude::Server;
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::connection::tests::MockConnection;

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("test listener failed"))]
    struct TestListenError;

    #[derive(Debug, Default)]
    struct TestListenState {
        connections: Mutex<VecDeque<Arc<MockConnection>>>,
        accepts: AtomicUsize,
        shutdowns: AtomicUsize,
    }

    #[derive(Debug, Default)]
    struct TestListener {
        state: Arc<TestListenState>,
    }

    impl TestListener {
        fn with_connections(connections: impl IntoIterator<Item = Arc<MockConnection>>) -> Self {
            Self {
                state: Arc::new(TestListenState {
                    connections: Mutex::new(connections.into_iter().collect()),
                    accepts: AtomicUsize::default(),
                    shutdowns: AtomicUsize::default(),
                }),
            }
        }
    }

    impl quic::Listen for TestListener {
        type Connection = MockConnection;
        type Error = TestListenError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            self.state.accepts.fetch_add(1, Ordering::Relaxed);
            self.state
                .connections
                .lock()
                .expect("connection queue mutex should not be poisoned")
                .pop_front()
                .ok_or(TestListenError)
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            self.state.shutdowns.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn blanket_accept_returns_connection_client() {
        let mut listener = TestListener::with_connections([Arc::new(MockConnection::new())]);
        let state = listener.state.clone();

        let client = Listen::accept(&mut listener)
            .await
            .expect("blanket accept should return a remote connection client");

        assert_eq!(state.accepts.load(Ordering::Relaxed), 1);

        let remote = RemoteConnection::from(client);
        assert!(quic::Lifecycle::check(&remote).is_ok());
    }

    #[tokio::test]
    async fn blanket_accept_stringifies_transport_errors() {
        let mut listener = TestListener::default();

        let error = Listen::accept(&mut listener)
            .await
            .expect_err("empty listener should fail");

        let ListenError::Remote { source } = error else {
            panic!("listener error should cross RPC boundary as remote error");
        };
        assert_eq!(source.as_str(), "test listener failed");
    }

    #[tokio::test]
    async fn blanket_shutdown_delegates_to_quic_listener() {
        let listener = TestListener::default();
        let state = listener.state.clone();

        Listen::shutdown(&listener)
            .await
            .expect("blanket shutdown should succeed");

        assert_eq!(state.shutdowns.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn remote_listener_delegates_to_listen_client() {
        let listener = TestListener::with_connections([Arc::new(MockConnection::new())]);
        let state = listener.state.clone();
        let (server, client) = ListenServer::new(listener, 1);
        let _server_task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let (_listener, _result) = server.serve().await;
            }
            .in_current_span(),
        ));
        let mut remote = RemoteListener::new(client);

        let connection = quic::Listen::accept(&mut remote)
            .await
            .expect("remote listener should accept through RTC");
        quic::Listen::shutdown(&remote)
            .await
            .expect("remote listener should shut down through RTC");

        assert_eq!(state.accepts.load(Ordering::Relaxed), 1);
        assert_eq!(state.shutdowns.load(Ordering::Relaxed), 1);
        assert!(quic::Lifecycle::check(connection.as_ref()).is_ok());
    }

    #[tokio::test]
    async fn remote_listener_conversions_preserve_client_handle() {
        let listener = TestListener::default();
        let (server, client) = ListenServer::new(listener, 1);
        let _server_task_a = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let (_listener, _result) = server.serve().await;
            }
            .in_current_span(),
        ));

        let remote = RemoteListener::new(client);
        let inner = remote.into_inner();
        let remote = RemoteListener::from(inner);
        let _inner = ListenClient::from(remote);

        let listener = TestListener::default();
        let (server, client) = ListenServer::new(listener, 1);
        let _server_task_b = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let (_listener, _result) = server.serve().await;
            }
            .in_current_span(),
        ));

        let remote = ListenClient::into_quic(client);
        let inner: ListenClient = remote.into();
        let remote = RemoteListener::from(inner);
        let _inner = ListenClient::from(remote);
    }
}
