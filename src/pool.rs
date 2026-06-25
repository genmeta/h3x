use std::{error::Error, pin::pin, sync::Arc};

use dashmap::DashMap;
use futures::{StreamExt, never::Never};
use http::uri::Authority;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    connection::{Connection, ConnectionBuilder},
    quic,
    util::watch::Watch,
};

#[derive(Debug)]
pub struct ReuseableConnection<C: quic::Connection> {
    connection: Watch<Arc<Connection<C>>>,
    task: AsyncMutex<Option<AbortOnDropHandle<()>>>,
}

type ConnectionIdentifier = Authority;
type ReuseableConnections<C> = DashMap<ConnectionIdentifier, Arc<ReuseableConnection<C>>>;

impl<C: quic::Connection> ReuseableConnection<C> {
    pub fn pending() -> Self {
        Self {
            connection: Watch::new(),
            task: AsyncMutex::new(None),
        }
    }

    pub fn peek(&self) -> Option<Arc<Connection<C>>> {
        self.connection.peek()
    }

    pub fn reuse(&self) -> Option<Arc<Connection<C>>> {
        let connection = self.peek()?;
        // proactively check if the QUIC connection is still alive
        if connection.check().is_err() {
            return None;
        }
        if connection.peek_peer_goaway().is_some() {
            return None;
        }
        Some(connection)
    }

    pub async fn insert(&self, connection: Arc<Connection<C>>, task: AbortOnDropHandle<()>) {
        self.insert_with(async || (connection, task)).await
    }

    pub async fn insert_with(
        &self,
        f: impl AsyncFnOnce() -> (Arc<Connection<C>>, AbortOnDropHandle<()>),
    ) {
        self.try_insert_with::<Never>(async || Ok(f().await))
            .await
            .ok();
    }

    pub async fn try_insert_with<E>(
        &self,
        f: impl AsyncFnOnce() -> Result<(Arc<Connection<C>>, AbortOnDropHandle<()>), E>,
    ) -> Result<(), E> {
        let mut task_guard = self.task.lock().await;
        let (connection, task) = f().await?;
        self.connection.set(connection);
        *task_guard = Some(task);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Pool<C: quic::Connection> {
    pub(crate) connections: Arc<ReuseableConnections<C>>,
}

impl<C: quic::Connection> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            connections: self.connections.clone(),
        }
    }
}

impl<C: quic::Connection> Pool<C> {
    pub fn empty() -> Self {
        Self {
            connections: Default::default(),
        }
    }

    /// Clear all cached connections from the pool.
    pub fn clear(&self) {
        self.connections.clear();
    }

    /// Return the number of cached connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Return `true` if the pool contains no connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

impl<C: quic::Connection> Default for Pool<C> {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ConnectError<E: Error + 'static> {
    #[snafu(display("failed to initialize QUIC connection"))]
    Connector { source: E },
    #[snafu(transparent)]
    H3 { source: quic::ConnectionError },
    #[snafu(display("peer name mismatch: expected {expected}, actual {}", match actual {
        Some(name) => name,
        None => "<anonymous>", 
    }))]
    IncorrectIdentity {
        expected: String,
        actual: Option<String>,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InsertError {
    #[snafu(transparent)]
    Quic { source: quic::ConnectionError },
    #[snafu(display("peer does not provide identity"))]
    MissingIdentity,
    #[snafu(display("peer provided invalid identity (cannot be parsed as Authority)"))]
    InvalidIdentity,
}

impl<C: quic::Connection> Pool<C> {
    fn spawn_try_release(self, identify: Authority) {
        tokio::spawn(
            async move {
                (self.connections.as_ref()).remove_if(&identify, |_, connection| {
                    // only drop the entry when no other waiter holds it; otherwise we would
                    // orphan the waiters and let a concurrent caller create a parallel entry
                    // at the same key, causing unbounded connection fission on persistent
                    // handshake failures.
                    Arc::strong_count(connection) == 1 && connection.reuse().is_none()
                });
            }
            .in_current_span(),
        );
    }

    #[tracing::instrument(level = "debug", skip(self, connector))]
    pub async fn reuse_or_connect_with<Client>(
        &self,
        connector: &Client,
        builder: Arc<ConnectionBuilder<C>>,
        server: Authority,
    ) -> Result<Arc<Connection<C>>, ConnectError<Client::Error>>
    where
        Client: quic::Connect<Connection = C>,
    {
        let reuseable_connection = self
            .connections
            .entry(server.clone())
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()))
            .clone();
        // break borrow of dashmap::Entry to avoid deadlock

        let result = {
            let mut connections = pin!(reuseable_connection.connection.watch());

            loop {
                tracing::trace!("(re)trying to reuse connection");
                if let Some(connection) = reuseable_connection.reuse() {
                    tracing::trace!("found reusable connection, gogogo");
                    break Ok(connection);
                }

                let try_connect = async || {
                    tracing::trace!("establishing quic connection for h3 pool entry");
                    let quic_conn = connector
                        .connect(&server)
                        .await
                        .context(connect_error::ConnectorSnafu)?;
                    tracing::trace!("quic connection established, building h3 connection");
                    let connection = builder.build(quic_conn).await?;

                    tracing::trace!("h3 connection established, verifying peer identity");
                    let authority = connection.remote_authority().await?;
                    let actual_peer_name = authority.as_ref().map(|authority| authority.name());
                    if actual_peer_name.as_ref() != Some(&server.host()) {
                        return connect_error::IncorrectIdentitySnafu {
                            expected: server.host().to_string(),
                            actual: actual_peer_name.map(ToOwned::to_owned),
                        }
                        .fail();
                    }

                    let connection = Arc::new(connection);
                    // its ok to replace the connection, reference of replaced connection still in task until closed
                    let task = AbortOnDropHandle::new(tokio::spawn({
                        let connection = connection.clone();
                        let pool = self.clone();
                        let server = server.clone();
                        async move {
                            connection.closed().await;
                            pool.spawn_try_release(server);
                        }
                        .in_current_span()
                    }));
                    Ok((connection, task))
                };

                tokio::select! {
                    biased;
                    _new_conn = connections.next() => {
                        tracing::trace!("entry updated, try to reuse connection");
                    }
                    result = reuseable_connection.try_insert_with(try_connect) => {
                        result?;
                        tracing::trace!("new connection inserted");
                    }
                }
            }
        };

        match &result {
            Ok(..) => tracing::trace!("connection ready to use"),
            Err(..) => self.clone().spawn_try_release(server),
        }

        result
    }

    pub async fn try_insert(&self, connection: Arc<Connection<C>>) -> Result<(), InsertError> {
        let authority = connection
            .remote_authority()
            .await?
            .context(insert_error::MissingIdentitySnafu)?;

        let client: Authority = authority
            .name()
            .parse()
            .ok()
            .context(insert_error::InvalidIdentitySnafu)?;

        let identity = client;
        let reuseable_connection = self
            .connections
            .entry(identity.clone())
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()))
            .clone();

        let pool = self.clone();
        reuseable_connection
            .insert(
                connection.clone(),
                AbortOnDropHandle::new(tokio::spawn(
                    async move {
                        connection.closed().await;
                        pool.spawn_try_release(identity);
                    }
                    .in_current_span(),
                )),
            )
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error as StdError,
        io,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use dhttp_identity::identity::RemoteAuthority;
    use http::uri::Authority;
    use tokio::sync::Semaphore;
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Level;

    use super::{ConnectError, InsertError, Pool, ReuseableConnection};
    use crate::{
        connection::{Connection, ConnectionBuilder, ConnectionState},
        dhttp::{
            goaway::Goaway,
            protocol::DHttpProtocol,
            settings::{Setting, Settings},
        },
        quic,
        varint::VarInt,
    };

    fn test_connection_error(reason: &str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn abort_handle() -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async {}))
    }

    #[derive(Clone)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("log buffer poisoned").extend(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn matching_server() -> Authority {
        "test-remote:443".parse().unwrap()
    }

    fn inserted_identity() -> Authority {
        "test-remote".parse().unwrap()
    }

    fn alternate_builder() -> Arc<ConnectionBuilder<crate::connection::tests::MockConnection>> {
        let mut settings = Settings::default();
        settings.set(Setting::new(VarInt::from_u32(0x21), VarInt::from_u32(0x07)));
        Arc::new(ConnectionBuilder::new(Arc::new(settings)))
    }

    fn mock_connection(
        quic: crate::connection::tests::MockConnection,
    ) -> Connection<crate::connection::tests::MockConnection> {
        Connection::from_state_for_test(ConnectionState::new_for_test(
            Arc::new(quic),
            Arc::new(crate::protocol::Protocols::new()),
        ))
    }

    fn mock_connection_with_dhttp(
        quic: crate::connection::tests::MockConnection,
    ) -> Connection<crate::connection::tests::MockConnection> {
        let mut protocols = crate::protocol::Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(Arc::new(quic.clone())));
        Connection::from_state_for_test(ConnectionState::new_for_test(
            Arc::new(quic),
            Arc::new(protocols),
        ))
    }

    async fn reusable_connection(
        connection: Connection<crate::connection::tests::MockConnection>,
    ) -> Arc<ReuseableConnection<crate::connection::tests::MockConnection>> {
        let reusable = Arc::new(ReuseableConnection::pending());
        reusable.insert(Arc::new(connection), abort_handle()).await;
        reusable
    }

    async fn wait_until(label: &str, f: impl Fn() -> bool) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !f() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    }

    #[derive(Debug, Clone)]
    struct TestConnector {
        state: Arc<TestConnectorState>,
    }

    #[derive(Debug)]
    struct TestConnectorState {
        calls: AtomicUsize,
        error_message: Option<&'static str>,
        returned_quics: Mutex<Vec<crate::connection::tests::MockConnection>>,
        gate_first_call: Option<Arc<Semaphore>>,
    }

    impl TestConnector {
        fn succeed() -> Self {
            Self {
                state: Arc::new(TestConnectorState {
                    calls: AtomicUsize::new(0),
                    error_message: None,
                    returned_quics: Mutex::new(Vec::new()),
                    gate_first_call: None,
                }),
            }
        }

        fn succeed_with_first_call_gate() -> (Self, Arc<Semaphore>) {
            let gate = Arc::new(Semaphore::new(0));
            (
                Self {
                    state: Arc::new(TestConnectorState {
                        calls: AtomicUsize::new(0),
                        error_message: None,
                        returned_quics: Mutex::new(Vec::new()),
                        gate_first_call: Some(gate.clone()),
                    }),
                },
                gate,
            )
        }

        fn fail(message: &'static str) -> Self {
            Self {
                state: Arc::new(TestConnectorState {
                    calls: AtomicUsize::new(0),
                    error_message: Some(message),
                    returned_quics: Mutex::new(Vec::new()),
                    gate_first_call: None,
                }),
            }
        }

        fn call_count(&self) -> usize {
            self.state.calls.load(Ordering::SeqCst)
        }

        fn returned_quics(&self) -> Vec<crate::connection::tests::MockConnection> {
            self.state
                .returned_quics
                .lock()
                .expect("returned quics log poisoned")
                .clone()
        }
    }

    impl quic::Connect for TestConnector {
        type Connection = crate::connection::tests::MockConnection;
        type Error = io::Error;

        async fn connect(&self, _server: &Authority) -> Result<Arc<Self::Connection>, Self::Error> {
            let call = self.state.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0
                && let Some(gate) = &self.state.gate_first_call
            {
                gate.acquire()
                    .await
                    .expect("gate should not be closed")
                    .forget();
            }
            if let Some(message) = self.state.error_message {
                return Err(io::Error::other(message));
            }

            let quic = crate::connection::tests::MockConnection::new();
            quic.enable_stream_ops();
            self.state
                .returned_quics
                .lock()
                .expect("returned quics log poisoned")
                .push(quic.clone());
            Ok(Arc::new(quic))
        }
    }

    #[derive(Debug)]
    struct NamedRemoteAuthority(&'static str);

    impl RemoteAuthority for NamedRemoteAuthority {
        fn name(&self) -> &str {
            self.0
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug, Clone)]
    struct IdentityOverrideConnection {
        inner: crate::connection::tests::MockConnection,
        remote_name: Option<&'static str>,
    }

    impl IdentityOverrideConnection {
        fn new(remote_name: Option<&'static str>) -> Self {
            Self {
                inner: crate::connection::tests::MockConnection::new(),
                remote_name,
            }
        }

        fn with_stream_ops(remote_name: Option<&'static str>) -> Self {
            let inner = crate::connection::tests::MockConnection::new();
            inner.enable_stream_ops();
            Self { inner, remote_name }
        }
    }

    impl quic::ManageStream for IdentityOverrideConnection {
        type StreamReader = crate::connection::tests::TestReadStream;
        type StreamWriter = crate::connection::tests::TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            quic::ManageStream::open_bi(&self.inner).await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            quic::ManageStream::open_uni(&self.inner).await
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            quic::ManageStream::accept_bi(&self.inner).await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            quic::ManageStream::accept_uni(&self.inner).await
        }
    }

    impl quic::WithLocalAuthority for IdentityOverrideConnection {
        type LocalAuthority = crate::connection::tests::TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(Some(crate::connection::tests::TestLocalAuthority))
        }
    }

    impl quic::WithRemoteAuthority for IdentityOverrideConnection {
        type RemoteAuthority = NamedRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
            Ok(self.remote_name.map(NamedRemoteAuthority))
        }
    }

    impl quic::Lifecycle for IdentityOverrideConnection {
        fn close(&self, code: crate::error::Code, reason: std::borrow::Cow<'static, str>) {
            quic::Lifecycle::close(&self.inner, code, reason);
        }

        fn check(&self) -> Result<(), quic::ConnectionError> {
            quic::Lifecycle::check(&self.inner)
        }

        async fn closed(&self) -> quic::ConnectionError {
            quic::Lifecycle::closed(&self.inner).await
        }
    }

    #[derive(Debug, Clone)]
    struct IdentityConnector {
        connection: IdentityOverrideConnection,
    }

    impl IdentityConnector {
        fn new(remote_name: Option<&'static str>) -> Self {
            Self {
                connection: IdentityOverrideConnection::with_stream_ops(remote_name),
            }
        }
    }

    impl quic::Connect for IdentityConnector {
        type Connection = IdentityOverrideConnection;
        type Error = io::Error;

        async fn connect(&self, _server: &Authority) -> Result<Arc<Self::Connection>, Self::Error> {
            Ok(Arc::new(self.connection.clone()))
        }
    }

    #[derive(Debug)]
    struct UnavailableStreamsConnector;

    impl quic::Connect for UnavailableStreamsConnector {
        type Connection = crate::connection::tests::MockConnection;
        type Error = io::Error;

        async fn connect(&self, _server: &Authority) -> Result<Arc<Self::Connection>, Self::Error> {
            Ok(Arc::new(crate::connection::tests::MockConnection::new()))
        }
    }

    #[test]
    fn reusable_connection_pending_starts_empty() {
        let reusable = ReuseableConnection::<crate::connection::tests::MockConnection>::pending();

        assert!(reusable.peek().is_none());
        assert!(reusable.reuse().is_none());
    }

    #[tokio::test]
    async fn reusable_connection_insert_with_publishes_connection() {
        let expected = Arc::new(mock_connection_with_dhttp(
            crate::connection::tests::MockConnection::new(),
        ));
        let reusable = ReuseableConnection::pending();

        reusable
            .insert_with(async || (expected.clone(), abort_handle()))
            .await;

        assert!(Arc::ptr_eq(
            &reusable.peek().expect("connection should be visible"),
            &expected,
        ));
        assert!(Arc::ptr_eq(
            &reusable.reuse().expect("connection should be reusable"),
            &expected,
        ));
    }

    #[tokio::test]
    async fn reusable_connection_try_insert_with_replaces_existing_connection() {
        let old = Arc::new(mock_connection_with_dhttp(
            crate::connection::tests::MockConnection::new(),
        ));
        let new = Arc::new(mock_connection_with_dhttp(
            crate::connection::tests::MockConnection::new(),
        ));
        let reusable = ReuseableConnection::pending();
        reusable.insert(old.clone(), abort_handle()).await;

        reusable
            .try_insert_with::<io::Error>(async || Ok((new.clone(), abort_handle())))
            .await
            .expect("replacement should succeed");

        let reused = reusable
            .reuse()
            .expect("replacement should become reusable");
        assert!(Arc::ptr_eq(&reused, &new));
        assert!(!Arc::ptr_eq(&reused, &old));
    }

    #[test]
    fn pool_default_clone_shares_entries_and_clear() {
        let pool = Pool::<crate::connection::tests::MockConnection>::default();
        assert!(pool.is_empty());

        let cloned = pool.clone();
        let auth: Authority = "example.com:443".parse().unwrap();
        cloned
            .connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.len(), 1);
        assert!(!cloned.is_empty());

        pool.clear();
        assert!(cloned.is_empty());
    }

    #[test]
    fn connect_error_display_and_sources_are_semantic() {
        let connector: ConnectError<io::Error> = ConnectError::Connector {
            source: io::Error::other("dial failed"),
        };
        assert_eq!(
            connector.to_string(),
            "failed to initialize QUIC connection"
        );
        assert_eq!(
            StdError::source(&connector)
                .expect("connector error should preserve source")
                .to_string(),
            "dial failed"
        );

        let anonymous: ConnectError<io::Error> = ConnectError::IncorrectIdentity {
            expected: "expected.example".to_owned(),
            actual: None,
        };
        assert_eq!(
            anonymous.to_string(),
            "peer name mismatch: expected expected.example, actual <anonymous>"
        );
        assert!(StdError::source(&anonymous).is_none());

        let named: ConnectError<io::Error> = ConnectError::IncorrectIdentity {
            expected: "expected.example".to_owned(),
            actual: Some("actual.example".to_owned()),
        };
        assert_eq!(
            named.to_string(),
            "peer name mismatch: expected expected.example, actual actual.example"
        );
        assert!(StdError::source(&named).is_none());

        let source = test_connection_error("h3 failed");
        let source_display = source.to_string();
        let h3: ConnectError<io::Error> = ConnectError::H3 { source };
        assert_eq!(h3.to_string(), source_display);
    }

    #[test]
    fn insert_error_display_and_sources_are_semantic() {
        let missing = InsertError::MissingIdentity;
        assert_eq!(missing.to_string(), "peer does not provide identity");
        assert!(StdError::source(&missing).is_none());

        let invalid = InsertError::InvalidIdentity;
        assert_eq!(
            invalid.to_string(),
            "peer provided invalid identity (cannot be parsed as Authority)"
        );
        assert!(StdError::source(&invalid).is_none());

        let source = test_connection_error("insert failed");
        let source_display = source.to_string();
        let quic = InsertError::Quic { source };
        assert_eq!(quic.to_string(), source_display);
    }

    #[test]
    fn test_pool_key_is_authority_only() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let auth: Authority = "example.com:443".parse().unwrap();

        pool.connections
            .entry(auth.clone())
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        assert_eq!(
            pool.connections.len(),
            1,
            "builder must not affect pool key; only authority matters",
        );
    }

    #[test]
    fn test_pool_key_different_authority_different_entry() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let auth1: Authority = "example.com:443".parse().unwrap();
        let auth2: Authority = "other.com:443".parse().unwrap();

        pool.connections
            .entry(auth1)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth2)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        assert_eq!(
            pool.connections.len(),
            2,
            "different authorities must produce different pool entries",
        );
    }

    #[test]
    fn test_pool_key_plain_and_selector_authority_different_entry() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let auth_plain: Authority = "example.com".parse().unwrap();
        let auth_selected: Authority = "example.com:0".parse().unwrap();

        pool.connections
            .entry(auth_plain)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth_selected)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.connections.len(), 2);
    }

    #[test]
    fn test_pool_key_different_selector_authorities_different_entry() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let auth0: Authority = "example.com:0".parse().unwrap();
        let auth1: Authority = "example.com:1".parse().unwrap();

        pool.connections
            .entry(auth0)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth1)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.connections.len(), 2);
    }

    #[tokio::test]
    async fn reuse_returns_none_when_connection_is_unhealthy() {
        let quic = crate::connection::tests::MockConnection::new();
        quic.set_terminal_error(test_connection_error("broken"));

        let state = ConnectionState::new_for_test(
            Arc::new(quic),
            Arc::new(crate::protocol::Protocols::new()),
        );
        let reusable = reusable_connection(Connection::from_state_for_test(state)).await;

        assert!(reusable.reuse().is_none());
    }

    #[tokio::test]
    async fn pool_reuse_returns_none_after_peer_goaway_observed() {
        let quic = crate::connection::tests::MockConnection::new();

        let protocols = {
            let mut protocols = crate::protocol::Protocols::new();
            protocols.insert(DHttpProtocol::new_for_test(Arc::new(quic.clone())));
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(quic), protocols);
        let dhttp = state.dhttp();
        dhttp.peer_goaway.set(Goaway::new(VarInt::from_u32(123)));

        let reusable = reusable_connection(Connection::from_state_for_test(state)).await;
        assert!(reusable.reuse().is_none());
    }

    #[tokio::test]
    async fn reusable_connection_try_insert_with_error_preserves_existing_connection() {
        #[derive(Debug, PartialEq, Eq)]
        struct TestInsertFailure;

        let quic = crate::connection::tests::MockConnection::new();
        let expected = Arc::new(mock_connection_with_dhttp(quic));
        let reusable = Arc::new(ReuseableConnection::pending());

        reusable.insert(expected.clone(), abort_handle()).await;

        let error = reusable
            .try_insert_with(async || {
                Err::<
                    (
                        Arc<Connection<crate::connection::tests::MockConnection>>,
                        AbortOnDropHandle<()>,
                    ),
                    _,
                >(TestInsertFailure)
            })
            .await
            .expect_err("insertion should fail");

        assert_eq!(error, TestInsertFailure);
        assert!(Arc::ptr_eq(
            &reusable
                .reuse()
                .expect("existing connection should remain reusable"),
            &expected,
        ));
    }

    #[tokio::test]
    async fn pool_reuses_same_authority_even_with_different_builders() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connector = TestConnector::succeed();
        let server = matching_server();

        let first = pool
            .reuse_or_connect_with(
                &connector,
                Arc::new(ConnectionBuilder::default()),
                server.clone(),
            )
            .await
            .expect("first connect should succeed");
        let second = pool
            .reuse_or_connect_with(&connector, alternate_builder(), server)
            .await
            .expect("second connect should reuse");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(connector.call_count(), 1);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn pool_coordinates_in_flight_connect_attempts() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let (connector, first_call_gate) = TestConnector::succeed_with_first_call_gate();
        let server = matching_server();
        let builder = Arc::new(ConnectionBuilder::default());
        let first = pool.reuse_or_connect_with(&connector, builder.clone(), server.clone());
        let mut first = std::pin::pin!(first);
        assert!(
            futures::poll!(first.as_mut()).is_pending(),
            "gated first connect should remain pending until released",
        );
        assert_eq!(
            connector.call_count(),
            1,
            "first poll should start one dial"
        );
        assert_eq!(
            pool.len(),
            1,
            "pending entry should exist while first call is gated"
        );

        let second = pool.reuse_or_connect_with(&connector, builder, server.clone());
        let mut second = std::pin::pin!(second);
        assert!(
            futures::poll!(second.as_mut()).is_pending(),
            "second caller should pend while the first connection attempt is in flight",
        );

        wait_until("second waiter to attach to the same pending entry", || {
            let Some(entry) = pool.connections.get(&server) else {
                return false;
            };
            Arc::strong_count(entry.value()) >= 3
        })
        .await;

        assert_eq!(
            connector.call_count(),
            1,
            "second in-flight caller should wait on the pending entry instead of dialing again",
        );

        first_call_gate.add_permits(1);

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let (first, second) = loop {
            let first_poll = futures::poll!(first.as_mut());
            let second_poll = futures::poll!(second.as_mut());

            match (first_poll, second_poll) {
                (std::task::Poll::Ready(first), std::task::Poll::Ready(second)) => {
                    break (
                        first.expect("first connect should succeed"),
                        second.expect("second waiter should reuse the same connection"),
                    );
                }
                (std::task::Poll::Ready(_), std::task::Poll::Pending)
                    if std::time::Instant::now() >= deadline =>
                {
                    panic!("second in-flight waiter stalled after the first connection completed");
                }
                (std::task::Poll::Pending, _) if std::time::Instant::now() >= deadline => {
                    panic!("first in-flight connection attempt stalled before becoming reusable");
                }
                _ => tokio::task::yield_now().await,
            }
        };

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(connector.call_count(), 1);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn pool_returns_connector_error() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connector = TestConnector::fail("dial failed");
        let error = pool
            .reuse_or_connect_with(
                &connector,
                Arc::new(ConnectionBuilder::default()),
                matching_server(),
            )
            .await
            .expect_err("connect should fail");

        match error {
            ConnectError::Connector { source } => {
                assert_eq!(source.to_string(), "dial failed");
            }
            other => panic!("expected connector error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pool_rejects_incorrect_peer_identity() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connector = TestConnector::succeed();
        let server: Authority = "expected.example:443".parse().unwrap();

        let error = pool
            .reuse_or_connect_with(&connector, Arc::new(ConnectionBuilder::default()), server)
            .await
            .expect_err("identity mismatch should fail");

        match error {
            ConnectError::IncorrectIdentity { expected, actual } => {
                assert_eq!(expected, "expected.example");
                assert_eq!(actual.as_deref(), Some("test-remote"));
            }
            other => panic!("expected identity error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pool_rejects_anonymous_peer_identity() {
        let pool = Pool::<IdentityOverrideConnection>::empty();
        let connector = IdentityConnector::new(None);
        let server = matching_server();

        let error = pool
            .reuse_or_connect_with(&connector, Arc::new(ConnectionBuilder::default()), server)
            .await
            .expect_err("anonymous peer should fail identity verification");

        match error {
            ConnectError::IncorrectIdentity { expected, actual } => {
                assert_eq!(expected, "test-remote");
                assert!(actual.is_none());
            }
            other => panic!("expected identity error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pool_accepts_matching_identity_override_connection() {
        let pool = Pool::<IdentityOverrideConnection>::empty();
        let connector = IdentityConnector::new(Some("test-remote"));
        let server = matching_server();

        let connection = pool
            .reuse_or_connect_with(
                &connector,
                Arc::new(ConnectionBuilder::default()),
                server.clone(),
            )
            .await
            .expect("matching peer identity should connect");

        let reused = pool
            .reuse_or_connect_with(&connector, Arc::new(ConnectionBuilder::default()), server)
            .await
            .expect("matching peer identity should reuse");

        assert!(Arc::ptr_eq(&connection, &reused));
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn identity_override_connection_delegates_quic_capabilities() {
        let connection = IdentityOverrideConnection::with_stream_ops(Some("delegated.example"));

        quic::ManageStream::open_bi(&connection)
            .await
            .expect("open_bi should delegate to inner connection");
        quic::ManageStream::open_uni(&connection)
            .await
            .expect("open_uni should delegate to inner connection");
        quic::ManageStream::accept_bi(&connection)
            .await
            .expect("accept_bi should delegate to inner connection");
        quic::ManageStream::accept_uni(&connection)
            .await
            .expect("accept_uni should delegate to inner connection");

        let local = quic::WithLocalAuthority::local_authority(&connection)
            .await
            .expect("local authority lookup should succeed");
        assert!(local.is_some());

        let remote = quic::WithRemoteAuthority::remote_authority(&connection)
            .await
            .expect("remote authority lookup should succeed")
            .expect("remote authority should be present");
        assert_eq!(remote.name(), "delegated.example");
        assert!(remote.cert_chain().is_empty());

        assert!(quic::Lifecycle::check(&connection).is_ok());
        quic::Lifecycle::close(
            &connection,
            crate::error::Code::H3_NO_ERROR,
            "delegated close".into(),
        );
        assert_eq!(
            connection.inner.close_calls(),
            vec![(
                crate::error::Code::H3_NO_ERROR,
                "delegated close".to_owned()
            )],
        );

        connection
            .inner
            .set_terminal_error(test_connection_error("delegated terminal"));
        let closed = quic::Lifecycle::closed(&connection).await;
        assert!(closed.to_string().contains("delegated terminal"));
        assert_eq!(
            connection.inner.stream_calls(),
            vec!["open_bi", "open_uni", "accept_bi", "accept_uni"],
        );
    }

    #[tokio::test]
    async fn pool_returns_h3_error_when_connection_initialization_fails() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();

        let error = pool
            .reuse_or_connect_with(
                &UnavailableStreamsConnector,
                Arc::new(ConnectionBuilder::default()),
                matching_server(),
            )
            .await
            .expect_err("builder should fail when stream operations are unavailable");

        assert!(matches!(error, ConnectError::H3 { .. }));
    }

    #[tokio::test]
    async fn pool_replaces_closed_connection_with_new_one() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connector = TestConnector::succeed();
        let server = matching_server();
        let builder = Arc::new(ConnectionBuilder::default());

        let first = pool
            .reuse_or_connect_with(&connector, builder.clone(), server.clone())
            .await
            .expect("first connect should succeed");
        let first_quic = connector
            .returned_quics()
            .into_iter()
            .next()
            .expect("first connection should be recorded");
        first_quic.set_terminal_error(test_connection_error("closed"));

        let second = pool
            .reuse_or_connect_with(&connector, builder, server)
            .await
            .expect("second connect should replace the dead connection");

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(connector.call_count(), 2);
        assert_eq!(pool.len(), 1);
    }

    #[tokio::test]
    async fn try_insert_makes_connection_reusable_under_remote_identity() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connection = Arc::new(mock_connection_with_dhttp(
            crate::connection::tests::MockConnection::new(),
        ));

        pool.try_insert(connection.clone())
            .await
            .expect("insert should succeed");

        let reusable = pool
            .connections
            .get(&inserted_identity())
            .expect("entry should be keyed by remote identity");
        assert!(Arc::ptr_eq(
            &reusable.reuse().expect("connection should be reusable"),
            &connection,
        ));
    }

    #[tokio::test]
    async fn clear_drops_cached_connection_and_aborts_release_task() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let quic = crate::connection::tests::MockConnection::new();

        pool.try_insert(Arc::new(mock_connection_with_dhttp(quic.clone())))
            .await
            .expect("insert should succeed");

        pool.clear();

        wait_until("cached connection drop after clear", || {
            !quic.close_calls().is_empty()
        })
        .await;
        assert!(pool.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pool_error_path_does_not_emit_automatic_instrument_error_event() {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(Level::DEBUG)
            .with_writer({
                let captured = Arc::clone(&captured);
                move || SharedWriter(Arc::clone(&captured))
            })
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let connector = TestConnector::fail("dial failed");
        let error = pool
            .reuse_or_connect_with(
                &connector,
                Arc::new(ConnectionBuilder::default()),
                matching_server(),
            )
            .await
            .expect_err("connector should fail");

        assert!(matches!(error, ConnectError::Connector { .. }));

        let output = String::from_utf8(captured.lock().expect("log buffer poisoned").clone())
            .expect("log output must be valid UTF-8");
        assert!(
            !output.contains("ERROR"),
            "unexpected automatic error event: {output}",
        );
    }

    #[tokio::test]
    async fn connect_attempt_drop_releases_entry_closed_during_attempt() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let server = matching_server();
        let builder = Arc::new(ConnectionBuilder::default());
        let first_quic = crate::connection::tests::MockConnection::new();
        let first = Arc::new(mock_connection_with_dhttp(first_quic.clone()));
        let reusable = Arc::new(ReuseableConnection::pending());

        reusable.insert(first.clone(), abort_handle()).await;
        pool.connections.insert(server.clone(), reusable);

        // Force the next caller down the connect-attempt path while the old
        // connection is still present in the entry. This models an active
        // replacement attempt holding the same ReuseableConnection entry.
        first
            .dhttp()
            .peer_goaway
            .set(Goaway::new(VarInt::from_u32(1)));

        let (replacement_connector, replacement_gate) =
            TestConnector::succeed_with_first_call_gate();
        let replacement =
            pool.reuse_or_connect_with(&replacement_connector, builder, server.clone());
        let mut replacement = std::pin::pin!(replacement);

        assert!(
            futures::poll!(replacement.as_mut()).is_pending(),
            "replacement connect should be gated while holding the pool entry",
        );
        assert_eq!(
            replacement_connector.call_count(),
            1,
            "replacement attempt should have started one dial",
        );

        wait_until("replacement attempt to hold the existing entry", || {
            let Some(entry) = pool.connections.get(&server) else {
                return false;
            };
            Arc::strong_count(entry.value()) >= 2
        })
        .await;

        first_quic.set_terminal_error(test_connection_error("closed during replacement"));

        // Deterministically model the close watcher trying to release while the
        // replacement connect attempt still holds the entry. The release must
        // not remove the entry yet, otherwise a later caller could create a
        // parallel same-authority entry.
        pool.clone().spawn_try_release(server.clone());
        tokio::task::yield_now().await;

        assert_eq!(
            pool.len(),
            1,
            "active replacement attempt must keep the stale entry serialized",
        );

        drop(replacement);
        drop(replacement_gate);

        wait_until("stale entry release after replacement attempt drop", || {
            pool.is_empty()
        })
        .await;
    }

    #[tokio::test]
    async fn spawn_try_release_waits_until_no_other_waiter_holds_entry() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let quic = crate::connection::tests::MockConnection::new();
        let connection = Arc::new(mock_connection(quic.clone()));
        let server = inserted_identity();

        pool.try_insert(connection)
            .await
            .expect("insert should succeed");
        let reusable = pool
            .connections
            .get(&server)
            .expect("entry should exist")
            .value()
            .clone();

        quic.set_terminal_error(test_connection_error("release"));
        pool.clone().spawn_try_release(server.clone());
        tokio::task::yield_now().await;

        assert_eq!(pool.len(), 1, "held waiter must keep the entry alive");

        drop(reusable);
        pool.clone().spawn_try_release(server);
        wait_until("entry release after waiter drop", || pool.is_empty()).await;
    }

    #[tokio::test]
    async fn try_insert_releases_entry_after_connection_closes() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        let quic = crate::connection::tests::MockConnection::new();

        pool.try_insert(Arc::new(mock_connection(quic.clone())))
            .await
            .expect("insert should succeed");

        assert_eq!(pool.len(), 1);

        quic.set_terminal_error(test_connection_error("closed after insert"));
        wait_until("entry release after inserted connection closes", || {
            pool.is_empty()
        })
        .await;
    }

    #[tokio::test]
    async fn try_insert_rejects_missing_identity() {
        let pool = Pool::<IdentityOverrideConnection>::empty();
        let connection = Arc::new(Connection::from_state_for_test(
            ConnectionState::new_for_test(
                Arc::new(IdentityOverrideConnection::new(None)),
                Arc::new(crate::protocol::Protocols::new()),
            ),
        ));

        let error = pool
            .try_insert(connection)
            .await
            .expect_err("missing identity should fail");

        assert!(matches!(error, InsertError::MissingIdentity));
        assert!(pool.is_empty());
    }

    #[tokio::test]
    async fn try_insert_rejects_invalid_identity() {
        let pool = Pool::<IdentityOverrideConnection>::empty();
        let connection = Arc::new(Connection::from_state_for_test(
            ConnectionState::new_for_test(
                Arc::new(IdentityOverrideConnection::new(Some(
                    "not a valid authority",
                ))),
                Arc::new(crate::protocol::Protocols::new()),
            ),
        ));

        let error = pool
            .try_insert(connection)
            .await
            .expect_err("invalid identity should fail");

        assert!(matches!(error, InsertError::InvalidIdentity));
        assert!(pool.is_empty());
    }

    #[test]
    fn test_pool_len_empty() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_clear_empty() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();
        pool.clear();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_clear_with_entries() {
        let pool = Pool::<crate::connection::tests::MockConnection>::empty();

        let auth1: Authority = "example.com:443".parse().unwrap();
        let auth2: Authority = "other.com:443".parse().unwrap();
        let auth3: Authority = "test.net:443".parse().unwrap();

        pool.connections
            .entry(auth1)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth2)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));
        pool.connections
            .entry(auth3)
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()));

        assert_eq!(pool.len(), 3, "should have 3 entries before clear");

        pool.clear();
        assert_eq!(pool.len(), 0, "should have 0 entries after clear");
    }
}
