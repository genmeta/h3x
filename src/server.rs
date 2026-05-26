//! Compatibility server wrapper over [`crate::endpoint::server`].

use std::{error::Error, sync::Arc};

use futures::future;
use snafu::Report;
use tokio::task::JoinSet;
use tracing::Instrument;

pub use crate::endpoint::server::{MessageStreamError, ReadStream, UnresolvedRequest, WriteStream};
use crate::{
    connection::ConnectionBuilder,
    error::Code,
    pool::Pool,
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

#[derive(Debug)]
pub struct Servers<L: quic::Listen, S> {
    pool: Pool<L::Connection>,
    listener: L,
    builder: Arc<ConnectionBuilder<L::Connection>>,
    service: S,
}

#[bon::bon]
impl<L, S> Servers<L, S>
where
    L: quic::Listen,
{
    #[builder(
        builder_type(vis = "pub"),
        start_fn(name = from_quic_listener, vis = "pub")
    )]
    fn new(
        #[builder(default = Pool::empty())] pool: Pool<L::Connection>,
        listener: L,
        service: S,
        #[builder(default = Arc::new(ConnectionBuilder::new(Arc::default())))] builder: Arc<
            ConnectionBuilder<L::Connection>,
        >,
    ) -> Self {
        Self {
            pool,
            listener,
            builder,
            service,
        }
    }

    pub fn quic_listener(&self) -> &L {
        &self.listener
    }

    pub fn quic_listener_mut(&mut self) -> &mut L {
        &mut self.listener
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut S {
        &mut self.service
    }

    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        Pool<L::Connection>,
        L,
        S,
        Arc<ConnectionBuilder<L::Connection>>,
    ) {
        (self.pool, self.listener, self.service, self.builder)
    }
}

impl<L, S> Servers<L, S>
where
    L: quic::Listen,
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    fn handle_incoming_connection(
        &self,
        connection: Arc<L::Connection>,
    ) -> impl futures::Future<Output = ()> + Send + 'static {
        let pool = self.pool.clone();
        let builder = self.builder.clone();
        let service = self.service.clone();
        let span = tracing::info_span!("handle_connection", server_name = tracing::field::Empty);
        async move {
            tracing::debug!("accepted new QUIC connection");
            let Ok(connection) = builder.build(connection).await else {
                return;
            };

            tracing::debug!("accepted new H3 connection");
            let Ok(local_agent) = connection.local_agent().await else {
                return;
            };
            let Some(local_agent) = local_agent else {
                tracing::debug!("close incoming connection due to missing SNI");
                connection.close(
                    Code::H3_INTERNAL_ERROR,
                    "missing server name (SNI) on incoming connection",
                );
                return;
            };

            tracing::Span::current().record("server_name", local_agent.name());
            let connection = Arc::new(connection);
            _ = pool.try_insert(connection.clone()).await;
            let mut connection_tasks = JoinSet::new();

            loop {
                let (mut read_stream, write_stream) = match connection.accept_message_stream().await
                {
                    Ok(pair) => {
                        tracing::trace!("accepted incoming request stream");
                        pair
                    }
                    Err(error) => {
                        tracing::debug!(
                            error = %Report::from_error(error),
                            "failed to accept incoming request"
                        );
                        break;
                    }
                };

                let stream_id = match read_stream.stream_id().await {
                    Ok(stream_id) => stream_id,
                    Err(error) => {
                        tracing::debug!(
                            error = %Report::from_error(error),
                            "failed to acquire incoming request stream ID"
                        );
                        continue;
                    }
                };

                let mut service = service.clone();
                let connection = connection.clone();
                let unresolved_request = UnresolvedRequest {
                    stream_id: StreamId(stream_id),
                    read_stream,
                    write_stream,
                    connection: Arc::new(connection.erase()),
                };

                let handle_request = async move {
                    if let Err(error) = future::poll_fn(|cx| service.poll_ready(cx)).await {
                        let error = error.into();
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "service not ready to handle incoming request"
                        );
                        return;
                    }

                    if let Err(error) = service.call(unresolved_request).await {
                        let error = error.into();
                        tracing::debug!(
                            stream_id = %stream_id,
                            error = %Report::from_error(error.as_ref()),
                            "failed to handle incoming request"
                        );
                    }
                };
                connection_tasks.spawn(handle_request.in_current_span());
                while connection_tasks.try_join_next().is_some() {}
            }
        }
        .instrument(span)
    }

    pub async fn run(&mut self) -> L::Error {
        let mut tasks = JoinSet::default();

        loop {
            while tasks.try_join_next().is_some() {}
            match self.listener.accept().await {
                Ok(connection) => tasks.spawn(self.handle_incoming_connection(connection)),
                Err(error) => break error,
            };
        }
    }

    pub async fn shutdown(&self) -> Result<(), L::Error> {
        self.listener.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::{Ready, pending, ready},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tower_service::Service;

    use super::*;
    use crate::{
        connection::tests::{TestLocalAgent, TestReadStream, TestRemoteAgent, TestWriteStream},
        quic,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestListenErrorKind {
        Exhausted,
        Injected,
    }

    impl TestListenErrorKind {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Exhausted => "exhausted",
                Self::Injected => "injected",
            }
        }
    }

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("test listener failed: {}", kind.as_str()))]
    struct TestListenError {
        kind: TestListenErrorKind,
    }

    #[derive(Debug)]
    enum AcceptAction {
        Connection(Arc<TestConnection>),
        Error(TestListenErrorKind),
    }

    #[derive(Debug, Default)]
    struct TestListener {
        actions: VecDeque<AcceptAction>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl TestListener {
        fn with_actions(actions: impl IntoIterator<Item = AcceptAction>) -> Self {
            Self {
                actions: actions.into_iter().collect(),
                shutdowns: Arc::default(),
            }
        }
    }

    impl quic::Listen for TestListener {
        type Connection = TestConnection;
        type Error = TestListenError;

        async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
            match self.actions.pop_front() {
                Some(AcceptAction::Connection(connection)) => Ok(connection),
                Some(AcceptAction::Error(kind)) => Err(TestListenError { kind }),
                None => Err(TestListenError {
                    kind: TestListenErrorKind::Exhausted,
                }),
            }
        }

        async fn shutdown(&self) -> Result<(), Self::Error> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct TestConnection {
        closes: AtomicUsize,
        close_reasons: Mutex<Vec<(Code, String)>>,
    }

    impl TestConnection {
        fn close_count(&self) -> usize {
            self.closes.load(Ordering::Relaxed)
        }

        fn has_close_reason(&self, expected: &str) -> bool {
            self.close_reasons
                .lock()
                .expect("close reason mutex should not be poisoned")
                .iter()
                .any(|(_, reason)| reason == expected)
        }
    }

    impl quic::ManageStream for TestConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(TestWriteStream)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAgent for TestConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for TestConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for TestConnection {
        fn close(&self, code: Code, reason: std::borrow::Cow<'static, str>) {
            self.closes.fetch_add(1, Ordering::Relaxed);
            self.close_reasons
                .lock()
                .expect("close reason mutex should not be poisoned")
                .push((code, reason.into_owned()));
        }

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("test service failed"))]
    struct TestServiceError;

    #[derive(Clone, Debug, Default)]
    struct TestService {
        calls: Arc<AtomicUsize>,
    }

    impl Service<UnresolvedRequest> for TestService {
        type Response = ();
        type Error = TestServiceError;
        type Future = Ready<Result<(), Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: UnresolvedRequest) -> Self::Future {
            self.calls.fetch_add(1, Ordering::Relaxed);
            ready(Ok(()))
        }
    }

    fn test_servers(
        listener: TestListener,
        service: TestService,
    ) -> Servers<TestListener, TestService> {
        Servers::from_quic_listener()
            .listener(listener)
            .service(service)
            .build()
    }

    #[test]
    fn builder_accessors_and_into_parts_preserve_components() {
        let listener = TestListener::default();
        let shutdowns = listener.shutdowns.clone();
        let service = TestService::default();
        let calls = service.calls.clone();
        let builder = Arc::new(ConnectionBuilder::new(Arc::default()));
        let servers = Servers::from_quic_listener()
            .listener(listener)
            .service(service)
            .builder(builder.clone())
            .build();

        assert!(Arc::ptr_eq(&builder, &servers.builder));
        assert!(Arc::ptr_eq(&shutdowns, &servers.quic_listener().shutdowns));
        assert!(Arc::ptr_eq(&calls, &servers.service().calls));

        let (_pool, listener, service, extracted_builder) = servers.into_parts();

        assert!(Arc::ptr_eq(&builder, &extracted_builder));
        assert!(Arc::ptr_eq(&shutdowns, &listener.shutdowns));
        assert!(Arc::ptr_eq(&calls, &service.calls));
    }

    #[tokio::test]
    async fn shutdown_delegates_to_quic_listener() {
        let listener = TestListener::default();
        let shutdowns = listener.shutdowns.clone();
        let servers = test_servers(listener, TestService::default());

        servers.shutdown().await.expect("shutdown should succeed");

        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn run_returns_listener_error() {
        let listener =
            TestListener::with_actions([AcceptAction::Error(TestListenErrorKind::Injected)]);
        let mut servers = test_servers(listener, TestService::default());

        let error = servers.run().await;

        assert_eq!(error.kind, TestListenErrorKind::Injected);
    }

    #[tokio::test]
    async fn run_accepts_connections_until_listener_error() {
        let listener = TestListener::with_actions([
            AcceptAction::Connection(Arc::new(TestConnection::default())),
            AcceptAction::Error(TestListenErrorKind::Injected),
        ]);
        let mut servers = test_servers(listener, TestService::default());

        let error = servers.run().await;

        assert_eq!(error.kind, TestListenErrorKind::Injected);
    }

    #[tokio::test]
    async fn handle_incoming_connection_closes_connection_without_sni() {
        let connection = Arc::new(TestConnection::default());
        let servers = test_servers(TestListener::default(), TestService::default());

        servers.handle_incoming_connection(connection.clone()).await;

        assert!(connection.close_count() >= 1);
        assert!(connection.has_close_reason("missing server name (SNI) on incoming connection"));
    }

    #[test]
    fn quic_listener_mut_and_service_mut_expose_components() {
        let mut servers = test_servers(TestListener::default(), TestService::default());

        servers
            .quic_listener_mut()
            .actions
            .push_back(AcceptAction::Error(TestListenErrorKind::Injected));
        servers.service_mut().calls.store(7, Ordering::Relaxed);

        assert_eq!(servers.quic_listener().actions.len(), 1);
        assert_eq!(servers.service().calls.load(Ordering::Relaxed), 7);
    }
}
