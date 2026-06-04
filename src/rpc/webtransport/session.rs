//! RPC-forwarded WebTransport session.
//!
//! Follows the same pattern as [`super::super::quic::connection`]: a
//! `#[remoc::rtc::remote]` trait provides the wire protocol, a blanket-free
//! server impl delegates to [`WebTransportSession`], and [`RemoteWebTransportSession`]
//! wraps the generated client to present a convenient async API.

use std::sync::Arc;

use remoc::{prelude::Server, rtc::Client as RemocClient};
use tracing::Instrument;

use super::{
    super::{
        lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt as ConnectionLifecycleExt},
        quic::{ReadStreamClient, ReadStreamServer, WriteStreamClient, WriteStreamServer},
    },
    LifecycleExt,
};
use crate::{
    message::stream::guard,
    quic::{self, ConnectionError, DynLifecycle},
    stream_id::StreamId,
    varint::VarInt,
    webtransport::{self, AcceptStreamError, OpenStreamError},
};

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`WebTransportSession`].
///
/// Uses the native [`OpenStreamError`] and [`AcceptStreamError`] error types
/// directly — both are serializable. The `session_id` is not included because
/// it is immutable and can be passed out-of-band at construction time.
#[remoc::rtc::remote]
pub trait WebTransportRpcSession: Send + Sync {
    async fn open_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), OpenStreamError>;
    async fn open_uni(&self) -> Result<WriteStreamClient, OpenStreamError>;
    async fn accept_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), AcceptStreamError>;
    async fn accept_uni(&self) -> Result<ReadStreamClient, AcceptStreamError>;
}

// ---------------------------------------------------------------------------
// Server: impl WebTransportRpcSession for WebTransportSession
// ---------------------------------------------------------------------------

impl WebTransportRpcSession for webtransport::WebTransportSession {
    async fn open_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), OpenStreamError> {
        let (reader, writer) = webtransport::WebTransportSession::open_bi(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn open_uni(&self) -> Result<WriteStreamClient, OpenStreamError> {
        let writer = webtransport::WebTransportSession::open_uni(self).await?;
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok(wc)
    }

    async fn accept_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), AcceptStreamError> {
        let (reader, writer) = webtransport::WebTransportSession::accept_bi(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn accept_uni(&self) -> Result<ReadStreamClient, AcceptStreamError> {
        let reader = webtransport::WebTransportSession::accept_uni(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        // Inherent termination: the returned stream client owns the remoc
        // endpoint; when the client is dropped or the channel closes,
        // server.serve exits.
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        Ok(rc)
    }
}

// ---------------------------------------------------------------------------
// Client: RemoteWebTransportSession wraps WebTransportRpcSessionClient
// ---------------------------------------------------------------------------

/// A wrapper around [`WebTransportRpcSessionClient`] that converts RPC stream clients back
/// into boxed async streams.
///
/// This is the client-side handle for a remote WebTransport session. It mirrors
/// the [`WebTransportSession`] API but works across process/RPC boundaries.
///
/// The `session_id` is stored locally (passed at construction time) and does
/// not require an RPC call.
///
/// Error handling uses a parent [`DynLifecycle`] plus a local
/// [`ConnectionErrorLatch`] to inherit the parent connection's lifecycle.
/// The first connection error — whether from the parent or from the session's
/// own remoc channel — is latched and returned on every subsequent operation,
/// satisfying the QUIC connection-error consistency requirement.
#[derive(Clone)]
pub struct RemoteWebTransportSession {
    client: WebTransportRpcSessionClient,
    session_id: VarInt,
    parent: Arc<dyn DynLifecycle>,
    latch: ConnectionErrorLatch,
}

impl RemoteWebTransportSession {
    pub fn new(
        client: WebTransportRpcSessionClient,
        session_id: VarInt,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        Self {
            client,
            session_id,
            parent: conn_lifecycle,
            latch: ConnectionErrorLatch::new(),
        }
    }

    pub fn into_inner(self) -> WebTransportRpcSessionClient {
        self.client
    }

    /// Synthesize a transport error for remoc channel failures.
    fn remoc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: "remoc webtransport session channel closed".into(),
            },
        }
    }

    /// Liveness probe combining parent lifecycle and remoc channel state.
    fn probe(&self) -> Option<ConnectionError> {
        if let Err(e) = DynLifecycle::check(self.parent.as_ref()) {
            return Some(e);
        }
        if RemocClient::is_closed(&self.client) {
            return Some(Self::remoc_channel_error());
        }
        None
    }
}

impl HasLatch for RemoteWebTransportSession {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for RemoteWebTransportSession {
    fn close(&self, code: crate::error::Code, reason: std::borrow::Cow<'static, str>) {
        DynLifecycle::close(self.parent.as_ref(), code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| self.probe())
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(DynLifecycle::closed(self.parent.as_ref()))
            .await
    }
}

impl webtransport::Session for RemoteWebTransportSession {
    type StreamReader = guard::GuardedQuicReader;
    type StreamWriter = guard::GuardedQuicWriter;

    fn id(&self) -> StreamId {
        self.session_id.into()
    }

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError> {
        let (reader, writer) = self
            .guard_open(WebTransportRpcSession::open_bi(&self.client))
            .await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, OpenStreamError> {
        let writer = self
            .guard_open(WebTransportRpcSession::open_uni(&self.client))
            .await?;
        Ok(writer.into_boxed_quic())
    }

    async fn accept_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), AcceptStreamError> {
        let (reader, writer) = self
            .guard_accept(WebTransportRpcSession::accept_bi(&self.client))
            .await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, AcceptStreamError> {
        let reader = self
            .guard_accept(WebTransportRpcSession::accept_uni(&self.client))
            .await?;
        Ok(reader.into_boxed_quic())
    }
}

impl WebTransportRpcSessionClient {
    /// Convert into a [`RemoteWebTransportSession`].
    pub fn into_webtransport_session(
        self,
        session_id: VarInt,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> RemoteWebTransportSession {
        RemoteWebTransportSession::new(self, session_id, conn_lifecycle)
    }
}

impl From<RemoteWebTransportSession> for WebTransportRpcSessionClient {
    fn from(remote: RemoteWebTransportSession) -> Self {
        remote.client
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        future::pending,
        sync::{Arc, Mutex},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use remoc::prelude::ServerShared;
    use tokio::time::{Duration, timeout};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        error::Code,
        extended_connect::EstablishedConnect,
        message::test::{read_stream_for_test, write_stream_for_test},
        protocol::Protocols,
        qpack::field::Protocol,
        quic::{BoxQuicStreamReader, BoxQuicStreamWriter, GetStreamIdExt, StopStreamExt},
        webtransport::{SessionClosed, WEBTRANSPORT_H3, WebTransportProtocol},
    };

    struct TestRpcSession {
        fail_open: bool,
        close_accept: bool,
        fail_accept: bool,
        tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
    }

    impl TestRpcSession {
        fn new() -> Self {
            Self {
                fail_open: false,
                close_accept: false,
                fail_accept: false,
                tasks: Mutex::new(Vec::new()),
            }
        }

        fn fail_open() -> Self {
            Self {
                fail_open: true,
                ..Self::new()
            }
        }

        fn fail_accept() -> Self {
            Self {
                fail_accept: true,
                ..Self::new()
            }
        }

        fn close_accept() -> Self {
            Self {
                close_accept: true,
                ..Self::new()
            }
        }

        fn stream_pair(&self, stream_id: u32) -> (ReadStreamClient, WriteStreamClient) {
            let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (reader_server, reader_client) =
                ReadStreamServer::new(Box::pin(reader) as BoxQuicStreamReader, 1);
            let (writer_server, writer_client) =
                WriteStreamServer::new(Box::pin(writer) as BoxQuicStreamWriter, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = reader_server.serve().await;
                }
                .in_current_span(),
            ));
            self.push_task(tokio::spawn(
                async move {
                    let _ = writer_server.serve().await;
                }
                .in_current_span(),
            ));
            (reader_client, writer_client)
        }

        fn read_stream(&self, stream_id: u32) -> ReadStreamClient {
            let (reader, _writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (reader_server, reader_client) =
                ReadStreamServer::new(Box::pin(reader) as BoxQuicStreamReader, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = reader_server.serve().await;
                }
                .in_current_span(),
            ));
            reader_client
        }

        fn write_stream(&self, stream_id: u32) -> WriteStreamClient {
            let (_reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (writer_server, writer_client) =
                WriteStreamServer::new(Box::pin(writer) as BoxQuicStreamWriter, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = writer_server.serve().await;
                }
                .in_current_span(),
            ));
            writer_client
        }

        fn push_task(&self, task: tokio::task::JoinHandle<()>) {
            self.tasks
                .lock()
                .expect("tasks mutex should not be poisoned")
                .push(AbortOnDropHandle::new(task));
        }
    }

    impl WebTransportRpcSession for TestRpcSession {
        async fn open_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), OpenStreamError> {
            if self.fail_open {
                return Err(OpenStreamError::Open {
                    source: connection_error("rpc open failed"),
                });
            }
            Ok(self.stream_pair(1))
        }

        async fn open_uni(&self) -> Result<WriteStreamClient, OpenStreamError> {
            if self.fail_open {
                return Err(OpenStreamError::Open {
                    source: connection_error("rpc open failed"),
                });
            }
            Ok(self.write_stream(2))
        }

        async fn accept_bi(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), AcceptStreamError> {
            if self.fail_accept {
                return Err(AcceptStreamError::Connection {
                    source: connection_error("rpc accept failed"),
                });
            }
            if self.close_accept {
                return Err(AcceptStreamError::Closed {
                    source: SessionClosed,
                });
            }
            Ok(self.stream_pair(3))
        }

        async fn accept_uni(&self) -> Result<ReadStreamClient, AcceptStreamError> {
            if self.fail_accept {
                return Err(AcceptStreamError::Connection {
                    source: connection_error("rpc accept failed"),
                });
            }
            if self.close_accept {
                return Err(AcceptStreamError::Closed {
                    source: SessionClosed,
                });
            }
            Ok(self.read_stream(4))
        }
    }

    #[derive(Debug, Default)]
    struct TestLifecycle {
        closes: Mutex<Vec<(Code, Cow<'static, str>)>>,
        terminal: Mutex<Option<ConnectionError>>,
    }

    impl TestLifecycle {
        fn set_terminal(&self, error: ConnectionError) {
            *self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned") = Some(error);
        }

        fn closes(&self) -> Vec<(Code, Cow<'static, str>)> {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .clone()
        }
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, code: Code, reason: Cow<'static, str>) {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .push((code, reason));
        }

        fn check(&self) -> Result<(), ConnectionError> {
            self.terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
                .map_or(Ok(()), Err)
        }

        async fn closed(&self) -> ConnectionError {
            let terminal = self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone();
            match terminal {
                Some(error) => error,
                None => pending().await,
            }
        }
    }

    fn spawn_rpc_session<S>(
        session: Arc<S>,
    ) -> (AbortOnDropHandle<()>, WebTransportRpcSessionClient)
    where
        S: WebTransportRpcSession + 'static,
    {
        let (server, client) = WebTransportRpcSessionServerShared::new(session, 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn connection_error(reason: &'static str) -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_reason(error: &ConnectionError, expected: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    async fn assert_roundtrip(
        reader: &mut (impl Stream<Item = Result<Bytes, quic::StreamError>> + Unpin),
        writer: &mut (impl Sink<Bytes, Error = quic::StreamError> + Unpin),
        payload: &'static [u8],
    ) {
        let bytes = Bytes::from_static(payload);
        writer.send(bytes.clone()).await.expect("write");
        let received = reader
            .next()
            .await
            .expect("reader should produce one chunk")
            .expect("read");
        assert_eq!(received, bytes);
    }

    fn connection_with_webtransport_pair() -> (
        Arc<MockConnection>,
        Arc<ConnectionState<dyn quic::DynConnection>>,
    ) {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        let connection =
            Arc::new(ConnectionState::new_for_test(quic.clone(), Arc::new(protocols)).erase());
        (quic, connection)
    }

    fn connection_with_enabled_webtransport_pair() -> (
        Arc<MockConnection>,
        Arc<ConnectionState<dyn quic::DynConnection>>,
    ) {
        let (quic, connection) = connection_with_webtransport_pair();
        quic.enable_stream_ops();
        (quic, connection)
    }

    fn connection_with_webtransport() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        connection_with_webtransport_pair().1
    }

    fn webtransport_connect_on(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
    ) -> EstablishedConnect {
        let stream_id = StreamId::from(VarInt::from_u32(8));
        EstablishedConnect::ready(
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection,
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        )
    }

    fn webtransport_connect() -> EstablishedConnect {
        webtransport_connect_on(connection_with_webtransport())
    }

    async fn wait_for_remoc_client_to_close(client: &WebTransportRpcSessionClient) {
        timeout(Duration::from_secs(1), async {
            loop {
                if RemocClient::is_closed(client) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("remoc client should close");
    }

    #[tokio::test]
    async fn remote_session_delegates_stream_operations_and_lifecycle() {
        let session = Arc::new(TestRpcSession::new());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote =
            RemoteWebTransportSession::new(client.clone(), VarInt::from_u32(42), parent.clone());

        assert_eq!(
            webtransport::Session::id(&remote),
            StreamId::from(VarInt::from_u32(42)),
        );
        quic::Lifecycle::check(&remote).expect("remote session should be live");

        let (mut reader, mut writer) = webtransport::Session::open_bi(&remote)
            .await
            .expect("open_bi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(1)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(1)
        );
        assert_roundtrip(&mut reader, &mut writer, b"open-bidi").await;

        let mut writer = webtransport::Session::open_uni(&remote)
            .await
            .expect("open_uni");
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(2)
        );

        let (mut reader, mut writer) = webtransport::Session::accept_bi(&remote)
            .await
            .expect("accept_bi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(3)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(3)
        );
        assert_roundtrip(&mut reader, &mut writer, b"accept-bidi").await;

        let mut reader = webtransport::Session::accept_uni(&remote)
            .await
            .expect("accept_uni");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(4)
        );
        reader
            .stop(VarInt::from_u32(100))
            .await
            .expect("stop accept_uni reader");

        quic::Lifecycle::close(&remote, Code::H3_NO_ERROR, "done".into());
        assert_eq!(parent.closes(), vec![(Code::H3_NO_ERROR, "done".into())]);

        let converted = client.into_webtransport_session(VarInt::from_u32(7), parent);
        let _inner: WebTransportRpcSessionClient = converted.into();
    }

    #[tokio::test]
    async fn remote_session_into_inner_returns_rpc_client() {
        let session = Arc::new(TestRpcSession::new());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent.clone());

        let client = remote.into_inner();
        let converted = client.into_webtransport_session(VarInt::from_u32(43), parent);

        assert_eq!(
            webtransport::Session::id(&converted),
            StreamId::from(VarInt::from_u32(43)),
        );
        webtransport::Session::open_uni(&converted)
            .await
            .expect("client returned by into_inner should remain usable");
    }

    #[tokio::test]
    async fn remote_session_latches_open_errors() {
        let session = Arc::new(TestRpcSession::fail_open());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent.clone());

        let Err(error) = webtransport::Session::open_bi(&remote).await else {
            panic!("open error should surface");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open stream connection error");
        };
        assert_reason(&source, "rpc open failed");

        let Err(error) = webtransport::Session::open_uni(&remote).await else {
            panic!("latched open error should block uni opens");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open stream connection error");
        };
        assert_reason(&source, "rpc open failed");

        let error = quic::Lifecycle::check(&remote).expect_err("latched error should fail check");
        assert_reason(&error, "rpc open failed");

        let closed = timeout(Duration::from_secs(1), quic::Lifecycle::closed(&remote))
            .await
            .expect("latched closed should resolve immediately");
        assert_reason(&closed, "rpc open failed");
    }

    #[tokio::test]
    async fn remote_session_maps_accept_session_closed() {
        let session = Arc::new(TestRpcSession::close_accept());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent);

        let Err(error) = webtransport::Session::accept_bi(&remote).await else {
            panic!("accept_bi should report session closure");
        };
        assert!(matches!(error, AcceptStreamError::Closed { .. }));

        let Err(error) = webtransport::Session::accept_uni(&remote).await else {
            panic!("accept_uni should report session closure");
        };
        assert!(matches!(error, AcceptStreamError::Closed { .. }));
    }

    #[tokio::test]
    async fn remote_session_latches_accept_connection_errors() {
        let session = Arc::new(TestRpcSession::fail_accept());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent);

        let Err(error) = webtransport::Session::accept_bi(&remote).await else {
            panic!("accept_bi should surface connection failure");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason(&source, "rpc accept failed");

        let Err(error) = webtransport::Session::accept_uni(&remote).await else {
            panic!("latched accept error should block later accepts");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected latched accept connection error");
        };
        assert_reason(&source, "rpc accept failed");

        let error =
            quic::Lifecycle::check(&remote).expect_err("latched accept error should fail check");
        assert_reason(&error, "rpc accept failed");
    }

    #[tokio::test]
    async fn remote_session_observes_parent_lifecycle_errors() {
        let session = Arc::new(TestRpcSession::new());
        let (_server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent.clone());

        parent.set_terminal(connection_error("parent closed"));

        let error = quic::Lifecycle::check(&remote).expect_err("parent error should fail check");
        assert_reason(&error, "parent closed");

        let Err(error) = webtransport::Session::open_uni(&remote).await else {
            panic!("latched parent error should block opens");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open stream connection error");
        };
        assert_reason(&source, "parent closed");

        let closed = quic::Lifecycle::closed(&remote).await;
        assert_reason(&closed, "parent closed");
    }

    #[tokio::test]
    async fn remote_session_maps_closed_remoc_channel_to_transport_errors() {
        let session = Arc::new(TestRpcSession::new());
        let (server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent);

        drop(server_task);
        wait_for_remoc_client_to_close(&remote.client).await;

        let Err(error) = webtransport::Session::open_bi(&remote).await else {
            panic!("open_bi should surface remoc channel closure");
        };
        let OpenStreamError::Open { source } = error else {
            panic!("expected open stream connection error");
        };
        assert_reason(&source, "remoc webtransport session channel closed");

        let Err(error) = webtransport::Session::accept_uni(&remote).await else {
            panic!("accept_uni should surface remoc channel closure");
        };
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected accept connection error");
        };
        assert_reason(&source, "remoc webtransport session channel closed");

        let error =
            quic::Lifecycle::check(&remote).expect_err("latched remoc error should fail checks");
        assert_reason(&error, "remoc webtransport session channel closed");

        let closed = timeout(Duration::from_secs(1), quic::Lifecycle::closed(&remote))
            .await
            .expect("latched closed should resolve immediately");
        assert_reason(&closed, "remoc webtransport session channel closed");
    }

    #[tokio::test]
    async fn remote_session_prefers_parent_error_over_closed_remoc_channel() {
        let session = Arc::new(TestRpcSession::new());
        let (server_task, client) = spawn_rpc_session(session);
        let parent = Arc::new(TestLifecycle::default());
        let remote = RemoteWebTransportSession::new(client, VarInt::from_u32(42), parent.clone());

        drop(server_task);
        wait_for_remoc_client_to_close(&remote.client).await;
        parent.set_terminal(connection_error("parent closed"));

        let error = quic::Lifecycle::check(&remote).expect_err("parent error should win probe");
        assert_reason(&error, "parent closed");
    }

    #[tokio::test]
    async fn concrete_webtransport_rpc_session_surfaces_open_errors() {
        let session = webtransport::WebTransportSession::try_from(webtransport_connect())
            .expect("connect should create webtransport session");

        let open_bi = WebTransportRpcSession::open_bi(&session)
            .await
            .expect_err("mock connection cannot open bidi streams");
        assert!(matches!(
            open_bi,
            OpenStreamError::Open { .. } | OpenStreamError::Closed { .. },
        ));

        let open_uni = WebTransportRpcSession::open_uni(&session)
            .await
            .expect_err("mock connection cannot open uni streams");
        assert!(matches!(
            open_uni,
            OpenStreamError::Open { .. } | OpenStreamError::Closed { .. },
        ));
    }

    #[tokio::test]
    async fn concrete_webtransport_rpc_session_wraps_successful_open_streams() {
        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session =
            webtransport::WebTransportSession::try_from(webtransport_connect_on(connection))
                .expect("connect should create webtransport session");

        let (reader, writer) = WebTransportRpcSession::open_bi(&session)
            .await
            .expect("open_bi should wrap successful streams");
        let mut reader = reader.into_boxed_quic();
        let mut writer = writer.into_boxed_quic();
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(0)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(0)
        );
        writer
            .send(Bytes::from_static(b"wrapped-bidi"))
            .await
            .expect("wrapped bidi writer should remain usable");
        assert!(reader.next().await.is_none());

        let (_quic, connection) = connection_with_enabled_webtransport_pair();
        let session =
            webtransport::WebTransportSession::try_from(webtransport_connect_on(connection))
                .expect("connect should create webtransport session");

        let writer = WebTransportRpcSession::open_uni(&session)
            .await
            .expect("open_uni should wrap successful stream");
        let mut writer = writer.into_boxed_quic();
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(0)
        );
        writer
            .send(Bytes::from_static(b"wrapped-uni"))
            .await
            .expect("wrapped uni writer should remain usable");
    }

    #[tokio::test]
    async fn concrete_webtransport_rpc_session_preserves_connection_closed_accepts() {
        let (quic, connection) = connection_with_webtransport_pair();
        let session =
            webtransport::WebTransportSession::try_from(webtransport_connect_on(connection))
                .expect("connect should create webtransport session");
        quic.set_terminal_error(connection_error("accept_bi connection closed"));

        let accept_bi = timeout(
            Duration::from_secs(1),
            WebTransportRpcSession::accept_bi(&session),
        )
        .await
        .expect("accept_bi should resolve on closed connection")
        .expect_err("accept_bi should preserve connection closure");
        let AcceptStreamError::Connection { source } = accept_bi else {
            panic!("expected accept_bi connection error");
        };
        assert_reason(&source, "accept_bi connection closed");

        let (quic, connection) = connection_with_webtransport_pair();
        let session =
            webtransport::WebTransportSession::try_from(webtransport_connect_on(connection))
                .expect("connect should create webtransport session");
        quic.set_terminal_error(connection_error("accept_uni connection closed"));

        let accept_uni = timeout(
            Duration::from_secs(1),
            WebTransportRpcSession::accept_uni(&session),
        )
        .await
        .expect("accept_uni should resolve on closed connection")
        .expect_err("accept_uni should preserve connection closure");
        let AcceptStreamError::Connection { source } = accept_uni else {
            panic!("expected accept_uni connection error");
        };
        assert_reason(&source, "accept_uni connection closed");
    }
}
