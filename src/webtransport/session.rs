//! WebTransport session handle.
//!
//! A [`WebTransportSession`] is created from an
//! [`EstablishedConnect`](crate::extended_connect::EstablishedConnect) and
//! provides the application-facing API for opening and accepting streams within a
//! WebTransport session.
//!
//! Dropping the session automatically unregisters it from the protocol registry.

use std::{fmt, sync::Arc};

use snafu::ResultExt;
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{
    error::{
        AcceptStreamError, DatagramError, OpenStreamError, RegisterSessionError, SessionClosed,
        UnsupportedSnafu, accept_stream_error, open_stream_error,
    },
    protocol::{WEBTRANSPORT_BIDI_SIGNAL, WEBTRANSPORT_H3, WEBTRANSPORT_UNI_SIGNAL},
    registry::{RegisteredSession, SessionState},
};
use crate::{
    codec::{BoxReadStream, BoxWriteStream, EncodeExt, EncodeInto, SinkWriter},
    extended_connect::EstablishedConnect,
    quic::{self},
    stream_id::StreamId,
    varint::VarInt,
};

// ============================================================================
// Stream type aliases
// ============================================================================

/// A routed bidirectional stream (reader + writer) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedBiStream = (BoxReadStream, BoxWriteStream);

/// A routed unidirectional stream (reader only) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedUniStream = BoxReadStream;

// ============================================================================
// WebTransportSession
// ============================================================================

/// Handle for a registered WebTransport session.
///
/// Provides stream management for a single session: accepting streams routed
/// by the protocol layer and opening new streams to the remote peer.
///
/// Dropping the handle automatically unregisters the session from the protocol
/// registry.
pub struct WebTransportSession {
    state: Arc<SessionState>,
    bidi_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedBiStream>>,
    uni_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedUniStream>>,
    conn: Arc<dyn quic::DynConnection>,
    _control_task: AbortOnDropHandle<()>,
}

impl WebTransportSession {
    fn from_registered(
        registered: RegisteredSession,
        conn: Arc<dyn quic::DynConnection>,
        connect: EstablishedConnect,
    ) -> Self {
        let state = registered.state;
        let task_state = Arc::clone(&state);
        let control_task = async move {
            match connect.into_streams().await {
                Ok((mut read, _write)) => loop {
                    match read.read_data_chunk().await {
                        Ok(Some(_chunk)) => {}
                        Ok(None) => break,
                        Err(error) => {
                            tracing::debug!(
                                error = %snafu::Report::from_error(&error),
                                "webtransport connect stream read failed"
                            );
                            break;
                        }
                    }
                },
                Err(error) => {
                    tracing::debug!(
                        error = %snafu::Report::from_error(&error),
                        "failed to take over webtransport connect stream"
                    );
                }
            }
            task_state.close();
        };

        Self {
            state,
            bidi_rx: tokio::sync::Mutex::new(registered.bidi_rx),
            uni_rx: tokio::sync::Mutex::new(registered.uni_rx),
            conn,
            _control_task: AbortOnDropHandle::new(tokio::spawn(control_task.in_current_span())),
        }
    }

    /// The session ID (QUIC stream ID of the CONNECT stream that established
    /// this session).
    pub fn id(&self) -> StreamId {
        self.state.id()
    }

    /// Open a new bidirectional stream within this session.
    ///
    /// Writes the WebTransport bidi signal value (`0x41`) and the session ID as
    /// a routing header, then returns the raw stream pair positioned after the
    /// header.
    pub async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
        self.state
            .check_open()
            .context(open_stream_error::ClosedSnafu)?;
        let (reader, writer) = self
            .conn
            .open_bi()
            .await
            .context(open_stream_error::OpenSnafu)?;
        let writer = write_header(writer, WEBTRANSPORT_BIDI_SIGNAL, self.id()).await?;
        Ok((reader, writer))
    }

    /// Open a new unidirectional stream within this session.
    ///
    /// Writes the WebTransport uni signal value (`0x54`) and the session ID as
    /// a routing header, then returns the write half positioned after the
    /// header.
    pub async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
        self.state
            .check_open()
            .context(open_stream_error::ClosedSnafu)?;
        let writer = self
            .conn
            .open_uni()
            .await
            .context(open_stream_error::OpenSnafu)?;
        write_header(writer, WEBTRANSPORT_UNI_SIGNAL, self.id()).await
    }

    /// Accept a bidirectional stream routed to this session by the protocol layer.
    pub async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), AcceptStreamError> {
        self.state
            .check_open()
            .context(accept_stream_error::ClosedSnafu)?;
        let mut rx = self.bidi_rx.lock().await;
        tokio::select! {
            biased;
            source = self.conn.closed() => {
                self.state.close();
                Err(AcceptStreamError::Connection { source })
            }
            stream = rx.recv() => stream.ok_or(SessionClosed).context(accept_stream_error::ClosedSnafu),
        }
    }

    /// Accept a unidirectional stream routed to this session by the protocol layer.
    pub async fn accept_uni(&self) -> Result<BoxReadStream, AcceptStreamError> {
        self.state
            .check_open()
            .context(accept_stream_error::ClosedSnafu)?;
        let mut rx = self.uni_rx.lock().await;
        tokio::select! {
            biased;
            source = self.conn.closed() => {
                self.state.close();
                Err(AcceptStreamError::Connection { source })
            }
            stream = rx.recv() => stream.ok_or(SessionClosed).context(accept_stream_error::ClosedSnafu),
        }
    }

    /// Send a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn send_datagram(&self, _data: &[u8]) -> Result<(), DatagramError> {
        UnsupportedSnafu.fail()
    }

    /// Receive a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, DatagramError> {
        UnsupportedSnafu.fail()
    }
}

impl TryFrom<EstablishedConnect> for WebTransportSession {
    type Error = RegisterSessionError;

    fn try_from(connect: EstablishedConnect) -> Result<Self, Self::Error> {
        let protocol = match connect.protocol() {
            Some(protocol) => protocol,
            None => return Err(RegisterSessionError::MissingProtocol),
        };
        if protocol.as_str() != WEBTRANSPORT_H3 {
            let protocol = protocol.clone();
            return Err(RegisterSessionError::UnexpectedProtocol { protocol });
        }

        let (registered, conn) = {
            let protocol = connect
                .connection()
                .protocol::<super::WebTransportProtocol>()
                .ok_or(RegisterSessionError::ProtocolLayerMissing)?;
            let registered = protocol.register(connect.stream_id())?;
            let conn = protocol.connection();
            (registered, conn)
        };

        Ok(Self::from_registered(registered, conn, connect))
    }
}

// ============================================================================
// Header writing helper
// ============================================================================

/// Write the WebTransport stream routing header (signal + session_id) and flush.
async fn write_header(
    writer: BoxWriteStream,
    signal: VarInt,
    session_id: StreamId,
) -> Result<BoxWriteStream, OpenStreamError> {
    let mut codec_writer = SinkWriter::new(writer);
    encode_header_value(&mut codec_writer, signal)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    encode_header_value(&mut codec_writer, session_id)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    flush_header(&mut codec_writer)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    Ok(codec_writer.into_inner())
}

async fn encode_header_value<T>(
    codec_writer: &mut SinkWriter<BoxWriteStream>,
    value: T,
) -> Result<(), quic::StreamError>
where
    T: Send,
    for<'a> T: EncodeInto<&'a mut SinkWriter<BoxWriteStream>, Error = std::io::Error, Output = ()>,
{
    codec_writer.encode_one(value).await?;
    Ok(())
}

async fn flush_header(
    codec_writer: &mut SinkWriter<BoxWriteStream>,
) -> Result<(), quic::StreamError> {
    AsyncWriteExt::flush(codec_writer).await?;
    Ok(())
}

// ============================================================================
// Trait impls
// ============================================================================

impl fmt::Debug for WebTransportSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportSession")
            .field("id", &self.id())
            .finish()
    }
}

impl Drop for WebTransportSession {
    fn drop(&mut self) {
        self.state.close();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity as agent;
    use futures::{Sink, SinkExt, Stream, StreamExt, future::pending};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::Instrument;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        extended_connect::EstablishedConnect,
        message::test::{read_stream_for_test, write_stream_for_test},
        protocol::Protocols,
        qpack::field::Protocol,
        quic,
        stream_id::StreamId,
        varint::VarInt,
        webtransport::{WEBTRANSPORT_H3, WebTransportProtocol, registry::Registry},
    };

    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<WebTransportSession>();

    #[derive(Debug, Default)]
    struct StreamState {
        written: Mutex<Vec<u8>>,
        stopped: Mutex<Vec<VarInt>>,
        cancelled: Mutex<Vec<VarInt>>,
        flushes: Mutex<usize>,
    }

    impl StreamState {
        fn written(&self) -> Vec<u8> {
            self.written.lock().expect("written lock poisoned").clone()
        }

        fn cancelled_codes(&self) -> Vec<VarInt> {
            self.cancelled
                .lock()
                .expect("cancelled lock poisoned")
                .clone()
        }

        fn stopped_codes(&self) -> Vec<VarInt> {
            self.stopped.lock().expect("stopped lock poisoned").clone()
        }

        fn flushes(&self) -> usize {
            *self.flushes.lock().expect("flushes lock poisoned")
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        state: Arc<StreamState>,
        chunks: VecDeque<Bytes>,
        stream_id: VarInt,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    impl quic::GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .stopped
                .lock()
                .expect("stopped lock poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let mut flushes = self.state.flushes.lock().expect("flushes lock poisoned");
            *flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl quic::GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestLocalAgent;

    impl agent::LocalAgent for TestLocalAgent {
        fn name(&self) -> &str {
            "test-local"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }

        fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ED25519
        }

        fn sign(
            &self,
            _scheme: rustls::SignatureScheme,
            _data: &[u8],
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, agent::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Debug)]
    struct TestRemoteAgent;

    impl agent::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            "test-remote"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug)]
    struct TestConnection {
        state: Arc<StreamState>,
    }

    impl quic::ManageStream for TestConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            Ok((
                TestReadStream {
                    state: Arc::clone(&self.state),
                    chunks: VecDeque::new(),
                    stream_id: VarInt::from_u32(9),
                },
                TestWriteStream {
                    state: Arc::clone(&self.state),
                    stream_id: VarInt::from_u32(9),
                },
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(TestWriteStream {
                state: Arc::clone(&self.state),
                stream_id: VarInt::from_u32(10),
            })
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
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    fn connection_with_webtransport() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        Arc::new(ConnectionState::new_for_test(quic, Arc::new(protocols)).erase())
    }

    fn connect_with_protocol(protocol: Option<Protocol>) -> EstablishedConnect {
        let stream_id = StreamId::from(VarInt::from_u32(4));
        EstablishedConnect::ready(
            stream_id,
            protocol,
            connection_with_webtransport(),
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        )
    }

    fn connect_on_connection(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        stream_id: StreamId,
        protocol: Option<Protocol>,
    ) -> EstablishedConnect {
        EstablishedConnect::ready(
            stream_id,
            protocol,
            connection,
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        )
    }

    fn connection_without_webtransport() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        Arc::new(ConnectionState::new_for_test(quic.clone(), Arc::new(Protocols::new())).erase())
    }

    fn noop_task() -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async {}.in_current_span()))
    }

    fn session_with_connection(
        session_id: StreamId,
        conn: Arc<dyn quic::DynConnection>,
    ) -> (Registry, WebTransportSession) {
        let registry = Registry::default();
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let session = WebTransportSession {
            state: Arc::clone(&registered.state),
            bidi_rx: tokio::sync::Mutex::new(registered.bidi_rx),
            uni_rx: tokio::sync::Mutex::new(registered.uni_rx),
            conn,
            _control_task: noop_task(),
        };
        (registry, session)
    }

    fn assert_transport_reason(error: &quic::ConnectionError, expected_reason: &str) {
        match error {
            quic::ConnectionError::Transport { source } => {
                assert_eq!(source.reason.as_ref(), expected_reason);
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn try_from_established_connect_registers_session() {
        let session = WebTransportSession::try_from(connect_with_protocol(Some(Protocol::new(
            WEBTRANSPORT_H3,
        ))))
        .expect("valid webtransport connect registers session");

        assert_eq!(session.id(), StreamId::from(VarInt::from_u32(4)));
    }

    #[tokio::test]
    async fn try_from_rejects_missing_protocol() {
        let error = WebTransportSession::try_from(connect_with_protocol(None))
            .expect_err("missing protocol is invalid");
        assert!(matches!(error, RegisterSessionError::MissingProtocol));
    }

    #[tokio::test]
    async fn try_from_rejects_unexpected_protocol() {
        let error = WebTransportSession::try_from(connect_with_protocol(Some(Protocol::new(
            "other-protocol",
        ))))
        .expect_err("wrong protocol token is invalid");
        assert!(matches!(
            error,
            RegisterSessionError::UnexpectedProtocol { .. }
        ));
    }

    #[tokio::test]
    async fn try_from_rejects_missing_protocol_layer() {
        let error = WebTransportSession::try_from(connect_on_connection(
            connection_without_webtransport(),
            StreamId::from(VarInt::from_u32(4)),
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect_err("missing webtransport protocol layer is invalid");

        assert!(matches!(error, RegisterSessionError::ProtocolLayerMissing));
    }

    #[tokio::test]
    async fn try_from_rejects_duplicate_session_registration() {
        let connection = connection_with_webtransport();
        let stream_id = StreamId::from(VarInt::from_u32(4));

        let first = WebTransportSession::try_from(connect_on_connection(
            Arc::clone(&connection),
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect("first registration should succeed");

        let error = WebTransportSession::try_from(connect_on_connection(
            connection,
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect_err("duplicate session id should be rejected");

        assert!(matches!(
            error,
            RegisterSessionError::AlreadyRegistered { session_id } if session_id == stream_id
        ));

        drop(first);
    }

    #[tokio::test]
    async fn open_bi_writes_webtransport_header_and_keeps_writer_usable() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        let (_reader, mut writer) = session.open_bi().await.expect("open_bi should succeed");
        writer
            .send(Bytes::from_static(&[0xaa, 0xbb]))
            .await
            .expect("writer should remain usable after header");

        assert_eq!(stream_state.written(), vec![0x40, 0x41, 0x04, 0xaa, 0xbb]);
        assert!(stream_state.flushes() >= 1);
        assert!(stream_state.cancelled_codes().is_empty());
    }

    #[tokio::test]
    async fn open_uni_writes_webtransport_header_and_keeps_writer_usable() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        let mut writer = session.open_uni().await.expect("open_uni should succeed");
        writer
            .send(Bytes::from_static(&[0xcc]))
            .await
            .expect("writer should remain usable after header");

        assert_eq!(stream_state.written(), vec![0x40, 0x54, 0x04, 0xcc]);
        assert!(stream_state.flushes() >= 1);
        assert!(stream_state.cancelled_codes().is_empty());
    }

    #[tokio::test]
    async fn open_streams_map_connection_errors() {
        let conn = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = conn.clone();
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        let bi_error = match session.open_bi().await {
            Ok(_) => panic!("open_bi should fail"),
            Err(error) => error,
        };
        let uni_error = match session.open_uni().await {
            Ok(_) => panic!("open_uni should fail"),
            Err(error) => error,
        };

        match bi_error {
            OpenStreamError::Open { source } => {
                assert_transport_reason(&source, "open_bi unavailable");
            }
            other => panic!("expected open error, got {other:?}"),
        }

        match uni_error {
            OpenStreamError::Open { source } => {
                assert_transport_reason(&source, "open_uni unavailable");
            }
            other => panic!("expected open error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closed_session_maps_open_and_accept_to_closed_errors() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        session.state.close();

        assert!(matches!(
            session.open_bi().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.open_uni().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.accept_bi().await,
            Err(AcceptStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.accept_uni().await,
            Err(AcceptStreamError::Closed { .. })
        ));
    }

    #[tokio::test]
    async fn accept_bi_returns_routed_stream() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        let routed_state = Arc::new(StreamState::default());

        assert!(
            registry
                .route_bi(
                    session.id(),
                    (
                        Box::pin(TestReadStream {
                            state: Arc::clone(&routed_state),
                            chunks: VecDeque::from([Bytes::from_static(&[0x11, 0x22])]),
                            stream_id: VarInt::from_u32(11),
                        }) as BoxReadStream,
                        Box::pin(TestWriteStream {
                            state: Arc::clone(&routed_state),
                            stream_id: VarInt::from_u32(11),
                        }) as BoxWriteStream,
                    ),
                )
                .is_ok()
        );

        let (mut reader, mut writer) = session.accept_bi().await.expect("accept_bi should succeed");
        writer
            .send(Bytes::from_static(&[0x33]))
            .await
            .expect("routed writer should stay usable");

        assert_eq!(
            reader
                .next()
                .await
                .expect("reader should yield a chunk")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x11, 0x22])
        );
        assert_eq!(routed_state.written(), vec![0x33]);
        assert!(stream_state.written().is_empty());
    }

    #[tokio::test]
    async fn accept_uni_returns_routed_stream() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        let routed_state = Arc::new(StreamState::default());

        assert!(
            registry
                .route_uni(
                    session.id(),
                    Box::pin(TestReadStream {
                        state: Arc::clone(&routed_state),
                        chunks: VecDeque::from([Bytes::from_static(&[0x44])]),
                        stream_id: VarInt::from_u32(12),
                    }) as BoxReadStream,
                )
                .is_ok()
        );

        let mut reader = session
            .accept_uni()
            .await
            .expect("accept_uni should succeed");
        assert_eq!(
            reader
                .next()
                .await
                .expect("reader should yield a chunk")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x44])
        );
        assert!(routed_state.stopped_codes().is_empty());
    }

    #[tokio::test]
    async fn accept_bi_maps_connection_closed() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        match session.accept_bi().await {
            Ok(_) => panic!("accept_bi should fail"),
            Err(error) => match error {
                AcceptStreamError::Connection { source } => {
                    assert_transport_reason(&source, "connection closed");
                }
                other => panic!("expected connection error, got {other:?}"),
            },
        }
    }

    #[tokio::test]
    async fn accept_uni_maps_connection_closed() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        match session.accept_uni().await {
            Ok(_) => panic!("accept_uni should fail"),
            Err(error) => match error {
                AcceptStreamError::Connection { source } => {
                    assert_transport_reason(&source, "connection closed");
                }
                other => panic!("expected connection error, got {other:?}"),
            },
        }
    }

    #[tokio::test]
    async fn datagram_methods_return_unsupported() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session
                .send_datagram(b"hello")
                .await
                .expect_err("send_datagram should be unsupported"),
            DatagramError::Unsupported
        ));
        assert!(matches!(
            session
                .recv_datagram()
                .await
                .expect_err("recv_datagram should be unsupported"),
            DatagramError::Unsupported
        ));
    }
}
