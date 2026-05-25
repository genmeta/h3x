//! WebTransport protocol layer for h3x stream dispatch.
//!
//! Integrates WebTransport into the h3x layered protocol architecture. The
//! protocol layer identifies incoming WebTransport streams by peeking for the
//! signal values (`0x41` for bidi, `0x54` for uni), then routes them to the
//! appropriate session based on session ID.
//!
//! # Stream identification
//!
//! The protocol layer consumes exactly two fields from each incoming stream:
//!
//! 1. The stream signal value ([`VarInt`])
//! 2. The session ID ([`StreamId`](crate::stream_id::StreamId))
//!
//! The session receives the stream positioned after these two fields.

use std::{fmt, sync::Arc};

use futures::future::BoxFuture;

use super::{
    error::RegisterSessionError,
    registry::{RegisteredSession, Registry},
};
use crate::{
    codec::{
        BoxReadStream, BoxWriteStream, DecodeExt, ErasedPeekableBiStream, ErasedPeekableUniStream,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, CancelStreamExt, ConnectionError, StopStreamExt},
    stream_id::StreamId,
    varint::VarInt,
};

// ============================================================================
// Constants
// ============================================================================

/// Extended CONNECT protocol token for WebTransport over HTTP/3.
pub const WEBTRANSPORT_H3: &str = "webtransport-h3";

/// Signal value for WebTransport bidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WEBTRANSPORT_BIDI_SIGNAL: VarInt = VarInt::from_u32(0x41);

/// Signal value for WebTransport unidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WEBTRANSPORT_UNI_SIGNAL: VarInt = VarInt::from_u32(0x54);

// ============================================================================
// WebTransportProtocol
// ============================================================================

/// WebTransport protocol layer for h3x.
///
/// Routes incoming QUIC streams to registered sessions by peeking the signal
/// value and session ID.
///
/// Created once per QUIC connection by [`WebTransportProtocolFactory`] and
/// shared (via `Arc<Protocols>`) across all concurrent streams.
pub struct WebTransportProtocol {
    registry: Registry,
    conn: Arc<dyn quic::DynConnection>,
}

impl fmt::Debug for WebTransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportProtocol")
            .field("sessions", &self.registry.len())
            .finish()
    }
}

impl WebTransportProtocol {
    pub(super) fn register(
        &self,
        session_id: StreamId,
    ) -> Result<RegisteredSession, RegisterSessionError> {
        self.registry.register(session_id)
    }

    pub(super) fn connection(&self) -> Arc<dyn quic::DynConnection> {
        Arc::clone(&self.conn)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(conn: Arc<dyn quic::DynConnection>) -> Self {
        Self {
            registry: Registry::default(),
            conn,
        }
    }
}

// ============================================================================
// Stream routing
// ============================================================================

impl WebTransportProtocol {
    async fn accept_bi_inner(
        &self,
        (mut reader, writer): ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        let Ok(signal_value) = reader.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed((reader, writer)));
        };

        if signal_value != WEBTRANSPORT_BIDI_SIGNAL {
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // WebTransport bidi stream confirmed. Decode session ID for routing.
        let Ok(session_id) = reader.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session id from webtransport bidi stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(session_id = %session_id, "routing webtransport bidi stream to session");

        let reader: BoxReadStream = Box::pin(reader.into_stream_reader());
        let writer: BoxWriteStream = writer.into_inner();

        if let Err((mut reader, mut writer)) = self.registry.route_bi(session_id, (reader, writer))
        {
            let code = crate::error::Code::H3_REQUEST_CANCELLED.into_inner();
            _ = tokio::join!(reader.stop(code), writer.cancel(code));
        }

        Ok(StreamVerdict::Accepted)
    }

    async fn accept_uni_inner(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        let Ok(signal_value) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if signal_value != WEBTRANSPORT_UNI_SIGNAL {
            return Ok(StreamVerdict::Passed(stream));
        }

        // WebTransport uni stream confirmed. Decode session ID for routing.
        let Ok(session_id) = stream.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session id from webtransport uni stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(session_id = %session_id, "routing webtransport uni stream to session");

        let reader: BoxReadStream = Box::pin(stream.into_stream_reader());

        if let Err(mut reader) = self.registry.route_uni(session_id, reader) {
            let code = crate::error::Code::H3_REQUEST_CANCELLED.into_inner();
            _ = reader.stop(code).await;
        }

        Ok(StreamVerdict::Accepted)
    }
}

impl Protocol for WebTransportProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        Box::pin(self.accept_uni_inner(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(self.accept_bi_inner(stream))
    }
}

// ============================================================================
// WebTransportProtocolFactory
// ============================================================================

/// Factory for creating [`WebTransportProtocol`] instances during connection setup.
///
/// Register this as a protocol layer to enable WebTransport stream routing:
///
/// ```ignore
/// let builder = ConnectionBuilder::new(settings)
///     .protocol(WebTransportProtocolFactory);
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct WebTransportProtocolFactory;

impl fmt::Display for WebTransportProtocolFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebTransport")
    }
}

impl<C: quic::Connection> ProductProtocol<C> for WebTransportProtocolFactory {
    type Protocol = WebTransportProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        _layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        let conn: Arc<dyn quic::DynConnection> = conn.clone();
        Box::pin(async move {
            Ok(WebTransportProtocol {
                registry: Registry::default(),
                conn,
            })
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

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
    use futures::{Sink, Stream, future::pending};

    use super::*;
    use crate::{
        codec::{PeekableStreamReader, SinkWriter, StreamReader},
        error::Code,
        quic,
    };

    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<WebTransportProtocol>();

    #[test]
    fn webtransport_constants_are_draft15_values() {
        assert_eq!(WEBTRANSPORT_H3, "webtransport-h3");
        assert_eq!(WEBTRANSPORT_BIDI_SIGNAL.into_inner(), 0x41);
        assert_eq!(WEBTRANSPORT_UNI_SIGNAL.into_inner(), 0x54);
    }

    #[tokio::test]
    async fn unknown_bidi_session_is_accepted_and_aborted() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41, 0x2a])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::H3_REQUEST_CANCELLED.into_inner()]
        );
        assert_eq!(
            state.cancelled_codes(),
            vec![Code::H3_REQUEST_CANCELLED.into_inner()]
        );
    }

    #[tokio::test]
    async fn unknown_uni_session_is_accepted_and_stopped() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x54, 0x2a])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::H3_REQUEST_CANCELLED.into_inner()]
        );
        assert!(state.cancelled_codes().is_empty());
    }

    #[derive(Debug, Default)]
    struct StreamState {
        stopped: Mutex<Vec<VarInt>>,
        cancelled: Mutex<Vec<VarInt>>,
    }

    impl StreamState {
        fn stopped_codes(&self) -> Vec<VarInt> {
            self.stopped.lock().expect("stopped lock poisoned").clone()
        }

        fn cancelled_codes(&self) -> Vec<VarInt> {
            self.cancelled
                .lock()
                .expect("cancelled lock poisoned")
                .clone()
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        state: Arc<StreamState>,
        chunks: VecDeque<Bytes>,
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
            Poll::Ready(Ok(VarInt::from_u32(0)))
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
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
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
            Poll::Ready(Ok(VarInt::from_u32(0)))
        }
    }

    impl quic::CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .cancelled
                .lock()
                .expect("cancelled lock poisoned")
                .push(code);
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

    #[derive(Debug, Default)]
    struct TestConnection;

    impl quic::ManageStream for TestConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            pending().await
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
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    fn test_reader(
        state: Arc<StreamState>,
        chunks: Vec<Bytes>,
    ) -> PeekableStreamReader<BoxReadStream> {
        let stream = TestReadStream {
            state,
            chunks: chunks.into(),
        };
        PeekableStreamReader::new(StreamReader::new(Box::pin(stream) as BoxReadStream))
    }

    fn test_writer(state: Arc<StreamState>) -> SinkWriter<BoxWriteStream> {
        SinkWriter::new(Box::pin(TestWriteStream { state }) as BoxWriteStream)
    }

    fn test_protocol() -> WebTransportProtocol {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection);
        WebTransportProtocol {
            registry: Registry::default(),
            conn,
        }
    }
}
