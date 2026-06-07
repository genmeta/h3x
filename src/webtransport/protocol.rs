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
    WebTransportSessionId,
    error::RegisterSessionError,
    registry::{RegisteredSession, Registry, RouteBiError, RouteUniError},
};
use crate::{
    codec::{BoxPeekableStreamReader, BoxStreamWriter, DecodeExt},
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{
        self, BoxQuicStreamReader, BoxQuicStreamWriter, ConnectionError, ResetStreamExt,
        StopStreamExt,
    },
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
        session_id: WebTransportSessionId,
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
        (mut reader, writer): (BoxPeekableStreamReader, BoxStreamWriter),
    ) -> Result<StreamVerdict<(BoxPeekableStreamReader, BoxStreamWriter)>, StreamError> {
        let Ok(signal_value) = reader.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed((reader, writer)));
        };

        if signal_value != WEBTRANSPORT_BIDI_SIGNAL {
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // WebTransport bidi stream confirmed. Decode session ID for routing.
        let Ok(raw_session_id) = reader.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session id from webtransport bidi stream");
            return Ok(StreamVerdict::Accepted);
        };
        let session_id = WebTransportSessionId::try_from(raw_session_id)
            .map_err(crate::connection::ConnectionError::from)?;

        tracing::debug!(session_id = %session_id, "routing webtransport bidi stream to session");

        let reader: BoxQuicStreamReader = Box::pin(reader.into_stream_reader());
        let writer: BoxQuicStreamWriter = writer.into_inner();

        match self.registry.route_bi(session_id, (reader, writer)) {
            Ok(()) => {}
            // draft-ietf-webtrans-http3 §4: "Session IDs that correspond to
            // closed sessions are not considered invalid"; §9.5 defines
            // WT_SESSION_GONE for streams whose associated session has closed.
            // https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3#section-4
            // https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3#section-9.5
            Err(RouteBiError::Closed((mut reader, mut writer))) => {
                let code = crate::error::Code::WT_SESSION_GONE.into_inner();
                _ = tokio::join!(reader.stop(code), writer.reset(code));
            }
            Err(RouteBiError::Unknown((mut reader, mut writer))) => {
                // draft-ietf-webtrans-http3 §4 allows buffering streams for a
                // not-yet-established session and requires WT_BUFFERED_STREAM_REJECTED
                // when that buffer is full. h3x uses a zero-capacity pre-session
                // buffer, so every valid unknown-session stream is rejected here.
                let code = crate::error::Code::WT_BUFFERED_STREAM_REJECTED.into_inner();
                _ = tokio::join!(reader.stop(code), writer.reset(code));
            }
            Err(RouteBiError::FlowControl((mut reader, mut writer))) => {
                let code = crate::error::Code::WT_FLOW_CONTROL_ERROR.into_inner();
                _ = tokio::join!(reader.stop(code), writer.reset(code));
            }
            Err(RouteBiError::Rejected((mut reader, mut writer))) => {
                let code = crate::error::Code::WT_FLOW_CONTROL_ERROR.into_inner();
                _ = tokio::join!(reader.stop(code), writer.reset(code));
            }
        }

        Ok(StreamVerdict::Accepted)
    }

    async fn accept_uni_inner(
        &self,
        mut stream: BoxPeekableStreamReader,
    ) -> Result<StreamVerdict<BoxPeekableStreamReader>, StreamError> {
        let Ok(signal_value) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if signal_value != WEBTRANSPORT_UNI_SIGNAL {
            return Ok(StreamVerdict::Passed(stream));
        }

        // WebTransport uni stream confirmed. Decode session ID for routing.
        let Ok(raw_session_id) = stream.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session id from webtransport uni stream");
            return Ok(StreamVerdict::Accepted);
        };
        let session_id = WebTransportSessionId::try_from(raw_session_id)
            .map_err(crate::connection::ConnectionError::from)?;

        tracing::debug!(session_id = %session_id, "routing webtransport uni stream to session");

        let reader: BoxQuicStreamReader = Box::pin(stream.into_stream_reader());

        match self.registry.route_uni(session_id, reader) {
            Ok(()) => {}
            // draft-ietf-webtrans-http3 §4: "Session IDs that correspond to
            // closed sessions are not considered invalid"; §9.5 defines
            // WT_SESSION_GONE for streams whose associated session has closed.
            // https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3#section-4
            // https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3#section-9.5
            Err(RouteUniError::Closed(mut reader)) => {
                let code = crate::error::Code::WT_SESSION_GONE.into_inner();
                _ = reader.stop(code).await;
            }
            Err(RouteUniError::Unknown(mut reader)) => {
                // draft-ietf-webtrans-http3 §4 allows buffering streams for a
                // not-yet-established session and requires WT_BUFFERED_STREAM_REJECTED
                // when that buffer is full. h3x uses a zero-capacity pre-session
                // buffer, so every valid unknown-session stream is rejected here.
                let code = crate::error::Code::WT_BUFFERED_STREAM_REJECTED.into_inner();
                _ = reader.stop(code).await;
            }
            Err(RouteUniError::FlowControl(mut reader)) => {
                let code = crate::error::Code::WT_FLOW_CONTROL_ERROR.into_inner();
                _ = reader.stop(code).await;
            }
            Err(RouteUniError::Rejected(mut reader)) => {
                let code = crate::error::Code::WT_FLOW_CONTROL_ERROR.into_inner();
                _ = reader.stop(code).await;
            }
        }

        Ok(StreamVerdict::Accepted)
    }
}

impl Protocol for WebTransportProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: BoxPeekableStreamReader,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableStreamReader>, StreamError>> {
        Box::pin(self.accept_uni_inner(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: (BoxPeekableStreamReader, BoxStreamWriter),
    ) -> BoxFuture<'a, Result<StreamVerdict<(BoxPeekableStreamReader, BoxStreamWriter)>, StreamError>>
    {
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
    use dhttp_identity::identity as authority;
    use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt, future::pending};

    use super::*;
    use crate::{
        codec::{PeekableStreamReader, SinkWriter, StreamReader},
        error::Code,
        protocol::InitProtocols,
        quic,
        webtransport::WebTransportSessionId,
    };

    #[test]
    fn webtransport_protocol_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<WebTransportProtocol>();
    }

    #[test]
    fn webtransport_constants_are_draft15_values() {
        assert_eq!(WEBTRANSPORT_H3, "webtransport-h3");
        assert_eq!(WEBTRANSPORT_BIDI_SIGNAL.into_inner(), 0x41);
        assert_eq!(WEBTRANSPORT_UNI_SIGNAL.into_inner(), 0x54);
        assert_eq!(Code::WT_SESSION_GONE.into_inner(), 0x170d7b68);
    }

    #[tokio::test]
    async fn unknown_bidi_session_is_rejected_with_wt_buffered_stream_rejected() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41, 0x28])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
        assert_eq!(
            state.reset_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
    }

    #[tokio::test]
    async fn unknown_uni_session_is_rejected_with_wt_buffered_stream_rejected() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x54, 0x28])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn incoming_stream_with_invalid_session_id_closes_connection_with_h3_id_error() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41, 0x03])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let error = match protocol.accept_bi((reader, writer)).await {
            Ok(_) => panic!("invalid WT session id must be connection scoped"),
            Err(error) => error,
        };

        assert_stream_connection_code(error, Code::H3_ID_ERROR);
    }

    #[test]
    fn registry_register_accepts_only_webtransport_session_id() {
        let protocol = test_protocol();
        let session_id = WebTransportSessionId::try_from(StreamId::from(VarInt::from_u32(4)))
            .expect("client bidi stream id is valid WT session id");

        let registered = protocol
            .register(session_id)
            .expect("registration succeeds");

        assert_eq!(registered.state.id(), session_id);
    }

    #[tokio::test]
    async fn closed_bidi_session_id_uses_wt_session_gone() {
        let protocol = test_protocol();
        let registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        registered.state.close();

        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41, 0x28])]);
        let writer = test_writer(state.clone());

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_SESSION_GONE.into_inner()]
        );
        assert_eq!(
            state.reset_codes(),
            vec![Code::WT_SESSION_GONE.into_inner()]
        );
    }

    #[tokio::test]
    async fn closed_uni_session_id_uses_wt_session_gone() {
        let protocol = test_protocol();
        let registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        registered.state.close();

        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x54, 0x28])]);

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_SESSION_GONE.into_inner()]
        );
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn registered_bidi_session_receives_payload_after_header() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(
            state.clone(),
            vec![Bytes::from_static(&[0x40, 0x41, 0x28, 0xde, 0xad])],
        );
        let writer = test_writer(state.clone());
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        let (mut routed_reader, _routed_writer) = registered
            .bidi_rx
            .recv()
            .await
            .expect("registered session should receive bidi stream");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xde, 0xad])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn registered_uni_session_receives_payload_after_header() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(
            state.clone(),
            vec![Bytes::from_static(&[0x40, 0x54, 0x28, 0xbe, 0xef])],
        );
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        let mut routed_reader = registered
            .uni_rx
            .recv()
            .await
            .expect("registered session should receive uni stream");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xbe, 0xef])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn split_bidi_routing_header_routes_registered_stream() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(
            state.clone(),
            vec![
                Bytes::from_static(&[0x40]),
                Bytes::from_static(&[0x41]),
                Bytes::from_static(&[0x28, 0xca, 0xfe]),
            ],
        );
        let writer = test_writer(state.clone());
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        let (mut routed_reader, _routed_writer) = registered
            .bidi_rx
            .recv()
            .await
            .expect("registered session should receive bidi stream");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xca, 0xfe])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn split_uni_routing_header_routes_registered_stream() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(
            state.clone(),
            vec![
                Bytes::from_static(&[0x40]),
                Bytes::from_static(&[0x54]),
                Bytes::from_static(&[0x28, 0xca, 0xfe]),
            ],
        );
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        let mut routed_reader = registered
            .uni_rx
            .recv()
            .await
            .expect("registered session should receive uni stream");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xca, 0xfe])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn wrong_bidi_signal_is_passed_through_without_aborting() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x05, 0x99])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed((mut passed_reader, _passed_writer)) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_reader).reset();
        let mut passed_reader = passed_reader.into_stream_reader();
        assert_eq!(
            passed_reader
                .next()
                .await
                .expect("reader should yield original bytes")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x05, 0x99])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn wrong_uni_signal_is_passed_through_without_stopping() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x06, 0x77])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed(mut passed_stream) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_stream).reset();
        let mut passed_stream = passed_stream.into_stream_reader();
        assert_eq!(
            passed_stream
                .next()
                .await
                .expect("reader should yield original bytes")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x06, 0x77])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn incomplete_bidi_signal_is_passed_through_without_aborting() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed((mut passed_reader, _passed_writer)) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_reader).reset();
        let mut passed_reader = passed_reader.into_stream_reader();
        assert_eq!(
            passed_reader
                .next()
                .await
                .expect("reader should yield original bytes")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x40])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn incomplete_uni_signal_is_passed_through_without_stopping() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed(mut passed_stream) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_stream).reset();
        let mut passed_stream = passed_stream.into_stream_reader();
        assert_eq!(
            passed_stream
                .next()
                .await
                .expect("reader should yield original bytes")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x40])
        );
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn truncated_bidi_session_id_is_accepted_without_abort() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn truncated_uni_session_id_is_accepted_without_stop() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x54])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn reset_while_decoding_bidi_signal_is_passed_through_without_aborting() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader_results(state.clone(), vec![Err(reset_stream_error(7))]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Passed(_)));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn reset_while_decoding_uni_signal_is_passed_through_without_stopping() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader_results(state.clone(), vec![Err(reset_stream_error(7))]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Passed(_)));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn reset_while_decoding_bidi_session_id_is_accepted_without_abort() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader_results(
            state.clone(),
            vec![
                Ok(Bytes::from_static(&[0x40, 0x41])),
                Err(reset_stream_error(9)),
            ],
        );
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn reset_while_decoding_uni_session_id_is_accepted_without_stop() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader_results(
            state.clone(),
            vec![
                Ok(Bytes::from_static(&[0x40, 0x54])),
                Err(reset_stream_error(9)),
            ],
        );
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn empty_bidi_stream_is_passed_through_without_side_effects() {
        let state = Arc::new(StreamState::default());
        let reader = test_reader(state.clone(), Vec::new());
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed((mut passed_reader, _passed_writer)) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_reader).reset();
        let mut passed_reader = passed_reader.into_stream_reader();
        assert!(passed_reader.next().await.is_none());
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn empty_uni_stream_is_passed_through_without_side_effects() {
        let state = Arc::new(StreamState::default());
        let stream = test_reader(state.clone(), Vec::new());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        let StreamVerdict::Passed(mut passed_stream) = verdict else {
            panic!("unexpected verdict");
        };
        Pin::new(&mut passed_stream).reset();
        let mut passed_stream = passed_stream.into_stream_reader();
        assert!(passed_stream.next().await.is_none());
        assert!(state.stopped_codes().is_empty());
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn full_bidi_session_channel_rejects_and_aborts_extra_stream() {
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        for _ in 0..16 {
            let state = Arc::new(StreamState::default());
            let reader = test_reader(
                state.clone(),
                vec![Bytes::from_static(&[0x40, 0x41, 0x28, 0xde, 0xad])],
            );
            let writer = test_writer(state.clone());

            let verdict = protocol
                .accept_bi((reader, writer))
                .await
                .expect("routing should not fail");

            assert!(matches!(verdict, StreamVerdict::Accepted));
            assert!(state.stopped_codes().is_empty());
            assert!(state.reset_codes().is_empty());
        }

        let overflow_state = Arc::new(StreamState::default());
        let reader = test_reader(
            overflow_state.clone(),
            vec![Bytes::from_static(&[0x40, 0x41, 0x28, 0xfa, 0xce])],
        );
        let writer = test_writer(overflow_state.clone());

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            overflow_state.stopped_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );
        assert_eq!(
            overflow_state.reset_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );

        let (mut routed_reader, _routed_writer) = registered
            .bidi_rx
            .recv()
            .await
            .expect("registered session should still retain queued streams");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xde, 0xad])
        );
    }

    #[tokio::test]
    async fn failed_bidi_rejection_for_unknown_session_is_ignored() {
        let state = Arc::new(StreamState::with_stop_and_reset_errors());
        let reader = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x41, 0x28])]);
        let writer = test_writer(state.clone());
        let protocol = test_protocol();

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
        assert_eq!(
            state.reset_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
    }

    #[tokio::test]
    async fn full_uni_session_channel_rejects_and_stops_extra_stream() {
        let protocol = test_protocol();
        let mut registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");

        for _ in 0..16 {
            let state = Arc::new(StreamState::default());
            let stream = test_reader(
                state.clone(),
                vec![Bytes::from_static(&[0x40, 0x54, 0x28, 0xbe, 0xef])],
            );

            let verdict = protocol
                .accept_uni(stream)
                .await
                .expect("routing should not fail");

            assert!(matches!(verdict, StreamVerdict::Accepted));
            assert!(state.stopped_codes().is_empty());
            assert!(state.reset_codes().is_empty());
        }

        let overflow_state = Arc::new(StreamState::default());
        let stream = test_reader(
            overflow_state.clone(),
            vec![Bytes::from_static(&[0x40, 0x54, 0x28, 0xca, 0xfe])],
        );

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            overflow_state.stopped_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );
        assert!(overflow_state.reset_codes().is_empty());

        let mut routed_reader = registered
            .uni_rx
            .recv()
            .await
            .expect("registered session should still retain queued streams");
        assert_eq!(
            routed_reader
                .next()
                .await
                .expect("reader should yield a payload chunk")
                .expect("payload chunk should succeed"),
            Bytes::from_static(&[0xbe, 0xef])
        );
    }

    #[tokio::test]
    async fn failed_uni_rejection_for_unknown_session_is_ignored() {
        let state = Arc::new(StreamState::with_stop_error());
        let stream = test_reader(state.clone(), vec![Bytes::from_static(&[0x40, 0x54, 0x28])]);
        let protocol = test_protocol();

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            state.stopped_codes(),
            vec![Code::WT_BUFFERED_STREAM_REJECTED.into_inner()]
        );
        assert!(state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn closed_bidi_session_receiver_rejects_and_aborts_stream() {
        let protocol = test_protocol();
        let RegisteredSession {
            state: _session_state,
            bidi_rx,
            uni_rx: _uni_rx,
        } = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        drop(bidi_rx);

        let stream_state = Arc::new(StreamState::default());
        let reader = test_reader(
            stream_state.clone(),
            vec![Bytes::from_static(&[0x40, 0x41, 0x28, 0xfa, 0xce])],
        );
        let writer = test_writer(stream_state.clone());

        let verdict = protocol
            .accept_bi((reader, writer))
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            stream_state.stopped_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );
        assert_eq!(
            stream_state.reset_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );
    }

    #[tokio::test]
    async fn closed_uni_session_receiver_rejects_and_stops_stream() {
        let protocol = test_protocol();
        let RegisteredSession {
            state: _session_state,
            bidi_rx: _bidi_rx,
            uni_rx,
        } = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        drop(uni_rx);

        let stream_state = Arc::new(StreamState::default());
        let stream = test_reader(
            stream_state.clone(),
            vec![Bytes::from_static(&[0x40, 0x54, 0x28, 0xfa, 0xce])],
        );

        let verdict = protocol
            .accept_uni(stream)
            .await
            .expect("routing should not fail");

        assert!(matches!(verdict, StreamVerdict::Accepted));
        assert_eq!(
            stream_state.stopped_codes(),
            vec![Code::WT_FLOW_CONTROL_ERROR.into_inner()]
        );
        assert!(stream_state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn factory_init_keeps_connection_and_starts_empty() {
        let conn = Arc::new(TestConnection);
        let expected: Arc<dyn quic::DynConnection> = conn.clone();
        let protocol = WebTransportProtocolFactory
            .init(&conn, &Protocols::new())
            .await
            .expect("factory init should succeed");

        assert!(Arc::ptr_eq(&protocol.connection(), &expected));
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 0 }"
        );
    }

    #[tokio::test]
    async fn factory_initializer_inserts_webtransport_protocol_once() {
        let conn = Arc::new(TestConnection);
        let mut layers = Protocols::new();

        WebTransportProtocolFactory
            .init_protocols(&conn, &mut layers)
            .await
            .expect("factory initializer should insert protocol");

        let protocol = layers
            .get::<WebTransportProtocol>()
            .expect("webtransport protocol should be registered");
        let _registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 1 }"
        );

        WebTransportProtocolFactory
            .init_protocols(&conn, &mut layers)
            .await
            .expect("second initialization should be a no-op");

        let protocol = layers
            .get::<WebTransportProtocol>()
            .expect("webtransport protocol should remain registered");
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 1 }"
        );
    }

    #[test]
    fn new_for_test_connection_and_duplicate_registration_behave_consistently() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection);
        let protocol = WebTransportProtocol::new_for_test(conn.clone());
        let session_id = wt_session_id(40);

        assert!(Arc::ptr_eq(&protocol.connection(), &conn));

        let registered = protocol
            .register(session_id)
            .expect("session registration should succeed");
        assert_eq!(registered.state.id(), session_id);

        match protocol.register(session_id) {
            Err(RegisterSessionError::AlreadyRegistered {
                session_id: duplicate,
            }) => assert_eq!(duplicate, session_id),
            other => panic!("unexpected duplicate registration result: {other:?}"),
        }

        registered.state.close();

        let error = protocol
            .register(session_id)
            .expect_err("closed session id must remain reserved");
        assert!(matches!(
            error,
            RegisterSessionError::AlreadyRegistered {
                session_id: duplicate
            } if duplicate == session_id
        ));
    }

    #[test]
    fn explicit_session_close_unregisters_and_reports_closed() {
        let protocol = test_protocol();
        let session_id = wt_session_id(40);
        let registered = protocol
            .register(session_id)
            .expect("session registration should succeed");
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 1 }"
        );

        registered.state.close();

        assert!(registered.state.check_open().is_err());
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 0 }"
        );
        let error = protocol
            .register(session_id)
            .expect_err("closed session id must remain reserved");
        assert!(matches!(
            error,
            RegisterSessionError::AlreadyRegistered {
                session_id: duplicate
            } if duplicate == session_id
        ));
    }

    #[test]
    fn protocol_debug_and_factory_display_expose_session_count_and_name() {
        use std::collections::{BTreeSet, HashSet};

        let mut hash_set = HashSet::new();
        hash_set.insert(WebTransportProtocolFactory);
        hash_set.insert(WebTransportProtocolFactory);
        assert_eq!(hash_set.len(), 1);

        let mut btree_set = BTreeSet::new();
        btree_set.insert(WebTransportProtocolFactory);
        btree_set.insert(WebTransportProtocolFactory);
        assert_eq!(btree_set.len(), 1);

        let protocol = test_protocol();
        assert_eq!(format!("{}", WebTransportProtocolFactory), "WebTransport");
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 0 }"
        );

        let _registered = protocol
            .register(wt_session_id(40))
            .expect("session registration should succeed");
        assert_eq!(
            format!("{protocol:?}"),
            "WebTransportProtocol { sessions: 1 }"
        );
    }

    #[tokio::test]
    async fn test_stream_doubles_delegate_stream_id_stop_reset_and_sink_operations() {
        use quic::{GetStreamIdExt as _, ResetStreamExt as _, StopStreamExt as _};

        let state = Arc::new(StreamState::default());

        let mut reader = TestReadStream {
            state: state.clone(),
            chunks: VecDeque::from([Ok(Bytes::from_static(b"payload"))]),
        };
        assert_eq!(
            reader
                .stream_id()
                .await
                .expect("reader stream id should be available"),
            VarInt::from_u32(0)
        );
        assert_eq!(
            reader
                .next()
                .await
                .expect("reader should yield chunk")
                .expect("chunk should succeed"),
            Bytes::from_static(b"payload")
        );
        reader
            .stop(VarInt::from_u32(0x11))
            .await
            .expect("reader stop should succeed");
        assert_eq!(state.stopped_codes(), vec![VarInt::from_u32(0x11)]);

        let mut writer = TestWriteStream {
            state: state.clone(),
        };
        assert_eq!(
            writer
                .stream_id()
                .await
                .expect("writer stream id should be available"),
            VarInt::from_u32(0)
        );
        writer
            .send(Bytes::from_static(b"ignored"))
            .await
            .expect("test writer sink send should succeed");
        writer
            .flush()
            .await
            .expect("test writer sink flush should succeed");
        writer
            .close()
            .await
            .expect("test writer sink close should succeed");
        writer
            .reset(VarInt::from_u32(0x12))
            .await
            .expect("writer reset should succeed");
        assert_eq!(state.reset_codes(), vec![VarInt::from_u32(0x12)]);

        let failing_reader_state = Arc::new(StreamState::with_stop_error());
        let mut failing_reader = TestReadStream {
            state: failing_reader_state.clone(),
            chunks: VecDeque::new(),
        };
        let error = failing_reader
            .stop(VarInt::from_u32(0x13))
            .await
            .expect_err("configured stop error should surface");
        assert!(error.is_reset());
        assert_eq!(
            failing_reader_state.stopped_codes(),
            vec![VarInt::from_u32(0x13)]
        );

        let failing_writer_state = Arc::new(StreamState::with_stop_and_reset_errors());
        let mut failing_writer = TestWriteStream {
            state: failing_writer_state.clone(),
        };
        let error = failing_writer
            .reset(VarInt::from_u32(0x14))
            .await
            .expect_err("configured reset error should surface");
        assert!(error.is_reset());
        assert_eq!(
            failing_writer_state.reset_codes(),
            vec![VarInt::from_u32(0x14)]
        );
    }

    #[tokio::test]
    async fn test_connection_double_delegates_agents_lifecycle_and_pending_streams() {
        let conn = TestConnection;

        assert!(
            quic::ManageStream::open_bi(&conn).now_or_never().is_none(),
            "test open_bi should remain pending"
        );
        assert!(
            quic::ManageStream::open_uni(&conn).now_or_never().is_none(),
            "test open_uni should remain pending"
        );
        assert!(
            quic::ManageStream::accept_bi(&conn)
                .now_or_never()
                .is_none(),
            "test accept_bi should remain pending"
        );
        assert!(
            quic::ManageStream::accept_uni(&conn)
                .now_or_never()
                .is_none(),
            "test accept_uni should remain pending"
        );

        assert!(
            quic::WithLocalAuthority::local_authority(&conn)
                .await
                .expect("local authority lookup should succeed")
                .is_none()
        );
        assert!(
            quic::WithRemoteAuthority::remote_authority(&conn)
                .await
                .expect("remote authority lookup should succeed")
                .is_none()
        );
        quic::Lifecycle::close(&conn, Code::H3_NO_ERROR, Cow::Borrowed("test close"));
        quic::Lifecycle::check(&conn).expect("test connection should remain open");
        assert!(
            quic::Lifecycle::closed(&conn).now_or_never().is_none(),
            "test closed future should remain pending"
        );

        let dyn_conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection);
        assert!(
            dyn_conn.open_bi().now_or_never().is_none(),
            "dyn open_bi should delegate to the pending test connection"
        );
        assert!(
            dyn_conn.open_uni().now_or_never().is_none(),
            "dyn open_uni should delegate to the pending test connection"
        );
        assert!(
            dyn_conn.accept_bi().now_or_never().is_none(),
            "dyn accept_bi should delegate to the pending test connection"
        );
        assert!(
            dyn_conn.accept_uni().now_or_never().is_none(),
            "dyn accept_uni should delegate to the pending test connection"
        );
        assert!(
            dyn_conn
                .local_authority()
                .await
                .expect("dyn local authority lookup should succeed")
                .is_none()
        );
        assert!(
            dyn_conn
                .remote_authority()
                .await
                .expect("dyn remote authority lookup should succeed")
                .is_none()
        );
        dyn_conn.close(Code::H3_NO_ERROR, Cow::Borrowed("dyn test close"));
        dyn_conn
            .check()
            .expect("dyn test connection should remain open");
        assert!(
            dyn_conn.closed().now_or_never().is_none(),
            "dyn closed future should delegate to the pending test connection"
        );
    }

    #[tokio::test]
    async fn test_agent_doubles_expose_identity_metadata_and_signing() {
        let local = TestLocalAuthority;
        assert_eq!(authority::LocalAuthority::name(&local), "test-local");
        assert!(authority::LocalAuthority::cert_chain(&local).is_empty());
        assert_eq!(
            authority::LocalAuthority::sign(&local, b"payload")
                .await
                .expect("test local authority signing should succeed"),
            Vec::<u8>::new()
        );

        let remote = TestRemoteAuthority;
        assert_eq!(authority::RemoteAuthority::name(&remote), "test-remote");
        assert!(authority::RemoteAuthority::cert_chain(&remote).is_empty());
    }

    #[derive(Debug, Default)]
    struct StreamState {
        stopped: Mutex<Vec<VarInt>>,
        resets: Mutex<Vec<VarInt>>,
        fail_stop: bool,
        fail_reset: bool,
    }

    impl StreamState {
        fn with_stop_error() -> Self {
            Self {
                fail_stop: true,
                ..Self::default()
            }
        }

        fn with_stop_and_reset_errors() -> Self {
            Self {
                fail_stop: true,
                fail_reset: true,
                ..Self::default()
            }
        }

        fn stopped_codes(&self) -> Vec<VarInt> {
            self.stopped.lock().expect("stopped lock poisoned").clone()
        }

        fn reset_codes(&self) -> Vec<VarInt> {
            self.resets.lock().expect("resets lock poisoned").clone()
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        state: Arc<StreamState>,
        chunks: VecDeque<Result<Bytes, quic::StreamError>>,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front())
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
            if self.state.fail_stop {
                Poll::Ready(Err(reset_stream_error(0x1f)))
            } else {
                Poll::Ready(Ok(()))
            }
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

    impl quic::ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .resets
                .lock()
                .expect("resets lock poisoned")
                .push(code);
            if self.state.fail_reset {
                Poll::Ready(Err(reset_stream_error(0x2f)))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    #[derive(Debug)]
    struct TestLocalAuthority;

    impl authority::LocalAuthority for TestLocalAuthority {
        fn name(&self) -> &str {
            "test-local"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
        fn sign(
            &self,
            _data: &[u8],
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, authority::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Debug)]
    struct TestRemoteAuthority;

    impl authority::RemoteAuthority for TestRemoteAuthority {
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

    impl quic::WithLocalAuthority for TestConnection {
        type LocalAuthority = TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for TestConnection {
        type RemoteAuthority = TestRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
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
    ) -> PeekableStreamReader<BoxQuicStreamReader> {
        test_reader_results(state, chunks.into_iter().map(Ok).collect())
    }

    fn test_reader_results(
        state: Arc<StreamState>,
        chunks: Vec<Result<Bytes, quic::StreamError>>,
    ) -> PeekableStreamReader<BoxQuicStreamReader> {
        let stream = TestReadStream {
            state,
            chunks: chunks.into(),
        };
        PeekableStreamReader::new(StreamReader::new(Box::pin(stream) as BoxQuicStreamReader))
    }

    fn test_writer(state: Arc<StreamState>) -> SinkWriter<BoxQuicStreamWriter> {
        SinkWriter::new(Box::pin(TestWriteStream { state }) as BoxQuicStreamWriter)
    }

    fn test_protocol() -> WebTransportProtocol {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection);
        WebTransportProtocol {
            registry: Registry::default(),
            conn,
        }
    }

    fn wt_session_id(id: u32) -> WebTransportSessionId {
        WebTransportSessionId::try_from(StreamId::from(VarInt::from_u32(id)))
            .expect("test id must be a valid webtransport session id")
    }

    fn reset_stream_error(code: u32) -> quic::StreamError {
        quic::StreamError::Reset {
            code: VarInt::from_u32(code),
        }
    }

    fn assert_stream_connection_code(error: StreamError, expected: Code) {
        let StreamError::Connection { source } = error else {
            panic!("expected connection-scoped stream error, got {error:?}");
        };
        let crate::connection::ConnectionError::H3 { source } = source else {
            panic!("expected h3 connection error, got {source:?}");
        };
        assert_eq!(source.code(), expected);
    }
}
