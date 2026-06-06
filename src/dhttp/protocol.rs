//! DHTTP/3 protocol layer implementation.
//!
//! `DHttpLayer` encapsulates all HTTP/3-specific logic for stream identification
//! and protocol initialization. It implements [`Protocol`] to participate in
//! the layered stream routing architecture.

use std::{
    fmt, ops,
    pin::{Pin, pin},
    sync::Arc,
};

use futures::{
    FutureExt, Sink, SinkExt, StreamExt,
    future::{self, BoxFuture},
    never::Never,
    stream::{self, FusedStream},
};
use snafu::Snafu;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    buflist::BufList,
    codec::{
        BoxPeekableStreamReader, BoxStreamWriter, DecodeExt, EncodeExt, Feed, SinkWriter,
        StreamReader,
    },
    connection::{ConnectionGoaway, ConnectionState, LifecycleExt, StreamError},
    dhttp::{
        frame::{Frame, stream::FrameStream},
        goaway::Goaway,
        message::guard,
        settings::Settings,
        stream::UnidirectionalStream,
    },
    error::{
        Code, H3CriticalStreamClosed, H3FrameUnexpected, H3IdError, H3MissingSettings,
        H3StreamCreationError,
    },
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError, GetStreamIdExt, ResetStreamExt, StopStreamExt},
    util::{ring_channel::RingChannel, set_once::SetOnce, watch::Watch},
    varint::VarInt,
};

type BoxSink<'a, Item, Err> = Pin<Box<dyn Sink<Item, Error = Err> + Send + 'a>>;

/// Internal shared state for the DHTTP/3 layer.
///
/// This struct holds the HTTP/3-specific protocol state that is shared
/// between the layer and its background tasks.
#[derive(Debug)]
pub struct DHttpState {
    /// Local HTTP/3 settings advertised to the peer.
    pub local_settings: Arc<Settings>,
    /// Peer's HTTP/3 settings, received via the control stream.
    pub peer_settings: SetOnce<Arc<Settings>>,
    /// Local GOAWAY state, set when this endpoint initiates graceful shutdown.
    pub local_goaway: Watch<Goaway>,
    /// Peer's GOAWAY state, set when the peer initiates graceful shutdown.
    pub peer_goaway: Watch<Goaway>,
    /// Maximum stream ID that this endpoint has initialized (opened).
    pub max_initialized_stream_id: Watch<VarInt>,
    /// Maximum stream ID that this endpoint has received from the peer.
    pub max_received_stream_id: Watch<VarInt>,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::{
        codec::{EncodeExt, PeekableStreamReader, SinkWriter, StreamReader},
        connection::{ConnectionState, tests::MockConnection},
        dhttp::settings::Settings,
        extended_connect::settings::EnableConnectProtocol,
        protocol::Protocols,
        quic::{
            self, BoxQuicStreamReader, BoxQuicStreamWriter, GetStreamId, GetStreamIdExt,
            ResetStream,
        },
    };

    #[derive(Debug)]
    struct TestReadStream {
        stream_id: VarInt,
    }

    impl quic::GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl quic::StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        stream_id: VarInt,
    }

    impl quic::GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl quic::ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
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

    fn test_erased_streams(
        stream_id: u32,
    ) -> (
        StreamReader<guard::GuardQuicReader>,
        SinkWriter<guard::GuardQuicWriter>,
    ) {
        let stream_id = VarInt::from_u32(stream_id);
        let reader =
            StreamReader::new(guard::GuardQuicReader::new(
                Box::pin(TestReadStream { stream_id }) as BoxQuicStreamReader,
            ));
        let writer =
            SinkWriter::new(guard::GuardQuicWriter::new(
                Box::pin(TestWriteStream { stream_id }) as BoxQuicStreamWriter,
            ));
        (reader, writer)
    }

    async fn test_peekable_uni_stream_with_bytes(bytes: &[u8]) -> BoxPeekableStreamReader {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(2));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test uni bytes");
        writer.close().await.expect("close test uni stream");
        PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxQuicStreamReader))
    }

    fn test_empty_peekable_uni_stream() -> BoxPeekableStreamReader {
        PeekableStreamReader::new(StreamReader::new(Box::pin(TestReadStream {
            stream_id: VarInt::from_u32(2),
        }) as BoxQuicStreamReader))
    }

    async fn test_peekable_bi_stream_with_bytes(
        stream_id: u32,
        bytes: &[u8],
    ) -> (BoxPeekableStreamReader, BoxStreamWriter) {
        let (reader, mut write_side) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        write_side
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test bidi bytes");
        write_side.close().await.expect("close test bidi read side");

        let (_read_side, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        (
            PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxQuicStreamReader)),
            SinkWriter::new(Box::pin(writer) as BoxQuicStreamWriter),
        )
    }

    fn test_empty_peekable_bi_stream(stream_id: u32) -> (BoxPeekableStreamReader, BoxStreamWriter) {
        let stream_id = VarInt::from_u32(stream_id);
        (
            PeekableStreamReader::new(StreamReader::new(
                Box::pin(TestReadStream { stream_id }) as BoxQuicStreamReader
            )),
            SinkWriter::new(Box::pin(TestWriteStream { stream_id }) as BoxQuicStreamWriter),
        )
    }

    fn test_connection_state() -> ConnectionState<MockConnection> {
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        ConnectionState::new_for_test(quic, Arc::new(protocols))
    }

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    fn assert_stream_connection_code(error: StreamError, expected: Code) {
        assert!(matches!(
            error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            } if source.code() == expected
        ));
    }

    fn test_transport_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_transport_error_reason(error: &quic::ConnectionError, expected: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport connection error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    async fn stream_reader_from_frames(
        frames: impl IntoIterator<Item = Frame<BufList>>,
    ) -> StreamReader<BoxQuicStreamReader> {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(2));
        let mut writer = SinkWriter::new(writer);
        for frame in frames {
            writer
                .encode_one(frame)
                .await
                .expect("encode test control frame");
        }
        writer.close().await.expect("close test control stream");
        StreamReader::new(Box::pin(reader) as BoxQuicStreamReader)
    }

    async fn settings_frame(settings: &Settings) -> Frame<BufList> {
        BufList::new()
            .encode(settings)
            .await
            .expect("settings encoding into buflist is infallible")
    }

    async fn goaway_frame(stream_id: u32) -> Frame<BufList> {
        BufList::new()
            .encode(Goaway::new(VarInt::from_u32(stream_id)))
            .await
            .expect("goaway encoding into buflist is infallible")
    }

    #[test]
    fn dhttp_factory_display_names_protocol() {
        let factory = DHttpProtocolFactory::default();

        assert_eq!(factory.to_string(), "DHTTP/3");
    }

    #[tokio::test]
    async fn test_stream_helpers_cover_writer_control_and_sink_traits() {
        let stream_id = VarInt::from_u32(27);
        let mut writer = TestWriteStream { stream_id };

        assert_eq!(
            futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        futures::future::poll_fn(|cx| Pin::new(&mut writer).poll_reset(cx, VarInt::from_u32(1)))
            .await
            .expect("reset succeeds");
        writer
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("send succeeds");
        writer.flush().await.expect("flush succeeds");
        writer.close().await.expect("close succeeds");
    }

    #[tokio::test]
    async fn dhttp_protocol_debug_capacity_and_trait_routes_are_stable() {
        let state = test_connection_state();
        let debug = format!("{:?}", state.dhttp());
        assert!(debug.contains("DHttpLayer"));
        assert!(debug.contains("control_stream"));
        assert_eq!(state.dhttp().max_unresolved_request_streams().await, 32);

        let uni = test_peekable_uni_stream_with_bytes(&[0x02]).await;
        assert!(matches!(
            Protocol::accept_uni(state.dhttp(), uni)
                .await
                .expect("trait uni accept"),
            StreamVerdict::Passed(_)
        ));

        let bi = test_peekable_bi_stream_with_bytes(28, &[0x41]).await;
        assert!(matches!(
            Protocol::accept_bi(state.dhttp(), bi)
                .await
                .expect("trait bidi accept"),
            StreamVerdict::Passed(_)
        ));
    }

    #[test]
    fn dhttp_factory_same_settings_equal_hash() {
        let s1 = Arc::new(Settings::default());
        let s2 = Arc::new(Settings::default());

        let f1 = DHttpProtocolFactory::new(s1);
        let f2 = DHttpProtocolFactory::new(s2);

        assert_eq!(hash_of(&f1), hash_of(&f2));
    }

    #[test]
    fn dhttp_factory_different_settings_different_hash() {
        let s_default = Settings::default();
        let mut s_other = Settings::default();

        s_other.set(EnableConnectProtocol::setting(true));

        let f1 = DHttpProtocolFactory::new(Arc::new(s_default));
        let f2 = DHttpProtocolFactory::new(Arc::new(s_other));

        assert_ne!(hash_of(&f1), hash_of(&f2));
    }

    #[test]
    fn dhttp_factory_same_settings_eq() {
        let s1 = Arc::new(Settings::default());
        let s2 = Arc::new(Settings::default());

        let f1 = DHttpProtocolFactory::new(s1);
        let f2 = DHttpProtocolFactory::new(s2);

        assert_eq!(f1, f2);
    }

    #[test]
    fn dhttp_factory_different_settings_not_eq() {
        let s_default = Settings::default();
        let mut s_other = Settings::default();
        s_other.set(EnableConnectProtocol::setting(true));

        let f1 = DHttpProtocolFactory::new(Arc::new(s_default));
        let f2 = DHttpProtocolFactory::new(Arc::new(s_other));

        assert_ne!(f1, f2);
    }

    #[test]
    fn begin_local_goaway_defaults_to_zero_without_received_streams() {
        let state = DHttpState::new(Arc::new(Settings::default()));

        let goaway = state.begin_local_goaway();

        assert_eq!(goaway.stream_id(), VarInt::from_u32(0));
        assert_eq!(state.local_goaway.peek(), Some(goaway));
    }

    #[test]
    fn begin_local_goaway_uses_max_received_stream_id() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        state
            .register_accepted_stream(VarInt::from_u32(3))
            .expect("first accepted stream");
        state
            .register_accepted_stream(VarInt::from_u32(11))
            .expect("higher accepted stream");
        state
            .register_accepted_stream(VarInt::from_u32(7))
            .expect("lower accepted stream");

        let goaway = state.begin_local_goaway();

        assert_eq!(goaway.stream_id(), VarInt::from_u32(11));
        assert_eq!(state.local_goaway.peek(), Some(goaway));
    }

    #[test]
    fn initialized_stream_updates_initialized_only() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        let stream_id = VarInt::from_u32(7);

        state
            .register_initialized_stream(stream_id)
            .expect("initialized stream should be accepted");

        assert_eq!(state.max_initialized_stream_id.peek(), Some(stream_id));
        assert_eq!(state.max_received_stream_id.peek(), None);
    }

    #[test]
    fn initialized_stream_tracks_maximum_stream_id() {
        let state = DHttpState::new(Arc::new(Settings::default()));

        state
            .register_initialized_stream(VarInt::from_u32(15))
            .expect("first initialized stream");
        state
            .register_initialized_stream(VarInt::from_u32(5))
            .expect("lower initialized stream");

        assert_eq!(
            state.max_initialized_stream_id.peek(),
            Some(VarInt::from_u32(15))
        );
    }

    #[test]
    fn accepted_stream_updates_received_only() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        let stream_id = VarInt::from_u32(9);

        state
            .register_accepted_stream(stream_id)
            .expect("accepted stream should be accepted");

        assert_eq!(state.max_received_stream_id.peek(), Some(stream_id));
        assert_eq!(state.max_initialized_stream_id.peek(), None);
    }

    #[test]
    fn accepted_stream_tracks_maximum_stream_id() {
        let state = DHttpState::new(Arc::new(Settings::default()));

        state
            .register_accepted_stream(VarInt::from_u32(12))
            .expect("first accepted stream");
        state
            .register_accepted_stream(VarInt::from_u32(4))
            .expect("lower accepted stream");

        assert_eq!(
            state.max_received_stream_id.peek(),
            Some(VarInt::from_u32(12))
        );
    }

    #[test]
    fn accepted_stream_rejected_at_local_goaway_boundary() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        state.local_goaway.set(Goaway::new(VarInt::from_u32(10)));

        let error = state
            .register_accepted_stream(VarInt::from_u32(10))
            .expect_err("stream at local goaway boundary must be rejected");

        assert_eq!(error, ConnectionGoaway::Local);
    }

    #[test]
    fn initialized_stream_rejected_after_peer_goaway_latched() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        state
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(13)))
            .expect("first peer goaway should be accepted");

        let error = state
            .register_initialized_stream(VarInt::from_u32(11))
            .expect_err("initialized stream must be rejected after peer goaway");

        assert_eq!(error, ConnectionGoaway::Peer);
    }

    #[test]
    fn apply_peer_goaway_rejects_increasing_stream_id_ordering() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        state
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(20)))
            .expect("first peer goaway should be accepted");

        let error = state
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(21)))
            .expect_err("increasing peer goaway stream id must be rejected");

        assert!(matches!(
            error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source },
            } if source.code() == Code::H3_ID_ERROR
        ));
    }

    #[tokio::test]
    async fn control_stream_reads_settings_goaway_unknown_and_reports_close() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        let mut settings = Settings::default();
        settings.set(EnableConnectProtocol::setting(true));
        let settings = Arc::new(settings);
        let unknown = Frame::new(VarInt::from_u32(0x2f), BufList::new())
            .expect("unknown frame type is valid");
        let stream = stream_reader_from_frames([
            settings_frame(&settings).await,
            unknown,
            goaway_frame(9).await,
        ])
        .await;

        let error = match state.handle_control_stream(stream).await {
            Ok(never) => match never {},
            Err(error) => error,
        };

        assert_stream_connection_code(error, Code::H3_CLOSED_CRITICAL_STREAM);
        assert_eq!(state.peer_settings.peek(), Some(settings));
        assert_eq!(
            state.peer_goaway.peek(),
            Some(Goaway::new(VarInt::from_u32(9)))
        );
    }

    #[tokio::test]
    async fn control_stream_rejects_non_settings_first_frame_and_duplicate_settings() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        let error = match state
            .handle_control_stream(stream_reader_from_frames([goaway_frame(1).await]).await)
            .await
        {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_stream_connection_code(error, Code::H3_MISSING_SETTINGS);

        let state = DHttpState::new(Arc::new(Settings::default()));
        let settings = Settings::default();
        let error = match state
            .handle_control_stream(
                stream_reader_from_frames([
                    settings_frame(&settings).await,
                    settings_frame(&settings).await,
                ])
                .await,
            )
            .await
        {
            Ok(never) => match never {},
            Err(error) => error,
        };
        assert_stream_connection_code(error, Code::H3_FRAME_UNEXPECTED);
    }

    #[tokio::test]
    async fn peer_goaway_covers_resolves_immediately_when_already_covered() {
        let state = DHttpState::new(Arc::new(Settings::default()));
        let goaway = Goaway::new(VarInt::from_u32(8));
        state
            .apply_peer_goaway(goaway)
            .expect("peer goaway should be accepted");

        let observed = state.peer_goaway_covers(VarInt::from_u32(10)).await;
        assert_eq!(observed, goaway);
    }

    #[tokio::test]
    async fn peer_goaway_covers_waits_until_covered_boundary() {
        let state = Arc::new(DHttpState::new(Arc::new(Settings::default())));
        let waiter_state = state.clone();
        let waiter =
            tokio::spawn(
                async move { waiter_state.peer_goaway_covers(VarInt::from_u32(10)).await },
            );

        tokio::task::yield_now().await;
        state
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(12)))
            .expect("non-covering goaway should be accepted");
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        let covering = Goaway::new(VarInt::from_u32(9));
        state
            .apply_peer_goaway(covering)
            .expect("covering goaway should be accepted");

        let observed = timeout(Duration::from_millis(100), waiter)
            .await
            .expect("peer goaway waiter should resolve")
            .expect("join should succeed");
        assert_eq!(observed, covering);
    }

    #[tokio::test]
    async fn peer_goaway_covers_ignores_non_covering_existing_value() {
        let state = Arc::new(DHttpState::new(Arc::new(Settings::default())));
        state
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(20)))
            .expect("non-covering peer goaway should be accepted");

        let waiter_state = state.clone();
        let waiter =
            tokio::spawn(
                async move { waiter_state.peer_goaway_covers(VarInt::from_u32(10)).await },
            );
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        let covering = Goaway::new(VarInt::from_u32(10));
        state
            .apply_peer_goaway(covering)
            .expect("covering peer goaway should be accepted");

        let observed = timeout(Duration::from_millis(100), waiter)
            .await
            .expect("peer goaway waiter should resolve")
            .expect("join should succeed");
        assert_eq!(observed, covering);
    }

    #[tokio::test]
    async fn accept_uni_passes_stream_when_type_cannot_be_decoded() {
        let state = test_connection_state();
        let stream = test_empty_peekable_uni_stream();

        assert!(matches!(
            state.dhttp().accept_uni(stream).await.expect("uni verdict"),
            StreamVerdict::Passed(_)
        ));
    }

    #[tokio::test]
    async fn accept_uni_accepts_first_control_stream_and_rejects_duplicate() {
        let state = test_connection_state();

        let first = test_peekable_uni_stream_with_bytes(&[0x00]).await;
        assert!(matches!(
            state
                .dhttp()
                .accept_uni(first)
                .await
                .expect("first control"),
            StreamVerdict::Accepted
        ));

        let duplicate = test_peekable_uni_stream_with_bytes(&[0x00]).await;
        let error = match state.dhttp().accept_uni(duplicate).await {
            Ok(_) => panic!("duplicate control stream must fail"),
            Err(error) => error,
        };

        assert_stream_connection_code(error, Code::H3_STREAM_CREATION_ERROR);
    }

    #[tokio::test]
    async fn accept_uni_rejects_push_stream_without_max_push_id() {
        let state = test_connection_state();
        let stream = test_peekable_uni_stream_with_bytes(&[0x01]).await;

        let error = match state.dhttp().accept_uni(stream).await {
            Ok(_) => panic!("push stream should exceed push id limit"),
            Err(error) => error,
        };

        assert_stream_connection_code(error, Code::H3_ID_ERROR);
    }

    #[tokio::test]
    async fn accept_uni_accepts_reserved_stream_type() {
        let state = test_connection_state();
        let stream = test_peekable_uni_stream_with_bytes(&[0x21]).await;

        assert!(matches!(
            state
                .dhttp()
                .accept_uni(stream)
                .await
                .expect("reserved stream verdict"),
            StreamVerdict::Accepted
        ));
    }

    #[tokio::test]
    async fn accept_uni_passes_unknown_stream_type() {
        let state = test_connection_state();
        let stream = test_peekable_uni_stream_with_bytes(&[0x02]).await;

        assert!(matches!(
            state
                .dhttp()
                .accept_uni(stream)
                .await
                .expect("unknown stream verdict"),
            StreamVerdict::Passed(_)
        ));
    }

    #[tokio::test]
    async fn accept_bi_passes_stream_when_frame_type_cannot_be_decoded() {
        let state = test_connection_state();
        let stream = test_empty_peekable_bi_stream(0);

        assert!(matches!(
            state
                .dhttp()
                .accept_bi(stream)
                .await
                .expect("empty bidi verdict"),
            StreamVerdict::Passed(_)
        ));
    }

    #[tokio::test]
    async fn accept_bi_routes_known_http3_frame_type() {
        let state = test_connection_state();
        let stream = test_peekable_bi_stream_with_bytes(12, &[0x01]).await;

        assert!(matches!(
            state
                .dhttp()
                .accept_bi(stream)
                .await
                .expect("headers frame verdict"),
            StreamVerdict::Accepted
        ));

        let (mut reader, _writer) = state.dhttp().unresolved_request_streams.receive().await;
        assert_eq!(
            reader.stream_id().await.expect("routed stream id"),
            VarInt::from_u32(12)
        );
    }

    #[tokio::test]
    async fn accept_bi_routes_reserved_http3_frame_type() {
        let state = test_connection_state();
        let stream = test_peekable_bi_stream_with_bytes(16, &[0x21]).await;

        assert!(matches!(
            state
                .dhttp()
                .accept_bi(stream)
                .await
                .expect("reserved frame verdict"),
            StreamVerdict::Accepted
        ));
    }

    #[tokio::test]
    async fn accept_bi_passes_unknown_frame_type() {
        let state = test_connection_state();
        let stream = test_peekable_bi_stream_with_bytes(20, &[0x41]).await;

        assert!(matches!(
            state
                .dhttp()
                .accept_bi(stream)
                .await
                .expect("unknown frame verdict"),
            StreamVerdict::Passed(_)
        ));
    }

    #[tokio::test]
    async fn accept_bi_evicts_oldest_unresolved_stream_when_ring_is_full() {
        let state = test_connection_state();

        for stream_id in 0..=32 {
            let stream = test_peekable_bi_stream_with_bytes(stream_id, &[0x01]).await;
            assert!(matches!(
                state
                    .dhttp()
                    .accept_bi(stream)
                    .await
                    .expect("known frame verdict"),
                StreamVerdict::Accepted
            ));
        }

        let (mut reader, _writer) = state.dhttp().unresolved_request_streams.receive().await;
        assert_eq!(
            reader.stream_id().await.expect("oldest retained stream id"),
            VarInt::from_u32(1)
        );
    }

    #[test]
    fn http3_frame_type_classifier_covers_known_reserved_and_unknown_values() {
        assert!(DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x00)));
        assert!(DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x01)));
        assert!(DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x0d)));
        assert!(DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x21)));
        assert!(DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x40)));
        assert!(!DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x02)));
        assert!(!DHttpProtocol::is_http3_frame_type(VarInt::from_u32(0x41)));
    }

    #[tokio::test]
    async fn protocol_factory_init_opens_uni_and_sets_local_settings() {
        let conn = Arc::new(MockConnection::new());
        conn.enable_stream_ops();
        let mut settings = Settings::default();
        settings.set(EnableConnectProtocol::setting(true));
        let settings = Arc::new(settings);
        let factory = DHttpProtocolFactory::new(settings.clone());

        let protocol = factory.init(&conn).await.expect("protocol init");

        assert_eq!(protocol.local_settings, settings);
        assert_eq!(conn.stream_calls(), vec!["open_uni"]);
    }

    #[tokio::test]
    async fn protocol_factory_init_returns_open_uni_connection_error() {
        let conn = Arc::new(MockConnection::new());
        let factory = DHttpProtocolFactory::default();

        let error = factory
            .init(&conn)
            .await
            .expect_err("open_uni failure should fail init");

        assert!(matches!(error, quic::ConnectionError::Transport { .. }));
        assert_eq!(conn.stream_calls(), vec!["open_uni"]);
    }

    #[test]
    fn connection_state_accessors_return_dhttp_state_values() {
        let state = test_connection_state();
        state
            .dhttp()
            .register_initialized_stream(VarInt::from_u32(4))
            .expect("initialized stream");
        state
            .dhttp()
            .register_accepted_stream(VarInt::from_u32(8))
            .expect("accepted stream");
        state
            .dhttp()
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(12)))
            .expect("peer goaway");

        assert_eq!(state.settings(), Arc::new(Settings::default()));
        assert_eq!(state.max_initialized_stream_id(), Some(VarInt::from_u32(4)));
        assert_eq!(state.max_received_stream_id(), Some(VarInt::from_u32(8)));
        assert_eq!(
            state.peek_peer_goaway(),
            Some(Goaway::new(VarInt::from_u32(12)))
        );
    }

    #[tokio::test]
    async fn peer_settings_resolves_when_settings_already_available() {
        let state = test_connection_state();
        let settings = Arc::new(Settings::default());
        state
            .dhttp()
            .peer_settings
            .set(settings.clone())
            .expect("set peer settings");

        let observed = state
            .peer_settings()
            .await
            .expect("peer settings should resolve");

        assert_eq!(observed, settings);
    }

    #[tokio::test]
    async fn peer_settings_resolves_to_connection_error_when_settings_never_arrive() {
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));
        quic.set_terminal_error(test_transport_error("peer settings closed"));

        let error = timeout(Duration::from_millis(100), state.peer_settings())
            .await
            .expect("peer settings should resolve on connection close")
            .expect_err("connection closure should yield an error");

        assert_transport_error_reason(&error, "peer settings closed");
    }

    #[tokio::test]
    async fn peer_goawaies_yields_peer_goaway_updates() {
        let state = test_connection_state();
        let goaway = Goaway::new(VarInt::from_u32(18));

        let mut goawaies = pin!(state.peer_goawaies());
        state
            .dhttp()
            .apply_peer_goaway(goaway)
            .expect("peer goaway");

        let observed = timeout(Duration::from_millis(100), goawaies.next())
            .await
            .expect("peer goaway stream should yield")
            .expect("peer goaway stream should not end")
            .expect("peer goaway item should be ok");

        assert_eq!(observed, goaway);
    }

    #[tokio::test]
    async fn peer_goawaies_yields_connection_error_when_connection_closes() {
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));
        quic.set_terminal_error(test_transport_error("peer goawaies closed"));

        let mut goawaies = pin!(state.peer_goawaies());
        let error = timeout(Duration::from_millis(100), goawaies.next())
            .await
            .expect("peer goaway stream should resolve")
            .expect("peer goaway stream should not end")
            .expect_err("connection closure should yield an error");

        assert_transport_error_reason(&error, "peer goawaies closed");
    }

    #[tokio::test]
    async fn goaway_sends_local_goaway_using_max_received_stream_id() {
        let state = test_connection_state();
        state
            .dhttp()
            .register_accepted_stream(VarInt::from_u32(14))
            .expect("accepted stream");

        state.goaway().await.expect("send goaway");

        assert_eq!(
            state.dhttp().local_goaway.peek(),
            Some(Goaway::new(VarInt::from_u32(14)))
        );
    }

    #[tokio::test]
    async fn initial_raw_message_stream_registers_opened_stream() {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));

        let (mut reader, _writer) = state
            .initial_raw_message_stream()
            .await
            .expect("initial stream");

        assert_eq!(
            reader.stream_id().await.expect("stream id"),
            VarInt::from_u32(0)
        );
        assert_eq!(state.max_initialized_stream_id(), Some(VarInt::from_u32(0)));
        assert_eq!(quic.stream_calls(), vec!["open_bi"]);
    }

    #[tokio::test]
    async fn accept_raw_message_stream_returns_connection_error_when_connection_closes() {
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));
        quic.set_terminal_error(test_transport_error("accept raw closed"));

        let error = match state.accept_raw_message_stream().await {
            Ok(_) => panic!("connection closure should stop raw message acceptance"),
            Err(error) => error,
        };
        let AcceptRawMessageStreamError::Connection { source } = error else {
            panic!("expected connection error");
        };

        assert_transport_error_reason(&source, "accept raw closed");
    }

    #[tokio::test]
    async fn initial_raw_message_stream_rejects_when_peer_goaway_latched() {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic, Arc::new(protocols));
        state
            .dhttp()
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(0)))
            .expect("peer goaway");

        let error = match state.initial_raw_message_stream().await {
            Ok(_) => panic!("peer goaway should reject initialized stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            InitialRawMessageStreamError::Goaway {
                source: ConnectionGoaway::Peer
            }
        ));
    }

    #[tokio::test]
    async fn inbound_accept_not_blocked_by_peer_goaway_signal() {
        let state = test_connection_state();
        state
            .dhttp()
            .peer_goaway
            .set(Goaway::new(VarInt::from_u32(4)));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(6));

        let (mut reader, _writer) = state
            .accept_raw_message_stream()
            .await
            .expect("peer goaway must not hard-stop inbound accept");

        assert_eq!(
            reader.stream_id().await.expect("stream id"),
            VarInt::from_u32(6)
        );
    }

    #[tokio::test]
    async fn inbound_accept_rejects_stream_at_or_above_local_goaway_boundary() {
        let state = test_connection_state();
        state
            .dhttp()
            .local_goaway
            .set(Goaway::new(VarInt::from_u32(9)));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(9));

        let error = state
            .accept_raw_message_stream()
            .await
            .err()
            .expect("stream at local goaway boundary should be rejected");

        assert!(matches!(
            error,
            AcceptRawMessageStreamError::Goaway {
                source: ConnectionGoaway::Local
            }
        ));
    }

    #[tokio::test]
    async fn inbound_accept_allows_stream_below_local_goaway_boundary() {
        let state = test_connection_state();
        state
            .dhttp()
            .local_goaway
            .set(Goaway::new(VarInt::from_u32(7)));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(3));

        let (mut reader, _writer) = state
            .accept_raw_message_stream()
            .await
            .expect("stream below local goaway boundary should be accepted");

        assert_eq!(
            reader.stream_id().await.expect("stream id"),
            VarInt::from_u32(3)
        );
    }

    #[tokio::test]
    async fn queued_streams_are_drained_with_local_goaway_boundary_split() {
        let state = test_connection_state();
        state
            .dhttp()
            .local_goaway
            .set(Goaway::new(VarInt::from_u32(6)));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(4));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(8));

        let (mut reader, _writer) = state
            .accept_raw_message_stream()
            .await
            .expect("stream below boundary should be delivered first");
        assert_eq!(
            reader.stream_id().await.expect("stream id"),
            VarInt::from_u32(4)
        );

        let error = state
            .accept_raw_message_stream()
            .await
            .err()
            .expect("stream at or above boundary should be rejected");

        assert!(matches!(
            error,
            AcceptRawMessageStreamError::Goaway {
                source: ConnectionGoaway::Local
            }
        ));
    }

    #[tokio::test]
    async fn latched_local_goaway_after_watcher_creation_still_enforces_boundary() {
        let state = test_connection_state();
        let wait_state = state.clone();

        let accept_task = tokio::spawn(async move { wait_state.accept_raw_message_stream().await });
        tokio::task::yield_now().await;
        state
            .dhttp()
            .local_goaway
            .set(Goaway::new(VarInt::from_u32(10)));
        _ = state
            .dhttp()
            .unresolved_request_streams
            .send(test_erased_streams(10));

        let error = timeout(Duration::from_millis(100), accept_task)
            .await
            .expect("accept task should resolve")
            .expect("join should succeed")
            .err()
            .expect("boundary should apply even if goaway was set after accept started");

        assert!(matches!(
            error,
            AcceptRawMessageStreamError::Goaway {
                source: ConnectionGoaway::Local
            }
        ));
    }
}

impl DHttpState {
    /// Creates a new `DHttpLayerState` with the given local settings.
    fn new(local_settings: Arc<Settings>) -> Self {
        Self {
            local_settings,
            peer_settings: SetOnce::new(),
            local_goaway: Watch::new(),
            peer_goaway: Watch::new(),
            max_initialized_stream_id: Watch::new(),
            max_received_stream_id: Watch::new(),
        }
    }

    pub(crate) fn begin_local_goaway(&self) -> Goaway {
        let mut local_goaway = self.local_goaway.lock();
        let max_received_stream_id = self.max_received_stream_id.lock();

        let max_received_stream_id = max_received_stream_id
            .get()
            .copied()
            .unwrap_or(VarInt::from_u32(0));

        let goaway = Goaway::new(max_received_stream_id);
        local_goaway.set(goaway);

        goaway
    }

    pub(crate) fn apply_peer_goaway(&self, goaway: Goaway) -> Result<(), StreamError> {
        let mut peer_goaway = self.peer_goaway.lock();
        if let Some(previous_goaway) = peer_goaway.get().copied()
            && goaway.stream_id() > previous_goaway.stream_id()
        {
            return Err(H3IdError::GoawayStreamIdOrdering.into());
        }

        tracing::debug!(
            previous_stream_id = ?peer_goaway.get().map(|item| item.stream_id()),
            new_stream_id = ?goaway.stream_id(),
            "Received peer GOAWAY"
        );
        peer_goaway.set(goaway);
        Ok(())
    }

    async fn handle_control_stream<S: quic::ReadStream>(
        &self,
        stream: StreamReader<S>,
    ) -> Result<Never, StreamError> {
        let mut control_frame_stream = pin!(FrameStream::new(stream));

        // First frame MUST be SETTINGS.
        let mut settings_frame = control_frame_stream
            .as_mut()
            .next_frame()
            .await
            .ok_or(H3CriticalStreamClosed::Control)??;
        if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
            return Err(H3MissingSettings.into());
        }
        let settings = Arc::new(settings_frame.decode_one::<Settings>().await?);
        tracing::debug!(?settings, "received remote settings");
        self.peer_settings
            .set(settings)
            .expect("handle control task set once");

        loop {
            let mut frame = control_frame_stream
                .as_mut()
                .next_unreserved_frame()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;
            if frame.r#type() == Frame::SETTINGS_FRAME_TYPE {
                return Err(H3FrameUnexpected::DuplicateSettings.into());
            } else if frame.r#type() == Frame::GOAWAY_FRAME_TYPE {
                let goaway = frame.decode_one::<Goaway>().await?;
                self.apply_peer_goaway(goaway)?;
            } else {
                // unknown frame type
            }
        }
    }

    pub(crate) fn register_initialized_stream(
        &self,
        stream_id: VarInt,
    ) -> Result<(), ConnectionGoaway> {
        let peer_goaway = self.peer_goaway.lock();
        if peer_goaway.get().is_some() {
            return Err(ConnectionGoaway::Peer);
        }

        let mut max_initialized_stream_id = self.max_initialized_stream_id.lock();
        max_initialized_stream_id.set(
            max_initialized_stream_id
                .get()
                .map_or(stream_id, |current| *current.max(&stream_id)),
        );

        Ok(())
    }

    pub(crate) fn register_accepted_stream(
        &self,
        stream_id: VarInt,
    ) -> Result<(), ConnectionGoaway> {
        let local_goaway = self.local_goaway.lock();
        if let Some(goaway) = local_goaway.get().copied()
            && stream_id >= goaway.stream_id()
        {
            return Err(ConnectionGoaway::Local);
        }
        let mut max_received_stream_id = self.max_received_stream_id.lock();
        max_received_stream_id.set(
            max_received_stream_id
                .get()
                .map_or(stream_id, |current| *current.max(&stream_id)),
        );

        Ok(())
    }

    pub(crate) async fn peer_goaway_covers(&self, stream_id: VarInt) -> Goaway {
        if let Some(goaway) = self.peer_goaway.peek()
            && stream_id >= goaway.stream_id()
        {
            return goaway;
        }

        let effective_peer_goaway = self
            .peer_goaway
            .watch()
            .filter(move |goaway| future::ready(stream_id >= goaway.stream_id()));
        let mut effective_peer_goaway = pin!(effective_peer_goaway.fuse());
        effective_peer_goaway.select_next_some().await
    }
}

type FrameSink = Feed<BoxSink<'static, Frame<BufList>, StreamError>, Frame<BufList>>;

/// DHTTP/3 protocol layer.
///
/// Implements [`Protocol`] to handle HTTP/3 stream identification and
/// initialization. This layer recognizes HTTP/3 unidirectional stream types
/// (control, push, reserved) and accepts all
/// bidirectional streams as HTTP/3 request streams.
pub struct DHttpProtocol {
    /// DHTTP/3 protocol state.
    pub state: Arc<DHttpState>,

    /// Type-erased connection for lifecycle and stream operations.
    pub connection: Arc<dyn quic::DynConnection>,

    /// Control stream frame sink
    pub control_stream: AsyncMutex<FrameSink>,

    handle_control_stream: SetOnce<AbortOnDropHandle<()>>,

    unresolved_request_streams: RingChannel<(
        StreamReader<guard::GuardQuicReader>,
        SinkWriter<guard::GuardQuicWriter>,
    )>,
}

impl ops::Deref for DHttpProtocol {
    type Target = Arc<DHttpState>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl std::fmt::Debug for DHttpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DHttpLayer")
            .field("state", &self.state)
            .field("control_stream", &"...")
            .finish()
    }
}

impl DHttpProtocol {
    pub async fn max_unresolved_request_streams(&self) -> usize {
        self.unresolved_request_streams.capacity()
    }

    async fn accept_uni(
        &self,
        mut stream: BoxPeekableStreamReader,
    ) -> Result<StreamVerdict<BoxPeekableStreamReader>, StreamError> {
        let Ok(stream_type) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        let raw = stream_type.into_inner();

        if stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE {
            let state = self.state.clone();
            let connection = self.connection.clone();

            let init_handle_control_task = || {
                let handle_control = async move {
                    tokio::select! {
                        biased;
                        Err(stream_error) = state.handle_control_stream(stream.into_stream_reader()) => {
                            // Only connection-scope errors have a meaningful
                            // side effect (close the connection). Stream-scope
                            // errors on the control stream are themselves a
                            // connection-level violation that the protocol code
                            // already signals via `H3_CLOSED_CRITICAL_STREAM`,
                            // so there is nothing extra to do here.
                            if let StreamError::Connection { source } = stream_error {
                                connection.handle_connection_error(source).await;
                            }
                        }
                        _connection_error = connection.closed() => {
                            // Connection error occurred, likely due to shutdown. Just exit the task.
                        }
                    }
                };
                AbortOnDropHandle::new(tokio::spawn(handle_control.in_current_span()))
            };

            if self
                .handle_control_stream
                .set_with(init_handle_control_task)
                .is_err()
            {
                return Err(H3StreamCreationError::DuplicateControlStream.into());
            }
            Ok(StreamVerdict::Accepted)
        } else if stream_type == UnidirectionalStream::PUSH_STREAM_TYPE {
            // The push ID space begins at zero and ends at a maximum value set by
            // the MAX_PUSH_ID frame. In particular, a server is not able to push
            // until after the client sends a MAX_PUSH_ID frame. A client sends
            // MAX_PUSH_ID frames to control the number of pushes that a server can
            // promise. A server SHOULD use push IDs sequentially, beginning from
            // zero. A client MUST treat receipt of a push stream as a connection
            // error of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or
            // when the stream references a push ID that is greater than the maximum
            // push ID.
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#section-4.6-3
            Err(H3IdError::PushIdExceedsLimit.into())
        } else if raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f) {
            // Reserved unidirectional stream types are accepted but ignored.
            stream.stop(Code::H3_NO_ERROR.into_inner()).await?;
            Ok(StreamVerdict::Accepted)
        } else {
            // Not an HTTP/3 stream type. Reset cursor so the next layer
            // can re-read the stream type VarInt.
            Ok(StreamVerdict::Passed(stream))
        }
    }

    async fn accept_bi(
        &self,
        (mut reader, writer): (BoxPeekableStreamReader, BoxStreamWriter),
    ) -> Result<StreamVerdict<(BoxPeekableStreamReader, BoxStreamWriter)>, StreamError> {
        // HTTP/3 bidirectional streams are request streams (RFC 9114 §4.1).
        // The first bytes on a request stream are HTTP/3 frames, starting with
        // a frame type VarInt. We peek the first VarInt to determine whether
        // this stream belongs to HTTP/3 or to another protocol (e.g.,
        // WebTransport uses signal value 0x41 which is NOT a valid HTTP/3
        // frame type).
        //
        // Known HTTP/3 frame types and reserved types (0x1f*N+0x21) are
        // accepted. Note that reserved frames MAY appear before HEADERS on a
        // request stream (RFC 9114 §7.2.8). Everything else is passed to the
        // next protocol layer.
        let frame_type = match reader.decode_one::<VarInt>().await {
            Ok(v) => v,
            Err(_) => {
                // Stream closed or error before we could read a frame type.
                // Cannot determine protocol — pass to the next layer.
                return Ok(StreamVerdict::Passed((reader, writer)));
            }
        };

        if Self::is_http3_frame_type(frame_type) {
            // This is an HTTP/3 request stream. Reset the peek cursor so the
            // frame type can be re-read by FrameStream during request processing.
            Pin::new(&mut reader).reset();
            let reader = reader
                .into_stream_reader()
                .map_stream(guard::GuardQuicReader::new);
            let writer = writer.map_sink(guard::GuardQuicWriter::new);
            let item = (reader, writer);
            if let Some(mut unresolved) = self.unresolved_request_streams.send(item) {
                // Ring channel is full — reject the oldest unresolved request.
                let code = Code::H3_REQUEST_REJECTED.into_inner();
                _ = tokio::join!(unresolved.0.stop(code), unresolved.1.reset(code));
            }
            Ok(StreamVerdict::Accepted)
        } else {
            // Not an HTTP/3 frame type. Reset cursor so the next protocol
            // layer can re-read the first bytes.
            Ok(StreamVerdict::Passed((reader, writer)))
        }
    }

    /// Returns `true` if the given VarInt is a known HTTP/3 frame type or a
    /// reserved frame type (RFC 9114 §7.2.8).
    ///
    /// Known frame types (RFC 9114 §11.1):
    /// - 0x00 DATA, 0x01 HEADERS, 0x03 CANCEL_PUSH, 0x04 SETTINGS,
    ///   0x05 PUSH_PROMISE, 0x07 GOAWAY, 0x0d MAX_PUSH_ID
    ///
    /// Reserved: 0x1f * N + 0x21 for non-negative integer N
    const fn is_http3_frame_type(frame_type: VarInt) -> bool {
        let raw = frame_type.into_inner();
        matches!(raw, 0x00 | 0x01 | 0x03 | 0x04 | 0x05 | 0x07 | 0x0d)
            || (raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f))
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(connection: Arc<dyn quic::DynConnection>) -> Self {
        let sink: BoxSink<'static, Frame<BufList>, StreamError> =
            Box::pin(futures::sink::drain().sink_map_err(|never| match never {}));

        Self {
            state: Arc::new(DHttpState::new(Arc::new(Settings::default()))),
            connection,
            control_stream: AsyncMutex::new(Feed::new(sink)),
            handle_control_stream: SetOnce::new(),
            unresolved_request_streams: RingChannel::new(32),
        }
    }
}

impl Protocol for DHttpProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: BoxPeekableStreamReader,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableStreamReader>, StreamError>> {
        Box::pin(self.accept_uni(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: (BoxPeekableStreamReader, BoxStreamWriter),
    ) -> BoxFuture<'a, Result<StreamVerdict<(BoxPeekableStreamReader, BoxStreamWriter)>, StreamError>>
    {
        Box::pin(self.accept_bi(stream))
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct DHttpProtocolFactory {
    local_settings: Arc<Settings>,
}

impl fmt::Display for DHttpProtocolFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DHTTP/3")
    }
}

impl DHttpProtocolFactory {
    pub fn new(local_settings: Arc<Settings>) -> Self {
        Self { local_settings }
    }

    pub async fn init<C: quic::Connection>(
        &self,
        conn: &Arc<C>,
    ) -> Result<DHttpProtocol, quic::ConnectionError> {
        let uni_stream = SinkWriter::new(Box::pin(conn.open_uni().await?));
        let mut control_stream = match UnidirectionalStream::initial_control_stream(uni_stream)
            .await
        {
            Ok(stream) => {
                let control_frame_sink = stream.into_encode_sink().sink_map_err(
                    |error: quic::StreamError| match error {
                        quic::StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
                        quic_stream_error => quic_stream_error.into(),
                    },
                );
                Feed::new(Box::pin(control_frame_sink) as BoxSink<_, _>)
            }
            Err(stream_error) => {
                if let StreamError::Connection { source } = stream_error {
                    return Err(conn.handle_connection_error(source).await);
                }
                return Err(conn.closed().await);
            }
        };

        let Ok(settings_frame) = BufList::new().encode(self.local_settings.as_ref()).await;
        match control_stream.send(settings_frame).await {
            Ok(()) => (),
            Err(stream_error) => {
                if let StreamError::Connection { source } = stream_error {
                    return Err(conn.handle_connection_error(source).await);
                }
                return Err(conn.closed().await);
            }
        }

        let connection: Arc<dyn quic::DynConnection> = conn.clone();

        Ok(DHttpProtocol {
            state: Arc::new(DHttpState::new(self.local_settings.clone())),
            connection,
            control_stream: AsyncMutex::new(control_stream),
            handle_control_stream: SetOnce::new(),
            unresolved_request_streams: RingChannel::new(32), // TODO: configurable capacity
        })
    }
}

impl<C: quic::Connection> ProductProtocol<C> for DHttpProtocolFactory {
    type Protocol = DHttpProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        _ = layers;
        Box::pin(self.init(conn))
    }
}

impl<C: ?Sized> ConnectionState<C> {
    #[doc(alias = "http")]
    pub fn dhttp(&self) -> &DHttpProtocol {
        self.protocol::<DHttpProtocol>()
            .expect("DHttpProtocol is always initialized by ConnectionBuilder")
    }

    pub fn settings(&self) -> Arc<Settings> {
        self.dhttp().local_settings.clone()
    }

    pub fn max_received_stream_id(&self) -> Option<VarInt> {
        self.dhttp().max_received_stream_id.peek()
    }

    pub fn max_initialized_stream_id(&self) -> Option<VarInt> {
        self.dhttp().max_initialized_stream_id.peek()
    }

    pub fn peek_peer_goaway(&self) -> Option<Goaway> {
        self.dhttp().peer_goaway.peek()
    }
}

impl<C: quic::DynLifecycle + Sync> ConnectionState<C> {
    /// Per RFC 9114 §3.2/§6.2.1, SETTINGS MUST be the first frame on the
    /// control stream; a connection that closes before SETTINGS arrives is in
    /// error. Races [`Self::closed`] so callers cannot hang on a frame that
    /// will never come, mirroring [`Self::peer_goawaies`].
    pub async fn peer_settings(&self) -> Result<Arc<Settings>, quic::ConnectionError> {
        let settings = self.dhttp().peer_settings.get();
        let closed = self.closed();
        match future::select(pin!(settings), pin!(closed)).await {
            future::Either::Left((Some(settings), _)) => Ok(settings),
            future::Either::Left((None, closed)) => Err(closed.await),
            future::Either::Right((error, _)) => Err(error),
        }
    }

    pub fn peer_goawaies(
        &self,
    ) -> impl FusedStream<Item = Result<Goaway, quic::ConnectionError>> + Send + use<'_, C> {
        stream::select(
            self.dhttp().peer_goaway.watch().map(Ok),
            self.closed().map(Err).into_stream(),
        )
    }

    pub async fn goaway(&self) -> Result<(), quic::ConnectionError> {
        let send_goaway = async {
            let dhttp = self.dhttp();
            let mut control_stream = dhttp.control_stream.lock().await;
            let Ok(goaway_frame) = BufList::new().encode(dhttp.begin_local_goaway()).await;
            control_stream.send(goaway_frame).await
        };

        if let Err(stream_error) = send_goaway.await {
            if let StreamError::Connection { source } = stream_error {
                return Err(self.quic().handle_connection_error(source).await);
            }
            return Err(self.closed().await);
        }

        Ok(())
    }
}

#[derive(Debug, Snafu, Clone)]
pub enum InitialRawMessageStreamError {
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(transparent)]
    ResponseStream { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum AcceptRawMessageStreamError {
    #[snafu(transparent)]
    Connection { source: quic::ConnectionError },
    #[snafu(transparent)]
    RequestStream { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
}

impl<C: quic::Lifecycle + quic::ManageStream + Send + Sync> ConnectionState<C> {
    pub async fn initial_raw_message_stream(
        &self,
    ) -> Result<
        (
            StreamReader<guard::GuardQuicReader>,
            SinkWriter<guard::GuardQuicWriter>,
        ),
        InitialRawMessageStreamError,
    > {
        let (reader, writer) = self.open_bi().await?;
        let (mut reader, writer) = (Box::pin(reader), Box::pin(writer));
        self.dhttp()
            .register_initialized_stream(reader.stream_id().await?)?;
        Ok((
            StreamReader::new(guard::GuardQuicReader::new(reader)),
            SinkWriter::new(guard::GuardQuicWriter::new(writer)),
        ))
    }

    pub async fn accept_raw_message_stream(
        &self,
    ) -> Result<
        (
            StreamReader<guard::GuardQuicReader>,
            SinkWriter<guard::GuardQuicWriter>,
        ),
        AcceptRawMessageStreamError,
    > {
        let dhttp = self.dhttp();
        let (mut reader, mut writer) = tokio::select! {
            stream = dhttp.unresolved_request_streams.receive() => stream,
            connection_error = self.closed() => return Err(connection_error.into()),
        };
        let stream_id = reader.stream_id().await?;
        match dhttp.register_accepted_stream(stream_id) {
            Ok(()) => Ok((reader, writer)),
            Err(ConnectionGoaway::Local) => {
                let code = Code::H3_REQUEST_REJECTED.into_inner();
                _ = tokio::join!(reader.stop(code), writer.reset(code));
                Err(ConnectionGoaway::Local.into())
            }
            Err(ConnectionGoaway::Peer) => {
                unreachable!("inbound acceptance is not gated by peer_goaway")
            }
        }
    }
}
