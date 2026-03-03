//! DHTTP/3 protocol layer implementation.
//!
//! [`DHttpLayer`] encapsulates all HTTP/3-specific logic for stream identification
//! and protocol initialization. It implements [`ProtocolLayer`] to participate in
//! the layered stream routing architecture.

use std::{
    pin::{Pin, pin},
    sync::{Arc, Mutex, OnceLock},
};

use futures::{SinkExt, StreamExt, channel::oneshot, future::BoxFuture, stream::FusedStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    buflist::BufList,
    codec::{DecodeExt, Encode, EncodeExt, Feed, SinkWriter, StreamReader},
    connection::{
        ConnectionState, FrameSink, QPackEncoder, StreamError,
        settings::Settings,
        stream::{H3StreamCreationError, UnidirectionalStream},
    },
    error::{Code, H3CriticalStreamClosed, H3FrameUnexpected},
    frame::{Frame, goaway::Goaway},
    layer::{PeekableBiStream, PeekableUniStream, ProtocolLayer, StreamVerdict},
    qpack::BoxSink,
    quic::{self, ConnectionError},
    util::{set_once::SetOnce, watch::Watch},
    varint::VarInt,
};

/// Type alias for a `StreamReader` wrapping a boxed unidirectional read stream.
pub type UniStreamReader = StreamReader<Pin<Box<dyn crate::quic::ReadStream + Send>>>;

/// Internal shared state for the DHTTP/3 layer.
///
/// This struct holds the HTTP/3-specific protocol state that is shared
/// between the layer and its background tasks.
#[derive(Debug)]
pub struct DHttpLayerState {
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

impl DHttpLayerState {
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
}

/// DHTTP/3 protocol layer.
///
/// Implements [`ProtocolLayer`] to handle HTTP/3 stream identification and
/// initialization. This layer recognizes HTTP/3 unidirectional stream types
/// (control, push, reserved) and accepts all
/// bidirectional streams as HTTP/3 request streams.
pub struct DHttpLayer {
    /// Shared HTTP/3 protocol state.
    state: Arc<DHttpLayerState>,

    /// Control stream frame sink, set once during connection initialization.
    control_stream: OnceLock<AsyncMutex<FrameSink>>,

    /// Oneshot sender for dispatching the peer's control stream.
    control_stream_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,

    /// Erased connection state for peer goaway / error delegation.
    conn_state: OnceLock<Arc<ConnectionState<dyn quic::Close + Send + Sync>>>,
}

impl std::fmt::Debug for DHttpLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DHttpLayer")
            .field("state", &self.state)
            .field("control_stream", &"...")
            .finish()
    }
}

impl DHttpLayer {
    /// Creates a new `DHttpLayer` with the given local settings.
    pub fn new(local_settings: Arc<Settings>) -> Self {
        Self {
            state: Arc::new(DHttpLayerState::new(local_settings)),
            control_stream: OnceLock::new(),
            control_stream_tx: Mutex::new(None),
            conn_state: OnceLock::new(),
        }
    }

    /// Creates a new `DHttpLayer` with default settings.
    pub fn with_default_settings() -> Self {
        Self::new(Arc::new(Settings::default()))
    }

    /// Returns a reference to the shared state.
    #[must_use]
    pub fn state(&self) -> &Arc<DHttpLayerState> {
        &self.state
    }

    /// Returns the local settings.
    #[must_use]
    pub fn local_settings(&self) -> &Arc<Settings> {
        &self.state.local_settings
    }

    /// Returns the peer settings if received.
    #[must_use]
    pub fn peer_settings(&self) -> Option<Arc<Settings>> {
        self.state.peer_settings.peek()
    }

    /// Returns the current local GOAWAY if set.
    #[must_use]
    pub fn local_goaway(&self) -> Option<Goaway> {
        self.state.local_goaway.peek()
    }

    /// Returns the current peer GOAWAY if set.
    #[must_use]
    pub fn peer_goaway(&self) -> Option<Goaway> {
        self.state.peer_goaway.peek()
    }

    /// Returns a stream of peer GOAWAY frames, delegating to the stored ConnectionState.
    ///
    /// Returns `None` if the layer has not been initialized via `init_dhttp()`.
    pub fn peer_goawaies(
        &self,
    ) -> Option<impl FusedStream<Item = Result<Goaway, quic::ConnectionError>> + use<>> {
        self.conn_state.get().map(|state| state.peer_goawaies())
    }

    /// Handles a stream-level error, delegating to the stored ConnectionState.
    ///
    /// Returns `None` if the layer has not been initialized via `init_dhttp()`.
    pub async fn handle_error(&self, error: StreamError) -> Option<quic::StreamError> {
        match self.conn_state.get() {
            Some(state) => Some(state.handle_error(error).await),
            None => None,
        }
    }
    /// Returns the control stream frame sink, if initialized.
    #[must_use]
    pub fn control_stream(&self) -> Option<&AsyncMutex<FrameSink>> {
        self.control_stream.get()
    }

    /// Sets the control stream frame sink. Returns `Err` if already set.
    pub fn set_control_stream(
        &self,
        sink: AsyncMutex<FrameSink>,
    ) -> Result<(), AsyncMutex<FrameSink>> {
        self.control_stream.set(sink)
    }
    /// Installs the oneshot dispatch channel for the incoming peer control stream.
    ///
    /// This channel is used by `accept_uni` to dispatch the accepted control
    /// stream to the appropriate handler.
    pub fn set_control_dispatch_channel(&self, control_tx: oneshot::Sender<UniStreamReader>) {
        *self
            .control_stream_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(control_tx);
    }

    /// Dispatches an accepted unidirectional stream to the appropriate handler
    /// based on its stream type.
    ///
    /// The stream type VarInt has already been consumed from the stream.
    fn dispatch_uni_stream(
        &self,
        stream_type: VarInt,
        stream: UniStreamReader,
    ) -> Result<(), StreamError> {
        if stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE {
            let tx = self
                .control_stream_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .ok_or(H3StreamCreationError::DuplicateControlStream)?;
            let _ = tx.send(stream);
        }
        // Push streams (0x01) and reserved streams are accepted but not dispatched.
        // Reserved streams have no semantics per RFC 9114 §6.2.3.
        // Push streams are currently not supported (TODO).
        Ok(())
    }

    /// Initializes the DHTTP/3 layer with real protocol logic.
    ///
    /// Opens the outgoing control stream, sends the SETTINGS frame, stores
    /// the control stream, sets up the control dispatch channel, and spawns
    /// the `handle_control` background task for processing incoming control frames.
    ///
    /// Returns a handle to the background task for supervisor management.
    pub async fn init_dhttp<C: quic::Connection>(
        &self,
        state: &Arc<ConnectionState<C>>,
        qpack_encoder: Arc<QPackEncoder>,
    ) -> Result<AbortOnDropHandle<Result<(), StreamError>>, ConnectionError> {
        // Store erased connection state so ReadStream/WriteStream can delegate through us.
        let erased: Arc<ConnectionState<dyn quic::Close + Send + Sync>> = state.clone();
        let _ = self.conn_state.set(erased);

        // Set up dispatch channel for incoming peer control stream
        let (control_stream_tx, control_stream_rx) = oneshot::channel();
        self.set_control_dispatch_channel(control_stream_tx);

        // Open outgoing control stream
        let uni_stream = SinkWriter::new(Box::pin(state.open_uni().await?));
        // Send control stream type header
        let mut control_stream = match UnidirectionalStream::new_control_stream(uni_stream).await {
            Ok(control_stream) => {
                let control_frame_sink = control_stream.into_encode_sink().sink_map_err(
                    |stream_error| match stream_error {
                        quic::StreamError::Reset { .. } => H3CriticalStreamClosed::Control.into(),
                        stream_error => stream_error.into(),
                    },
                );
                Feed::new(Box::pin(control_frame_sink) as BoxSink<_, _>)
            }
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        };

        // Send SETTINGS frame on the control stream
        let Ok(settings_frame) = BufList::new().encode(state.local_settings()).await;
        match control_stream.send(settings_frame).await {
            Ok(()) => (),
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        }
        match control_stream.flush().await {
            Ok(()) => (),
            Err(error) => {
                state.handle_error(error).await;
                return Err(state.error().await);
            }
        }

        // Store control stream in self
        let _ = self.set_control_stream(AsyncMutex::new(control_stream));

        // Spawn handle_control background task
        let conn_state = state.clone();
        let handle_control = async move {
            let control_stream = tokio::select! {
                Ok(control_stream) = control_stream_rx => control_stream,
                _error = conn_state.error() => return Ok::<_, StreamError>(()),
            };
            let mut control_frame_stream = pin!(control_stream.into_decode_stream::<Frame<_>, _>());

            // First frame MUST be SETTINGS.
            let mut settings_frame = control_frame_stream
                .next()
                .await
                .ok_or(H3CriticalStreamClosed::Control)??;
            if settings_frame.r#type() != Frame::SETTINGS_FRAME_TYPE {
                return Err(Code::H3_MISSING_SETTINGS.into());
            }
            let settings = Arc::new(settings_frame.decode_one::<Settings>().await?);
            tracing::debug!("Remote settings applied: {:?}", settings);
            conn_state
                .peer_settings
                .set(settings.clone())
                .map_err(|_| Code::H3_FRAME_UNEXPECTED)?;
            qpack_encoder.apply_settings(settings.clone()).await;

            loop {
                let mut frame = control_frame_stream
                    .next()
                    .await
                    .ok_or(H3CriticalStreamClosed::Control)??;

                if frame.r#type() == Frame::SETTINGS_FRAME_TYPE {
                    return Err(H3FrameUnexpected::DuplicateSettings.into());
                } else if frame.r#type() == Frame::GOAWAY_FRAME_TYPE {
                    let goaway = frame.decode_one::<Goaway>().await?;
                    if let Some(previous_goaway) = conn_state.peer_goaway.peek()
                        && goaway.stream_id() > previous_goaway.stream_id()
                    {
                        return Err(Code::H3_ID_ERROR.into());
                    }
                    _ = conn_state.peer_goaway.set(goaway)
                } else if frame.is_reversed_frame() {
                    continue;
                }
            }
        };
        let handle_control_task =
            AbortOnDropHandle::new(tokio::spawn(handle_control.in_current_span()));

        Ok(handle_control_task)
    }
}

impl<C: Send + Sync + 'static> ProtocolLayer<C> for DHttpLayer {
    fn name(&self) -> &'static str {
        "dhttp3"
    }

    fn init(&self, _quic: &C) -> BoxFuture<'_, Result<(), ConnectionError>> {
        // Initialization is done via `init_dhttp()` called from `Connection::new()`.
        Box::pin(async { Ok(()) })
    }

    fn accept_uni(
        &self,
        mut stream: PeekableUniStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableUniStream>, ConnectionError>> {
        Box::pin(async move {
            // Use the standard codec pattern to decode the stream type VarInt.
            // decode_one::<VarInt>() uses AsyncRead internally, which calls
            // poll_bytes on the PeekableStreamReader, advancing the cursor.
            let stream_type: VarInt = match stream.decode_one::<VarInt>().await {
                Ok(v) => v,
                Err(_) => {
                    // Failed to decode (stream exhausted or malformed).
                    // Reset cursor and pass through to the next layer.
                    stream.reset();
                    return Ok(StreamVerdict::Passed(stream));
                }
            };

            // Check if the decoded stream type is a known HTTP/3 type.
            let raw = stream_type.into_inner();
            let is_h3_type = stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE
                || stream_type == UnidirectionalStream::PUSH_STREAM_TYPE
                || (raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f));

            if is_h3_type {
                // Commit the peeked bytes (the VarInt) — makes the read permanent.
                stream.commit();
                let stream_reader = stream.into_stream_reader();

                // Dispatch the stream to the appropriate handler.
                self.dispatch_uni_stream(stream_type, stream_reader)
                    .map_err(|e| -> ConnectionError {
                        match e {
                            StreamError::Code { source } => crate::quic::TransportSnafu {
                                kind: source.code().value(),
                                frame_type: VarInt::from_u32(0),
                                reason: source.to_string().leak() as &'static str,
                            }
                            .build()
                            .into(),
                            StreamError::Quic { source } => match source {
                                quic::StreamError::Connection { source } => source,
                                quic::StreamError::Reset { .. } => crate::quic::TransportSnafu {
                                    kind: VarInt::from_u32(0),
                                    frame_type: VarInt::from_u32(0),
                                    reason: "stream reset during dispatch",
                                }
                                .build()
                                .into(),
                            },
                        }
                    })?;

                Ok(StreamVerdict::Accepted)
            } else {
                // Not an HTTP/3 stream type. Reset cursor so the next layer
                // can re-read the stream type VarInt.
                stream.reset();
                Ok(StreamVerdict::Passed(stream))
            }
        })
    }

    fn accept_bi(
        &self,
        _stream: PeekableBiStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableBiStream>, ConnectionError>> {
        // All bidirectional streams in HTTP/3 are request streams.
        // Accept them unconditionally.
        Box::pin(async { Ok(StreamVerdict::Accepted) })
    }
}

#[cfg(test)]
mod tests {
    use std::{any::Any, pin::Pin, sync::Arc};

    use bytes::Bytes;

    use super::DHttpLayer;
    use crate::{
        codec::{StreamReader, peekable::PeekableStreamReader},
        connection::settings::Settings,
        layer::{PeekableUniStream, ProtocolLayer, StreamVerdict},
        varint::VarInt,
    };

    /// Helper: create a PeekableUniStream from raw byte chunks.
    fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> PeekableUniStream {
        let chunks_owned: Vec<Bytes> = chunks.into_iter().map(Bytes::from_static).collect();
        // We need a Pin<Box<dyn quic::ReadStream + Send>>. Our mock stream
        // needs to implement GetStreamId, StopStream, Stream, and Any.
        // Use the mock_stream_pair from quic::test for proper streams,
        // but for simpler unit tests we can use a custom approach.

        // For these tests, we'll construct the PeekableStreamReader directly
        // from a StreamReader over a stream that yields the right types.
        // PeekableUniStream = PeekableStreamReader<Pin<Box<dyn ReadStream + Send>>>
        // This requires the inner stream to implement ReadStream which needs
        // GetStreamId + StopStream + Stream<Item=Result<Bytes, StreamError>> + Send + Any.

        // Use mock_stream_pair and feed data into it.
        let (reader, mut writer) = crate::quic::test::mock_stream_pair(VarInt::from_u32(0));

        // Spawn a task to feed data into the writer
        tokio::spawn(async move {
            use futures::SinkExt;
            for chunk in chunks_owned {
                if writer.send(chunk).await.is_err() {
                    break;
                }
            }
            // Close the writer
            let _ = writer.close().await;
        });

        let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
        let stream_reader = StreamReader::new(boxed_reader);
        PeekableStreamReader::new(stream_reader)
    }

    /// Helper: create a PeekableBiStream from raw byte chunks for the read side.
    fn peekable_bi_from_chunks(read_chunks: Vec<&'static [u8]>) -> crate::layer::PeekableBiStream {
        let (reader, mut writer_feed) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));
        let (_, write_side) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));

        let chunks_owned: Vec<Bytes> = read_chunks.into_iter().map(Bytes::from_static).collect();
        tokio::spawn(async move {
            use futures::SinkExt;
            for chunk in chunks_owned {
                if writer_feed.send(chunk).await.is_err() {
                    break;
                }
            }
            let _ = writer_feed.close().await;
        });

        let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
        let boxed_writer: Pin<Box<dyn crate::quic::WriteStream + Send>> = Box::pin(write_side);
        let stream_reader = StreamReader::new(boxed_reader);
        let peekable = PeekableStreamReader::new(stream_reader);
        (peekable, boxed_writer)
    }

    #[test]
    fn test_dhttp_layer_new() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();
        assert_eq!(ProtocolLayer::<()>::name(&layer), "dhttp3");
        assert!(layer.peer_settings().is_none());
        assert!(layer.local_goaway().is_none());
        assert!(layer.peer_goaway().is_none());
    }

    #[test]
    fn test_dhttp_layer_new_with_settings() {
        let _guard = tracing_subscriber::fmt::try_init();
        let settings = Arc::new(Settings::default());
        let layer = DHttpLayer::new(settings.clone());
        assert_eq!(ProtocolLayer::<()>::name(&layer), "dhttp3");
        assert!(std::sync::Arc::ptr_eq(layer.local_settings(), &settings));
    }

    #[tokio::test]
    async fn test_accept_uni_control_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        // Install dispatch channel so accept_uni can dispatch
        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        layer.set_control_dispatch_channel(control_tx);

        // Stream type 0x00 = control stream (1-byte VarInt)
        let stream = peekable_uni_from_chunks(vec![&[0x00], b"hello"]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_push_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        layer.set_control_dispatch_channel(control_tx);

        // Stream type 0x01 = push stream
        let stream = peekable_uni_from_chunks(vec![&[0x01]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_reserved_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        layer.set_control_dispatch_channel(control_tx);

        // Stream type 0x21 = reserved (0x21 + 0*0x1f)
        // 0x21 as 2-byte VarInt: 0x40, 0x21
        let stream = peekable_uni_from_chunks(vec![&[0x40, 0x21]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_unknown_stream_type() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        // Stream type 0x04 = unknown, not HTTP/3
        let stream = peekable_uni_from_chunks(vec![&[0x04], b"data"]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
    }

    #[tokio::test]
    async fn test_accept_uni_another_unknown_type() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        // Stream type 0x10 = unknown, not HTTP/3
        let stream = peekable_uni_from_chunks(vec![&[0x10]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
    }

    #[tokio::test]
    async fn test_accept_bi_always_accepted() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let stream = peekable_bi_from_chunks(vec![b"request data"]);
        let result = ProtocolLayer::<()>::accept_bi(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[test]
    fn test_trait_upcasting_downcast() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();
        let layer_ref: &dyn ProtocolLayer<()> = &layer;
        let any_ref: &dyn Any = layer_ref;
        assert!(any_ref.downcast_ref::<DHttpLayer>().is_some());
    }
}
