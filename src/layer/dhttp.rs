//! DHTTP/3 protocol layer implementation.
//!
//! [`DHttpLayer`] encapsulates all HTTP/3-specific logic for stream identification
//! and protocol initialization. It implements [`ProtocolLayer`] to participate in
//! the layered stream routing architecture.

use std::{
    any::Any,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
};

use futures::{channel::oneshot, future::BoxFuture};
use tokio::sync::Mutex as AsyncMutex;

use crate::{
    codec::StreamReader,
    connection::{
        FrameSink, QPackDecoder, QPackEncoder, StreamError,
        settings::Settings,
        stream::{H3StreamCreationError, UnidirectionalStream},
    },
    frame::goaway::Goaway,
    layer::{PeekableBiStream, PeekableUniStream, ProtocolLayer, StreamVerdict},
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
/// (control, QPACK encoder, QPACK decoder, push, reserved) and accepts all
/// bidirectional streams as HTTP/3 request streams.
pub struct DHttpLayer {
    /// Shared HTTP/3 protocol state.
    state: Arc<DHttpLayerState>,

    /// QPACK encoder, set once during connection initialization.
    qpack_encoder: OnceLock<Arc<QPackEncoder>>,
    /// QPACK decoder, set once during connection initialization.
    qpack_decoder: OnceLock<Arc<QPackDecoder>>,
    /// Control stream frame sink, set once during connection initialization.
    control_stream: OnceLock<AsyncMutex<FrameSink>>,

    /// Oneshot sender for dispatching the peer's control stream.
    control_stream_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,
    /// Oneshot sender for dispatching the peer's QPACK encoder instruction stream.
    qpack_encoder_inst_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,
    /// Oneshot sender for dispatching the peer's QPACK decoder instruction stream.
    qpack_decoder_inst_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,
}

impl std::fmt::Debug for DHttpLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DHttpLayer")
            .field("state", &self.state)
            .field("qpack_encoder", &"...")
            .field("qpack_decoder", &"...")
            .field("control_stream", &"...")
            .finish()
    }
}

impl DHttpLayer {
    /// Creates a new `DHttpLayer` with the given local settings.
    pub fn new(local_settings: Arc<Settings>) -> Self {
        Self {
            state: Arc::new(DHttpLayerState::new(local_settings)),
            qpack_encoder: OnceLock::new(),
            qpack_decoder: OnceLock::new(),
            control_stream: OnceLock::new(),
            control_stream_tx: Mutex::new(None),
            qpack_encoder_inst_tx: Mutex::new(None),
            qpack_decoder_inst_tx: Mutex::new(None),
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

    /// Returns the QPACK encoder, if initialized.
    #[must_use]
    pub fn qpack_encoder(&self) -> Option<&Arc<QPackEncoder>> {
        self.qpack_encoder.get()
    }

    /// Returns the QPACK decoder, if initialized.
    #[must_use]
    pub fn qpack_decoder(&self) -> Option<&Arc<QPackDecoder>> {
        self.qpack_decoder.get()
    }

    /// Returns the control stream frame sink, if initialized.
    #[must_use]
    pub fn control_stream(&self) -> Option<&AsyncMutex<FrameSink>> {
        self.control_stream.get()
    }

    /// Sets the QPACK encoder. Returns `Err` if already set.
    pub fn set_qpack_encoder(&self, encoder: Arc<QPackEncoder>) -> Result<(), Arc<QPackEncoder>> {
        self.qpack_encoder.set(encoder)
    }

    /// Sets the QPACK decoder. Returns `Err` if already set.
    pub fn set_qpack_decoder(&self, decoder: Arc<QPackDecoder>) -> Result<(), Arc<QPackDecoder>> {
        self.qpack_decoder.set(decoder)
    }

    /// Sets the control stream frame sink. Returns `Err` if already set.
    pub fn set_control_stream(
        &self,
        sink: AsyncMutex<FrameSink>,
    ) -> Result<(), AsyncMutex<FrameSink>> {
        self.control_stream.set(sink)
    }

    /// Installs the oneshot dispatch channels for incoming peer streams.
    ///
    /// These channels are used by `accept_uni` to dispatch accepted streams
    /// to the appropriate handlers (control stream, QPACK instruction streams).
    pub fn set_dispatch_channels(
        &self,
        control_tx: oneshot::Sender<UniStreamReader>,
        qpack_encoder_inst_tx: oneshot::Sender<UniStreamReader>,
        qpack_decoder_inst_tx: oneshot::Sender<UniStreamReader>,
    ) {
        *self
            .control_stream_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(control_tx);
        *self
            .qpack_encoder_inst_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(qpack_encoder_inst_tx);
        *self
            .qpack_decoder_inst_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(qpack_decoder_inst_tx);
    }

    /// Checks whether a VarInt stream type is a known HTTP/3 unidirectional
    /// stream type.
    ///
    /// Known types: control (0x00), push (0x01), QPACK encoder (0x02),
    /// QPACK decoder (0x03), and reserved types (0x21 + N * 0x1f).
    fn is_h3_uni_stream_type(stream_type: VarInt) -> bool {
        let raw = stream_type.into_inner();
        matches!(
            stream_type,
            _ if stream_type == UnidirectionalStream::CONTROL_STREAM_TYPE
                || stream_type == UnidirectionalStream::PUSH_STREAM_TYPE
                || stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                || stream_type == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE
        ) || (raw >= 0x21 && (raw - 0x21).is_multiple_of(0x1f))
    }

    /// Attempts to read a VarInt from the peeked bytes of a
    /// [`PeekableUniStream`].
    ///
    /// Returns `Some(varint)` if a complete VarInt could be decoded from the
    /// peeked data, `None` if not enough data is available yet.
    fn try_decode_varint_from_peek(data: &[u8]) -> Option<(VarInt, usize)> {
        if data.is_empty() {
            return None;
        }
        // VarInt encoding: first 2 bits of the first byte indicate length
        let first_byte = data[0];
        let len = 1 << (first_byte >> 6);
        if data.len() < len {
            return None;
        }
        // Decode the VarInt from the first `len` bytes
        let value = match len {
            1 => u64::from(first_byte & 0x3f),
            2 => {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&data[..2]);
                buf[0] &= 0x3f;
                u64::from(u16::from_be_bytes(buf))
            }
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                buf[0] &= 0x3f;
                u64::from(u32::from_be_bytes(buf))
            }
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                buf[0] &= 0x3f;
                u64::from_be_bytes(buf)
            }
            _ => return None,
        };
        // VarInt::from_u64 returns Err for values >= 2^62, but valid encodings
        // cannot exceed that, so this is safe.
        match VarInt::from_u64(value) {
            Ok(v) => Some((v, len)),
            Err(_) => None,
        }
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
        } else if stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE {
            let tx = self
                .qpack_encoder_inst_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .ok_or(H3StreamCreationError::DuplicateQpackEncoderStream)?;
            let _ = tx.send(stream);
        } else if stream_type == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE {
            let tx = self
                .qpack_decoder_inst_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?;
            let _ = tx.send(stream);
        }
        // Push streams (0x01) and reserved streams are accepted but not dispatched.
        // Reserved streams have no semantics per RFC 9114 §6.2.3.
        // Push streams are currently not supported (TODO).
        Ok(())
    }
}

impl<C: Send + Sync + 'static> ProtocolLayer<C> for DHttpLayer {
    fn name(&self) -> &'static str {
        "dhttp3"
    }

    fn init(&self, _quic: &C) -> BoxFuture<'_, Result<(), ConnectionError>> {
        // Initialization of control stream, QPACK encoder/decoder streams
        // is done by Connection::new() which calls set_qpack_encoder/decoder,
        // set_control_stream, and set_dispatch_channels on DHttpLayer.
        // This method is a no-op in T5.
        Box::pin(async { Ok(()) })
    }

    fn accept_uni(
        &self,
        mut stream: PeekableUniStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableUniStream>, ConnectionError>> {
        Box::pin(async move {
            // Fill the peek buffer so we can inspect the stream type VarInt.
            // If the stream is already exhausted before we can read the type,
            // pass it through (unknown/empty stream).
            let has_data = stream
                .fill_peek_buf()
                .await
                .map_err(|e| -> ConnectionError {
                    let _ = e;
                    crate::quic::TransportSnafu {
                        kind: VarInt::from_u32(0),
                        frame_type: VarInt::from_u32(0),
                        reason: "stream read error during type peek",
                    }
                    .build()
                    .into()
                })?;

            if !has_data {
                // Empty stream — not an HTTP/3 stream we recognize.
                // Reset cursor and pass through.
                stream.reset();
                return Ok(StreamVerdict::Passed(stream));
            }

            // Try to decode the stream type VarInt from peeked data.
            // We may need multiple fill_peek_buf calls if the VarInt spans
            // multiple chunks.
            loop {
                let data = stream.peek_slice();
                if let Some((stream_type, consumed)) = Self::try_decode_varint_from_peek(data) {
                    if Self::is_h3_uni_stream_type(stream_type) {
                        // This is an HTTP/3 stream type. Commit the peeked bytes
                        // (consume the type VarInt) and accept the stream.
                        stream.consume(consumed);
                        stream.commit();

                        // Convert back to StreamReader for dispatch.
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
                                        quic::StreamError::Reset { .. } => {
                                            crate::quic::TransportSnafu {
                                                kind: VarInt::from_u32(0),
                                                frame_type: VarInt::from_u32(0),
                                                reason: "stream reset during dispatch",
                                            }
                                            .build()
                                            .into()
                                        }
                                    },
                                }
                            })?;

                        return Ok(StreamVerdict::Accepted);
                    }
                    // Not an HTTP/3 stream type. Reset the cursor so the
                    // next layer can re-read the type VarInt.
                    stream.reset();
                    return Ok(StreamVerdict::Passed(stream));
                }

                // Not enough data to decode the VarInt yet. Try to get more.
                // First consume what we have so far to advance cursor, then
                // try to fill more data.
                let current_len = data.len();
                stream.consume(current_len);
                let has_more = stream
                    .fill_peek_buf()
                    .await
                    .map_err(|e| -> ConnectionError {
                        let _ = e;
                        crate::quic::TransportSnafu {
                            kind: VarInt::from_u32(0),
                            frame_type: VarInt::from_u32(0),
                            reason: "stream read error during type peek",
                        }
                        .build()
                        .into()
                    })?;

                if !has_more {
                    // Stream ended before we could read a complete VarInt.
                    // Reset and pass through.
                    stream.reset();
                    return Ok(StreamVerdict::Passed(stream));
                }
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

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{pin::Pin, sync::Arc};

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

    #[test]
    fn test_is_h3_uni_stream_type() {
        // Control stream: 0x00
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x00)));
        // Push stream: 0x01
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x01)));
        // QPACK encoder: 0x02
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x02)));
        // QPACK decoder: 0x03
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x03)));
        // Reserved: 0x21
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x21)));
        // Reserved: 0x21 + 0x1f = 0x40
        assert!(DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x40)));
        // Unknown: 0x04 (not a known type, not reserved)
        assert!(!DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x04)));
        // Unknown: 0x20 (not reserved pattern)
        assert!(!DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x20)));
        // Unknown: 0x10
        assert!(!DHttpLayer::is_h3_uni_stream_type(VarInt::from_u32(0x10)));
    }

    #[test]
    fn test_try_decode_varint() {
        // 1-byte VarInt: value 0x00 (control stream type)
        let data = [0x00];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, Some((VarInt::from_u32(0x00), 1)));

        // 1-byte VarInt: value 0x01 (push stream type)
        let data = [0x01];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, Some((VarInt::from_u32(0x01), 1)));

        // 1-byte VarInt: value 0x02 (QPACK encoder)
        let data = [0x02];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, Some((VarInt::from_u32(0x02), 1)));

        // 1-byte VarInt: value 0x03 (QPACK decoder)
        let data = [0x03];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, Some((VarInt::from_u32(0x03), 1)));

        // Empty data
        let data: [u8; 0] = [];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, None);

        // 2-byte VarInt: 0x40, 0x21 → value 0x21 (reserved stream type)
        let data = [0x40, 0x21];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, Some((VarInt::from_u32(0x21), 2)));

        // Incomplete 2-byte VarInt (only 1 byte available)
        let data = [0x40];
        let result = DHttpLayer::try_decode_varint_from_peek(&data);
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_accept_uni_control_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        // Install dispatch channels so accept_uni can dispatch
        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(control_tx, qpack_enc_tx, qpack_dec_tx);

        // Stream type 0x00 = control stream (1-byte VarInt)
        let stream = peekable_uni_from_chunks(vec![&[0x00], b"hello"]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_qpack_encoder_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(control_tx, qpack_enc_tx, qpack_dec_tx);

        // Stream type 0x02 = QPACK encoder stream
        let stream = peekable_uni_from_chunks(vec![&[0x02]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_qpack_decoder_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(control_tx, qpack_enc_tx, qpack_dec_tx);

        // Stream type 0x03 = QPACK decoder stream
        let stream = peekable_uni_from_chunks(vec![&[0x03]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_push_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();

        let (control_tx, _control_rx) = futures::channel::oneshot::channel();
        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(control_tx, qpack_enc_tx, qpack_dec_tx);

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
        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(control_tx, qpack_enc_tx, qpack_dec_tx);

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
    fn test_as_any_downcast() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = DHttpLayer::with_default_settings();
        let any_ref = ProtocolLayer::<()>::as_any(&layer);
        assert!(any_ref.downcast_ref::<DHttpLayer>().is_some());
    }
}
