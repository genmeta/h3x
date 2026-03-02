//! QPACK protocol layer implementation.
//!
//! [`QPackLayer`] encapsulates QPACK-specific logic for stream identification
//! and protocol state. It implements [`ProtocolLayer`] to participate in
//! the layered stream routing architecture.

use std::sync::{Arc, Mutex, OnceLock};

use futures::{channel::oneshot, future::BoxFuture};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    codec::{DecodeExt, EncodeExt, SinkWriter},
    connection::{
        ConnectionState, QPackDecoder, QPackEncoder, StreamError,
        settings::Settings,
        stream::{H3StreamCreationError, UnidirectionalStream},
    },
    layer::{
        PeekableBiStream, PeekableUniStream, ProtocolLayer, StreamVerdict, dhttp::UniStreamReader,
    },
    qpack::{
        BoxInstructionSink, BoxInstructionStream,
        decoder::{Decoder, DecoderInstruction},
        encoder::{Encoder, EncoderInstruction},
    },
    quic::{self, ConnectionError},
    util::try_future::TryFuture,
    varint::VarInt,
};

/// QPACK protocol layer.
///
/// Implements [`ProtocolLayer`] to handle QPACK stream identification.
/// This layer recognizes QPACK unidirectional stream types
/// (encoder 0x02, decoder 0x03) and passes all other streams through.
pub struct QPackLayer {
    /// QPACK encoder, set once during connection initialization.
    qpack_encoder: OnceLock<Arc<QPackEncoder>>,
    /// QPACK decoder, set once during connection initialization.
    qpack_decoder: OnceLock<Arc<QPackDecoder>>,
    /// Oneshot sender for dispatching the peer's QPACK encoder instruction stream.
    qpack_encoder_inst_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,
    /// Oneshot sender for dispatching the peer's QPACK decoder instruction stream.
    qpack_decoder_inst_tx: Mutex<Option<oneshot::Sender<UniStreamReader>>>,
}

impl std::fmt::Debug for QPackLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QPackLayer")
            .field("qpack_encoder", &"...")
            .field("qpack_decoder", &"...")
            .finish()
    }
}

impl Default for QPackLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl QPackLayer {
    /// Creates a new `QPackLayer`.
    pub fn new() -> Self {
        Self {
            qpack_encoder: OnceLock::new(),
            qpack_decoder: OnceLock::new(),
            qpack_encoder_inst_tx: Mutex::new(None),
            qpack_decoder_inst_tx: Mutex::new(None),
        }
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

    /// Sets the QPACK encoder. Returns `Err` if already set.
    pub fn set_qpack_encoder(&self, encoder: Arc<QPackEncoder>) -> Result<(), Arc<QPackEncoder>> {
        self.qpack_encoder.set(encoder)
    }

    /// Sets the QPACK decoder. Returns `Err` if already set.
    pub fn set_qpack_decoder(&self, decoder: Arc<QPackDecoder>) -> Result<(), Arc<QPackDecoder>> {
        self.qpack_decoder.set(decoder)
    }

    /// Installs the oneshot dispatch channels for incoming peer QPACK streams.
    ///
    /// These channels are used by `accept_uni` to dispatch accepted QPACK
    /// instruction streams to the appropriate handlers.
    pub fn set_dispatch_channels(
        &self,
        qpack_encoder_inst_tx: oneshot::Sender<UniStreamReader>,
        qpack_decoder_inst_tx: oneshot::Sender<UniStreamReader>,
    ) {
        *self
            .qpack_encoder_inst_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(qpack_encoder_inst_tx);
        *self
            .qpack_decoder_inst_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(qpack_decoder_inst_tx);
    }

    /// Initializes the QPACK layer with real protocol logic.
    ///
    /// Creates the QPACK encoder and decoder (with lazy TryFuture streams),
    /// sets up dispatch channels, stores encoder/decoder in self, and spawns
    /// the `receive_decoder_instructions` background task.
    ///
    /// Returns the QPACK encoder (for DHttpLayer) and a handle to the background task.
    pub fn init_qpack<C: quic::Connection>(
        &self,
        state: &Arc<ConnectionState<C>>,
    ) -> (
        Arc<QPackEncoder>,
        AbortOnDropHandle<Result<(), StreamError>>,
    ) {
        // Create dispatch channels for incoming peer QPACK streams
        let (qpack_encoder_inst_receiver_tx, qpack_encoder_inst_receiver_rx) = oneshot::channel();
        let (qpack_decoder_inst_receiver_tx, qpack_decoder_inst_receiver_rx) = oneshot::channel();
        self.set_dispatch_channels(
            qpack_encoder_inst_receiver_tx,
            qpack_decoder_inst_receiver_tx,
        );

        // Create QPACK encoder with lazy streams
        let qpack_encoder = {
            // Lazily open QPACK encoder stream. If the dynamic table is never
            // used, the stream is never opened.
            let conn_state = state.clone();
            let qpack_encoder_inst_sender = Box::pin(TryFuture::from(Box::pin(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let encoder_stream =
                    UnidirectionalStream::new_qpack_encoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(encoder_stream.into_encode_sink())
            })));

            let connection_error = state.error();
            let qpack_decoder_inst_receiver = Box::pin(TryFuture::from(async move {
                tokio::select! {
                    Ok(uni_stream_reader) = qpack_decoder_inst_receiver_rx => {
                        Ok(uni_stream_reader.into_decode_stream())
                    }
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                qpack_encoder_inst_sender as BoxInstructionSink<'static, EncoderInstruction>,
                qpack_decoder_inst_receiver as BoxInstructionStream<'static, DecoderInstruction>,
            ))
        };

        // Create QPACK decoder with lazy streams
        let qpack_decoder = {
            // Lazily open QPACK decoder stream. If the dynamic table is never
            // used by peer, the stream is never opened.
            let conn_state = state.clone();
            let qpack_decoder_inst_sender = Box::pin(TryFuture::from(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let decoder_stream =
                    UnidirectionalStream::new_qpack_decoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(decoder_stream.into_encode_sink())
            }));

            let connection_error = state.error();
            let qpack_encoder_inst_receiver = Box::pin(TryFuture::from(async move {
                tokio::select! {
                    Ok(uni_stream_reader) = qpack_encoder_inst_receiver_rx => {
                        Ok(uni_stream_reader.into_decode_stream())
                    }
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Decoder::new(
                state.local_settings().clone(),
                qpack_decoder_inst_sender as BoxInstructionSink<'static, DecoderInstruction>,
                qpack_encoder_inst_receiver as BoxInstructionStream<'static, EncoderInstruction>,
            ))
        };

        // Store encoder/decoder in self
        let _ = self.set_qpack_encoder(qpack_encoder.clone());
        let _ = self.set_qpack_decoder(qpack_decoder.clone());

        // Spawn receive_decoder_instructions background task
        let encoder = qpack_encoder.clone();
        let receive_decoder_instructions = async move {
            loop {
                encoder.receive_instruction().await?
            }

            #[allow(unreachable_code)]
            Ok::<_, StreamError>(())
        };
        (
            qpack_encoder,
            AbortOnDropHandle::new(tokio::spawn(receive_decoder_instructions.in_current_span())),
        )
    }

    /// Dispatches an accepted QPACK unidirectional stream to the appropriate handler
    /// based on its stream type.
    ///
    /// The stream type VarInt has already been consumed from the stream.
    fn dispatch_uni_stream(
        &self,
        stream_type: VarInt,
        stream: UniStreamReader,
    ) -> Result<(), StreamError> {
        if stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE {
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
        Ok(())
    }
}

impl<C: Send + Sync + 'static> ProtocolLayer<C> for QPackLayer {
    fn name(&self) -> &'static str {
        "qpack"
    }

    fn init(&self, _quic: &C) -> BoxFuture<'_, Result<(), ConnectionError>> {
        // Initialization is done via `init_qpack()` called from `Connection::new()`.
        Box::pin(async { Ok(()) })
    }

    fn accept_uni(
        &self,
        mut stream: PeekableUniStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableUniStream>, ConnectionError>> {
        Box::pin(async move {
            // Use the standard codec pattern to decode the stream type VarInt.
            let stream_type: VarInt = match stream.decode_one::<VarInt>().await {
                Ok(v) => v,
                Err(_) => {
                    // Failed to decode (stream exhausted or malformed).
                    // Reset cursor and pass through to the next layer.
                    stream.reset();
                    return Ok(StreamVerdict::Passed(stream));
                }
            };

            // Check if the decoded stream type is a QPACK type.
            let is_qpack_type = stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE
                || stream_type == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE;

            if is_qpack_type {
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
                // Not a QPACK stream type. Reset cursor so the next layer
                // can re-read the stream type VarInt.
                stream.reset();
                Ok(StreamVerdict::Passed(stream))
            }
        })
    }

    fn accept_bi(
        &self,
        stream: PeekableBiStream,
    ) -> BoxFuture<'_, Result<StreamVerdict<PeekableBiStream>, ConnectionError>> {
        // QPACK doesn't handle bidirectional streams.
        Box::pin(async { Ok(StreamVerdict::Passed(stream)) })
    }
}

#[cfg(test)]
mod tests {
    use std::{any::Any, pin::Pin};

    use bytes::Bytes;

    use super::QPackLayer;
    use crate::{
        codec::{StreamReader, peekable::PeekableStreamReader},
        layer::{PeekableUniStream, ProtocolLayer, StreamVerdict},
        varint::VarInt,
    };

    /// Helper: create a PeekableUniStream from raw byte chunks.
    fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> PeekableUniStream {
        let chunks_owned: Vec<Bytes> = chunks.into_iter().map(Bytes::from_static).collect();

        let (reader, mut writer) = crate::quic::test::mock_stream_pair(VarInt::from_u32(0));

        tokio::spawn(async move {
            use futures::SinkExt;
            for chunk in chunks_owned {
                if writer.send(chunk).await.is_err() {
                    break;
                }
            }
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
    fn test_qpack_layer_new() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();
        assert_eq!(ProtocolLayer::<()>::name(&layer), "qpack");
        assert!(layer.qpack_encoder().is_none());
        assert!(layer.qpack_decoder().is_none());
    }

    #[tokio::test]
    async fn test_accept_uni_qpack_encoder_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();

        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(qpack_enc_tx, qpack_dec_tx);

        // Stream type 0x02 = QPACK encoder stream
        let stream = peekable_uni_from_chunks(vec![&[0x02]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_qpack_decoder_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();

        let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
        let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
        layer.set_dispatch_channels(qpack_enc_tx, qpack_dec_tx);

        // Stream type 0x03 = QPACK decoder stream
        let stream = peekable_uni_from_chunks(vec![&[0x03]]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
    }

    #[tokio::test]
    async fn test_accept_uni_non_qpack_stream() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();

        // Stream type 0x00 = control stream (not QPACK), should pass through
        let stream = peekable_uni_from_chunks(vec![&[0x00], b"hello"]);
        let result = ProtocolLayer::<()>::accept_uni(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
    }

    #[tokio::test]
    async fn test_accept_bi_always_passed() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();

        let stream = peekable_bi_from_chunks(vec![b"request data"]);
        let result = ProtocolLayer::<()>::accept_bi(&layer, stream).await;
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
    }

    #[test]
    fn test_trait_upcasting_downcast() {
        let _guard = tracing_subscriber::fmt::try_init();
        let layer = QPackLayer::new();
        let layer_ref: &dyn ProtocolLayer<()> = &layer;
        let any_ref: &dyn Any = layer_ref;
        assert!(any_ref.downcast_ref::<QPackLayer>().is_some());
    }
}
