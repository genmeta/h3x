//! QPACK protocol layer implementation.
//!
//! `QPackLayer` encapsulates QPACK-specific logic for stream identification
//! and protocol state. It implements [`Protocol`] to participate in
//! the layered stream routing architecture.

use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures::{Sink, channel::oneshot, future::BoxFuture, never::Never, stream::BoxStream};
use snafu::Snafu;
use tokio::io::AsyncWrite;
use tracing::Instrument;

use crate::{
    codec::{
        DecodeExt, EncodeExt, ErasedPeekableBiStream, ErasedPeekableUniStream, ErasedStreamReader,
        SinkWriter,
    },
    connection::{ConnectionState, LifecycleExt, StreamError},
    dhttp::{protocol::DHttpProtocol, settings::Settings, stream::UnidirectionalStream},
    error::{Code, H3CriticalStreamClosed, H3StreamCreationError},
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    qpack::{
        decoder::{Decoder, DecoderInstruction},
        encoder::{Encoder, EncoderInstruction},
    },
    quic::{self, ConnectionError},
    util::try_future::TryFuture,
    varint::VarInt,
};

type BoxInstructionStream<'a, Instruction> = BoxStream<'a, Result<Instruction, StreamError>>;
type BoxSink<'a, Item, Err> = Pin<Box<dyn Sink<Item, Error = Err> + Send + 'a>>;
type BoxInstructionSink<'a, Instruction> = BoxSink<'a, Instruction, StreamError>;

impl UnidirectionalStream<()> {
    /// An encoder stream is a unidirectional stream of type 0x02. It
    /// carries an unframed sequence of encoder instructions from encoder
    /// to decoder.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.1>
    pub const QPACK_ENCODER_STREAM_TYPE: VarInt = VarInt::from_u32(0x02);

    /// A decoder stream is a unidirectional stream of type 0x03. It
    /// carries an unframed sequence of decoder instructions from decoder
    /// to encoder.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.2>
    pub const QPACK_DECODER_STREAM_TYPE: VarInt = VarInt::from_u32(0x03);
}

impl<S: ?Sized + Send> UnidirectionalStream<S> {
    pub const fn is_qpack_encoder_stream(&self) -> bool {
        self.r#type().into_inner() == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE.into_inner()
    }

    pub async fn initial_qpack_encoder_stream(stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::initial(UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE, stream)
            .await
            .map_err(|error| {
                error.map_stream_reset(|_| H3CriticalStreamClosed::QPackEncoder.into())
            })
    }

    pub const fn is_qpack_decoder_stream(&self) -> bool {
        self.r#type().into_inner() == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE.into_inner()
    }

    // RFC 9204 §4.2: decoder stream type = 0x03
    pub async fn initial_qpack_decoder_stream(stream: S) -> Result<Self, StreamError>
    where
        S: AsyncWrite + Unpin + Sized,
    {
        Self::initial(UnidirectionalStream::QPACK_DECODER_STREAM_TYPE, stream)
            .await
            .map_err(|error| {
                error.map_stream_reset(|_| H3CriticalStreamClosed::QPackDecoder.into())
            })
    }
}

pub type QPackEncoder = Encoder<
    BoxInstructionSink<'static, EncoderInstruction>,
    BoxInstructionStream<'static, DecoderInstruction>,
>;

pub type QPackDecoder = Decoder<
    BoxInstructionSink<'static, DecoderInstruction>,
    BoxInstructionStream<'static, EncoderInstruction>,
>;

/// QPACK protocol layer.
///
/// Implements [`Protocol`] to handle QPACK stream identification.
/// This layer recognizes QPACK unidirectional stream types
/// (encoder 0x02, decoder 0x03) and passes all other streams through.
pub struct QPackProtocol {
    /// Oneshot sender for dispatching the peer's QPACK encoder instruction stream.
    encoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<ErasedStreamReader>>>,
    /// QPACK encoder, set during connection initialization.
    pub encoder: Arc<QPackEncoder>,

    /// Oneshot sender for dispatching the peer's QPACK decoder instruction stream.
    decoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<ErasedStreamReader>>>,
    /// QPACK decoder, set during connection initialization.
    pub decoder: Arc<QPackDecoder>,
}

impl std::fmt::Debug for QPackProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QPackLayer")
            .field("encoder", &"...")
            .field("decoder", &"...")
            .finish()
    }
}

impl QPackProtocol {
    async fn accept_uni(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        let Ok(stream_type) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE {
            let uni_stream_reader = stream.into_stream_reader();
            _ = self
                .encoder_inst_receiver_tx
                .lock()
                .expect("lock is not poisoned")
                .take()
                .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?
                .send(uni_stream_reader);
            Ok(StreamVerdict::Accepted)
        } else if stream_type == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE {
            let uni_stream_reader = stream.into_stream_reader();
            _ = self
                .decoder_inst_receiver_tx
                .lock()
                .expect("lock is not poisoned")
                .take()
                .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?
                .send(uni_stream_reader);
            Ok(StreamVerdict::Accepted)
        } else {
            Ok(StreamVerdict::Passed(stream))
        }
    }

    async fn accept_bi(
        &self,
        stream: ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        Ok(StreamVerdict::Passed(stream))
    }
}

impl Protocol for QPackProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        Box::pin(self.accept_uni(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(self.accept_bi(stream))
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct QPackProtocolFactory {
    // No state for now, but can add config options here in the future.
}

impl QPackProtocolFactory {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn init<C: quic::Connection>(
        &self,
        conn: &Arc<C>,
        layers: &Protocols,
    ) -> Result<QPackProtocol, ConnectionError> {
        let dhttp = layers.get::<DHttpProtocol>().ok_or_else(|| {
            ConnectionError::from(quic::ApplicationError {
                code: Code::H3_INTERNAL_ERROR,
                reason: "DHttpLayer must be initialized before QPackLayer".into(),
            })
        })?;

        // Create dispatch channels for incoming peer QPACK streams
        let (encoder_inst_receiver_tx, encoder_inst_receiver_rx) =
            oneshot::channel::<ErasedStreamReader>();
        let (decoder_inst_receiver_tx, decoder_inst_receiver_rx) =
            oneshot::channel::<ErasedStreamReader>();

        // Create QPACK encoder with lazy streams
        let encoder = {
            // Lazily open QPACK encoder stream. If the dynamic table is never
            // used, the stream is never opened.
            let conn_state = conn.clone();
            let encoder_inst_sender = Box::pin(TryFuture::from(Box::pin(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let encoder_stream =
                    UnidirectionalStream::initial_qpack_encoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(encoder_stream.into_encode_sink())
            })));

            let conn_clone = conn.clone();
            let decoder_inst_receiver = Box::pin(TryFuture::from(async move {
                let connection_error = conn_clone.closed();
                tokio::select! {
                    Ok(uni_stream_reader) = decoder_inst_receiver_rx => {
                        Ok(uni_stream_reader.into_decode_stream())
                    }
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                encoder_inst_sender as BoxInstructionSink<'static, EncoderInstruction>,
                decoder_inst_receiver as BoxInstructionStream<'static, DecoderInstruction>,
            ))
        };

        // Create QPACK decoder with lazy streams
        let decoder = {
            // Lazily open QPACK decoder stream. If the dynamic table is never
            // used by peer, the stream is never opened.
            let conn_state = conn.clone();
            let decoder_inst_sender = Box::pin(TryFuture::from(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let decoder_stream =
                    UnidirectionalStream::initial_qpack_decoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(decoder_stream.into_encode_sink())
            }));

            let conn_clone = conn.clone();
            let encoder_inst_receiver = Box::pin(TryFuture::from(async move {
                let connection_error = conn_clone.closed();
                tokio::select! {
                    Ok(uni_stream_reader) = encoder_inst_receiver_rx => {
                        Ok(uni_stream_reader.into_decode_stream())
                    }
                    error = connection_error => Err(error),
                }
            }));

            Arc::new(Decoder::new(
                dhttp.local_settings.clone(),
                decoder_inst_sender as BoxInstructionSink<'static, DecoderInstruction>,
                encoder_inst_receiver as BoxInstructionStream<'static, EncoderInstruction>,
            ))
        };

        // Spawn receive_decoder_instructions background task
        let encoder_clone = encoder.clone();
        let conn_state = conn.clone();
        let peer_settings = dhttp.peer_settings.clone();

        let receive_decoder_instructions = async move {
            let receive_instructions = async {
                tokio::select! {
                    biased;
                    Err::<Never, _>(stream_error) = async { loop { encoder_clone.receive_instruction().await? } } => {
                        conn_state.handle_stream_error(stream_error).await;
                    }
                    _connection_error = conn_state.closed() => {
                        // Connection error occurred, background task will be aborted by the caller.
                    }
                }
            };
            let receive_peer_settings = async {
                if let Some(settings) = peer_settings.get().await {
                    encoder_clone.apply_settings(settings).await
                }
            };
            tokio::join!(biased; receive_instructions, receive_peer_settings);
        };

        tokio::spawn(receive_decoder_instructions.in_current_span());

        Ok(QPackProtocol {
            encoder_inst_receiver_tx: Mutex::new(Some(encoder_inst_receiver_tx)),
            encoder,
            decoder_inst_receiver_tx: Mutex::new(Some(decoder_inst_receiver_tx)),
            decoder,
        })
    }
}

impl<C: quic::Connection> ProductProtocol<C> for QPackProtocolFactory {
    type Protocol = QPackProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        Box::pin(self.init(conn, layers))
    }
}

#[derive(Snafu, Debug, Clone, Copy)]
#[snafu(display("qpack protocol is disabled"))]
pub struct QPackProtocolDisabled;

impl<C: ?Sized> ConnectionState<C> {
    #[inline]
    pub fn qpack(&self) -> Result<&QPackProtocol, QPackProtocolDisabled> {
        self.protocol().ok_or(QPackProtocolDisabled)
    }
}

// #[cfg(test)]
// mod tests {
//     use std::{any::Any, pin::Pin};

//     use bytes::Bytes;

//     use super::QPackLayer;
//     use crate::{
//         codec::{StreamReader, peekable::PeekableStreamReader},
//         layer::{BoxPeekableUniStream, Protocol, StreamVerdict},
//         varint::VarInt,
//     };

//     /// Helper: create a BoxPeekableUniStream from raw byte chunks.
//     fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> BoxPeekableUniStream {
//         let chunks_owned: Vec<Bytes> = chunks.into_iter().map(Bytes::from_static).collect();

//         let (reader, mut writer) = crate::quic::test::mock_stream_pair(VarInt::from_u32(0));

//         tokio::spawn(async move {
//             use futures::SinkExt;
//             for chunk in chunks_owned {
//                 if writer.send(chunk).await.is_err() {
//                     break;
//                 }
//             }
//             let _ = writer.close().await;
//         });

//         let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
//         let stream_reader = StreamReader::new(boxed_reader);
//         PeekableStreamReader::new(stream_reader)
//     }

//     /// Helper: create a BoxPeekableBiStream from raw byte chunks for the read side.
//     fn peekable_bi_from_chunks(read_chunks: Vec<&'static [u8]>) -> crate::layer::BoxPeekableBiStream {
//         let (reader, mut writer_feed) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));
//         let (_, write_side) = crate::quic::test::mock_stream_pair(VarInt::from_u32(4));

//         let chunks_owned: Vec<Bytes> = read_chunks.into_iter().map(Bytes::from_static).collect();
//         tokio::spawn(async move {
//             use futures::SinkExt;
//             for chunk in chunks_owned {
//                 if writer_feed.send(chunk).await.is_err() {
//                     break;
//                 }
//             }
//             let _ = writer_feed.close().await;
//         });

//         let boxed_reader: Pin<Box<dyn crate::quic::ReadStream + Send>> = Box::pin(reader);
//         let boxed_writer: Pin<Box<dyn crate::quic::WriteStream + Send>> = Box::pin(write_side);
//         let stream_reader = StreamReader::new(boxed_reader);
//         let peekable = PeekableStreamReader::new(stream_reader);
//         (peekable, boxed_writer)
//     }

//     #[test]
//     fn test_qpack_layer_new() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();
//         assert_eq!(Protocol::<()>::name(&layer), "qpack");
//         assert!(layer.qpack_encoder().is_none());
//         assert!(layer.qpack_decoder().is_none());
//     }

//     #[tokio::test]
//     async fn test_accept_uni_qpack_encoder_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();

//         let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
//         let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
//         layer.set_dispatch_channels(qpack_enc_tx, qpack_dec_tx);

//         // Stream type 0x02 = QPACK encoder stream
//         let stream = peekable_uni_from_chunks(vec![&[0x02]]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_qpack_decoder_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();

//         let (qpack_enc_tx, _qpack_enc_rx) = futures::channel::oneshot::channel();
//         let (qpack_dec_tx, _qpack_dec_rx) = futures::channel::oneshot::channel();
//         layer.set_dispatch_channels(qpack_enc_tx, qpack_dec_tx);

//         // Stream type 0x03 = QPACK decoder stream
//         let stream = peekable_uni_from_chunks(vec![&[0x03]]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Accepted));
//     }

//     #[tokio::test]
//     async fn test_accept_uni_non_qpack_stream() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();

//         // Stream type 0x00 = control stream (not QPACK), should pass through
//         let stream = peekable_uni_from_chunks(vec![&[0x00], b"hello"]);
//         let result = Protocol::<()>::accept_uni(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
//     }

//     #[tokio::test]
//     async fn test_accept_bi_always_passed() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();

//         let stream = peekable_bi_from_chunks(vec![b"request data"]);
//         let result = Protocol::<()>::accept_bi(&layer, stream).await;
//         assert!(result.is_ok());
//         assert!(matches!(result.unwrap(), StreamVerdict::Passed(_)));
//     }

//     #[test]
//     fn test_trait_upcasting_downcast() {
//         let _guard = tracing_subscriber::fmt::try_init();
//         let layer = QPackLayer::new();
//         let layer_ref: &dyn Protocol<()> = &layer;
//         let any_ref: &dyn Any = layer_ref;
//         assert!(any_ref.downcast_ref::<QPackLayer>().is_some());
//     }
// }

#[cfg(test)]
mod tests {
    use std::{
        cmp::Ordering,
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    #[test]
    fn qpack_factory_all_equal() {
        assert_eq!(QPackProtocolFactory::new(), QPackProtocolFactory::new());
    }

    #[test]
    fn qpack_factory_same_hash() {
        assert_eq!(
            hash_of(&QPackProtocolFactory::new()),
            hash_of(&QPackProtocolFactory::new()),
        );
    }

    #[test]
    fn qpack_factory_eq_is_reflexive() {
        let a = QPackProtocolFactory::new();
        let b = QPackProtocolFactory::new();
        assert_eq!(a, b);
    }
    #[test]
    fn qpack_decoder_stream_type_is_0x03() {
        assert_eq!(
            UnidirectionalStream::<()>::QPACK_DECODER_STREAM_TYPE.into_inner(),
            0x03,
        );
    }

    #[test]
    fn qpack_encoder_stream_type_is_0x02() {
        assert_eq!(
            UnidirectionalStream::<()>::QPACK_ENCODER_STREAM_TYPE.into_inner(),
            0x02,
        );
    }

    #[test]
    fn qpack_stream_type_constants_are_distinct() {
        assert_ne!(
            UnidirectionalStream::<()>::QPACK_ENCODER_STREAM_TYPE.into_inner(),
            UnidirectionalStream::<()>::QPACK_DECODER_STREAM_TYPE.into_inner(),
        );
    }
}
