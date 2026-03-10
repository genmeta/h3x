//! QPACK protocol layer implementation.
//!
//! [`QPackLayer`] encapsulates QPACK-specific logic for stream identification
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
        BoxPeekableBiStream, BoxPeekableUniStream, BoxStreamReader, DecodeExt, EncodeExt,
        SinkWriter,
    },
    connection::{ConnectionState, QuicConnection, StreamError},
    dhttp::{protocol::DHttpProtocol, settings::Settings, stream::UnidirectionalStream},
    error::{H3CriticalStreamClosed, H3StreamCreationError},
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
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.1
    pub const QPACK_ENCODER_STREAM_TYPE: VarInt = VarInt::from_u32(0x02);

    /// A decoder stream is a unidirectional stream of type 0x03. It
    /// carries an unframed sequence of decoder instructions from decoder
    /// to encoder.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.2-2.2
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
pub struct QPackProtocol<C: quic::Connection + ?Sized> {
    /// Oneshot sender for dispatching the peer's QPACK encoder instruction stream.
    encoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<BoxStreamReader<C>>>>,
    /// QPACK encoder, set during connection initialization.
    pub encoder: Arc<QPackEncoder>,

    /// Oneshot sender for dispatching the peer's QPACK decoder instruction stream.
    decoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<BoxStreamReader<C>>>>,
    /// QPACK decoder, set during connection initialization.
    pub decoder: Arc<QPackDecoder>,
}

impl<C: quic::Connection + ?Sized> std::fmt::Debug for QPackProtocol<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QPackLayer")
            .field("encoder", &"...")
            .field("decoder", &"...")
            .finish()
    }
}

impl<C: quic::Connection + ?Sized> QPackProtocol<C> {
    async fn accept_uni(
        &self,
        mut stream: BoxPeekableUniStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError> {
        let Ok(stream_type) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if stream_type == UnidirectionalStream::QPACK_ENCODER_STREAM_TYPE {
            let uni_stream_reader = stream.into_stream_reader();
            _ = self
                .encoder_inst_receiver_tx
                .lock()
                .unwrap()
                .take()
                .ok_or(H3StreamCreationError::DuplicateQpackDecoderStream)?
                .send(uni_stream_reader);
            Ok(StreamVerdict::Accepted)
        } else if stream_type == UnidirectionalStream::QPACK_DECODER_STREAM_TYPE {
            let uni_stream_reader = stream.into_stream_reader();
            _ = self
                .decoder_inst_receiver_tx
                .lock()
                .unwrap()
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
        stream: BoxPeekableBiStream<C>,
    ) -> Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError> {
        Ok(StreamVerdict::Passed(stream))
    }
}

impl<C: quic::Connection + ?Sized> Protocol<C> for QPackProtocol<C> {
    fn accept_uni<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableUniStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableUniStream<C>>, StreamError>> {
        _ = connection;
        Box::pin(self.accept_uni(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        connection: &'a Arc<QuicConnection<C>>,
        stream: BoxPeekableBiStream<C>,
    ) -> BoxFuture<'a, Result<StreamVerdict<BoxPeekableBiStream<C>>, StreamError>> {
        _ = connection;
        Box::pin(self.accept_bi(stream))
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct QPackProtocolFactory {
    // No state for now, but can add config options here in the future.
}

impl QPackProtocolFactory {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn init<C: quic::Connection + ?Sized>(
        &self,
        conn: &Arc<QuicConnection<C>>,
        layers: &Protocols<C>,
    ) -> Result<QPackProtocol<C>, ConnectionError> {
        let dhttp = layers
            .get::<DHttpProtocol>()
            .expect("DHttpLayer must be initialized before QPackLayer");

        // Create dispatch channels for incoming peer QPACK streams
        let (encoder_inst_receiver_tx, encoder_inst_receiver_rx) =
            oneshot::channel::<BoxStreamReader<C>>();
        let (decoder_inst_receiver_tx, decoder_inst_receiver_rx) =
            oneshot::channel::<BoxStreamReader<C>>();

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

            let connection_error = conn.error();
            let decoder_inst_receiver = Box::pin(TryFuture::from(async move {
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
                    UnidirectionalStream::initial_qpack_encoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(decoder_stream.into_encode_sink())
            }));

            let connection_error = conn.error();
            let encoder_inst_receiver = Box::pin(TryFuture::from(async move {
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
                    _connection_error = conn_state.error() => {
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

impl<C: quic::Connection + ?Sized> ProductProtocol<C> for QPackProtocolFactory {
    type Protocol = QPackProtocol<C>;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<QuicConnection<C>>,
        layers: &'a Protocols<C>,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        Box::pin(self.init(conn, layers))
    }
}

#[derive(Snafu, Debug, Clone, Copy)]
#[snafu(display("qpack protocol is disabled"))]
pub struct QPackProtocolDisabled;

impl<C: quic::Connection + ?Sized> ConnectionState<C> {
    #[inline]
    pub fn qpack(&self) -> Result<&QPackProtocol<C>, QPackProtocolDisabled> {
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
