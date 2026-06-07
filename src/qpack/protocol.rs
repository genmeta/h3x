//! QPACK protocol layer implementation.
//!
//! `QPackLayer` encapsulates QPACK-specific logic for stream identification
//! and protocol state. It implements [`Protocol`] to participate in
//! the layered stream routing architecture.

use std::{
    fmt,
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures::{Sink, channel::oneshot, future::BoxFuture, stream::BoxStream};
use snafu::Snafu;
use tokio::io::AsyncWrite;
use tracing::Instrument;

use crate::{
    codec::{
        BoxPeekableStreamReader, BoxStreamReader, BoxStreamWriter, DecodeExt, EncodeExt, SinkWriter,
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
    util::deferred::Deferred,
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
    encoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<BoxStreamReader>>>,
    /// QPACK encoder, set during connection initialization.
    pub encoder: Arc<QPackEncoder>,

    /// Oneshot sender for dispatching the peer's QPACK decoder instruction stream.
    decoder_inst_receiver_tx: Mutex<Option<oneshot::Sender<BoxStreamReader>>>,
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
        mut stream: BoxPeekableStreamReader,
    ) -> Result<StreamVerdict<BoxPeekableStreamReader>, StreamError> {
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
                .ok_or(H3StreamCreationError::DuplicateQpackEncoderStream)?
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
        stream: (BoxPeekableStreamReader, BoxStreamWriter),
    ) -> Result<StreamVerdict<(BoxPeekableStreamReader, BoxStreamWriter)>, StreamError> {
        Ok(StreamVerdict::Passed(stream))
    }
}

impl Protocol for QPackProtocol {
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
pub struct QPackProtocolFactory {
    // No state for now, but can add config options here in the future.
}

impl fmt::Display for QPackProtocolFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QPACK")
    }
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
            oneshot::channel::<BoxStreamReader>();
        let (decoder_inst_receiver_tx, decoder_inst_receiver_rx) =
            oneshot::channel::<BoxStreamReader>();

        // Create QPACK encoder with lazy streams
        let encoder = {
            // Lazily open QPACK encoder stream. If the dynamic table is never
            // used, the stream is never opened.
            let conn_state = conn.clone();
            let encoder_inst_sender = Box::pin(Deferred::from(Box::pin(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let encoder_stream =
                    UnidirectionalStream::initial_qpack_encoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(encoder_stream.into_encode_sink())
            })));

            let conn_clone = conn.clone();
            let decoder_inst_receiver = Box::pin(Deferred::from(async move {
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
            let decoder_inst_sender = Box::pin(Deferred::from(async move {
                let uni_stream = Box::pin(SinkWriter::new(conn_state.open_uni().await?));
                let decoder_stream =
                    UnidirectionalStream::initial_qpack_decoder_stream(uni_stream).await?;
                Ok::<_, StreamError>(decoder_stream.into_encode_sink())
            }));

            let conn_clone = conn.clone();
            let encoder_inst_receiver = Box::pin(Deferred::from(async move {
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

        // Spawn decoder background task
        let encoder_clone = encoder.clone();
        let conn_state = conn.clone();
        let peer_settings = dhttp.peer_settings.clone();

        let decoder_task = async move {
            let apply_peer_settings = async {
                if let Some(settings) = peer_settings.get().await {
                    encoder_clone.apply_settings(settings).await;
                }
            };
            let receive_instructions = async {
                loop {
                    if let Err(stream_error) = encoder_clone.receive_instruction().await {
                        // The instruction stream is a QPACK critical stream;
                        // any stream-scope failure on it is already promoted
                        // to a connection-scope error by `receive_instruction`
                        // (see `QPackEncoderStreamError`). We only need to
                        // drive connection close for the connection-scope
                        // case here.
                        if let StreamError::Connection { source } = stream_error {
                            conn_state.handle_connection_error(source).await;
                        }
                        return;
                    }
                }
            };
            tokio::select! {
                biased;
                _ = async move { tokio::join!(biased; receive_instructions, apply_peer_settings) } => {}
                _ = conn_state.closed() => {}
            }
        };

        // Terminates when conn_state.closed() resolves or the instruction stream ends.
        tokio::spawn(decoder_task.in_current_span());

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
//         layer::{BoxPeekableStreamReader, Protocol, StreamVerdict},
//         varint::VarInt,
//     };

//     /// Helper: create a BoxPeekableStreamReader from raw byte chunks.
//     fn peekable_uni_from_chunks(chunks: Vec<&'static [u8]>) -> BoxPeekableStreamReader {
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

//     /// Helper: create a (BoxPeekableStreamReader, BoxStreamWriter) from raw byte chunks for the read side.
//     fn peekable_bi_from_chunks(read_chunks: Vec<&'static [u8]>) -> crate::layer::(BoxPeekableStreamReader, BoxStreamWriter) {
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
        any::Any,
        borrow::Cow,
        collections::hash_map::DefaultHasher,
        fmt,
        hash::{Hash, Hasher},
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity::SignError;
    use futures::{SinkExt, StreamExt, channel::oneshot};
    use rustls::pki_types::CertificateDer;

    use super::*;
    use crate::{
        codec::{PeekableStreamReader, StreamReader},
        dhttp::protocol::DHttpProtocolFactory,
        quic::{BoxQuicStreamReader, BoxQuicStreamWriter},
    };

    #[derive(Debug, Clone, Copy)]
    struct TestLocalAuthority;

    impl dhttp_identity::identity::LocalAuthority for TestLocalAuthority {
        fn name(&self) -> &str {
            "test.local"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &[]
        }
        fn sign(&self, _data: &[u8]) -> futures::future::BoxFuture<'_, Result<Vec<u8>, SignError>> {
            Box::pin(std::future::ready(Err(SignError::UnsupportedKey)))
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct TestRemoteAuthority;

    impl dhttp_identity::identity::RemoteAuthority for TestRemoteAuthority {
        fn name(&self) -> &str {
            "test.remote"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Default, Clone)]
    struct MockConnection {
        stream_calls: Arc<Mutex<Vec<&'static str>>>,
        open_uni_readers: Arc<Mutex<Vec<Box<dyn Any + Send>>>>,
        open_uni_available: bool,
        closed_pending: bool,
    }

    impl fmt::Debug for MockConnection {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockConnection")
                .field("stream_calls", &self.stream_calls)
                .field(
                    "open_uni_readers",
                    &self
                        .open_uni_readers
                        .lock()
                        .expect("open uni readers lock poisoned")
                        .len(),
                )
                .field("open_uni_available", &self.open_uni_available)
                .field("closed_pending", &self.closed_pending)
                .finish()
        }
    }

    impl MockConnection {
        fn with_open_uni_available(open_uni_available: bool) -> Self {
            Self {
                stream_calls: Arc::default(),
                open_uni_readers: Arc::default(),
                open_uni_available,
                closed_pending: false,
            }
        }

        fn with_open_uni_available_and_pending_close(open_uni_available: bool) -> Self {
            Self {
                stream_calls: Arc::default(),
                open_uni_readers: Arc::default(),
                open_uni_available,
                closed_pending: true,
            }
        }

        fn stream_calls(&self) -> Vec<&'static str> {
            self.stream_calls
                .lock()
                .expect("stream call log poisoned")
                .clone()
        }

        fn record_stream_call(&self, call: &'static str) {
            self.stream_calls
                .lock()
                .expect("stream call log poisoned")
                .push(call);
        }
    }

    fn test_connection_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    impl quic::ManageStream for MockConnection {
        type StreamReader = BoxQuicStreamReader;
        type StreamWriter = BoxQuicStreamWriter;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            self.record_stream_call("open_bi");
            Err(test_connection_error("open_bi unavailable"))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            self.record_stream_call("open_uni");
            if !self.open_uni_available {
                return Err(test_connection_error("open_uni unavailable"));
            }

            let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(0));
            self.open_uni_readers
                .lock()
                .expect("open uni readers lock poisoned")
                .push(Box::new(reader));
            Ok(Box::pin(writer) as BoxQuicStreamWriter)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            self.record_stream_call("accept_bi");
            Err(test_connection_error("accept_bi unavailable"))
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            self.record_stream_call("accept_uni");
            Err(test_connection_error("accept_uni unavailable"))
        }
    }

    impl quic::WithLocalAuthority for MockConnection {
        type LocalAuthority = TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for MockConnection {
        type RemoteAuthority = TestRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for MockConnection {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            if self.closed_pending {
                std::future::pending().await
            } else {
                test_connection_error("connection closed")
            }
        }
    }

    fn hash_of<T: Hash>(t: &T) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    fn instruction_sink<Instruction: Send + 'static>() -> BoxInstructionSink<'static, Instruction> {
        Box::pin(futures::sink::unfold((), |(), _instruction| async {
            Ok::<(), StreamError>(())
        }))
    }

    fn instruction_stream<Instruction: Send + 'static>()
    -> BoxInstructionStream<'static, Instruction> {
        Box::pin(futures::stream::pending())
    }

    fn qpack_protocol() -> QPackProtocol {
        let (encoder_inst_receiver_tx, _encoder_inst_receiver_rx) =
            oneshot::channel::<BoxStreamReader>();
        let (decoder_inst_receiver_tx, _decoder_inst_receiver_rx) =
            oneshot::channel::<BoxStreamReader>();

        QPackProtocol {
            encoder_inst_receiver_tx: Mutex::new(Some(encoder_inst_receiver_tx)),
            encoder: Arc::new(Encoder::new(
                Arc::<Settings>::default(),
                instruction_sink::<EncoderInstruction>(),
                instruction_stream::<DecoderInstruction>(),
            )),
            decoder_inst_receiver_tx: Mutex::new(Some(decoder_inst_receiver_tx)),
            decoder: Arc::new(Decoder::new(
                Arc::<Settings>::default(),
                instruction_sink::<DecoderInstruction>(),
                instruction_stream::<EncoderInstruction>(),
            )),
        }
    }

    async fn peekable_uni_from_bytes(bytes: &'static [u8]) -> BoxPeekableStreamReader {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(0));
        if !bytes.is_empty() {
            writer
                .send(Bytes::from_static(bytes))
                .await
                .expect("send bytes");
        }
        writer.close().await.expect("close writer");
        PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxQuicStreamReader))
    }

    fn peekable_bi_stream() -> (BoxPeekableStreamReader, BoxStreamWriter) {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(4));
        (
            PeekableStreamReader::new(StreamReader::new(Box::pin(reader) as BoxQuicStreamReader)),
            SinkWriter::new(Box::pin(writer) as BoxQuicStreamWriter),
        )
    }

    fn assert_duplicate_stream_creation(error: StreamError, expected_message: &str) {
        let StreamError::Connection { source } = error else {
            panic!("expected connection-scoped stream error");
        };
        let crate::connection::ConnectionError::H3 { source } = source else {
            panic!("expected h3 connection error");
        };
        assert_eq!(source.code(), Code::H3_STREAM_CREATION_ERROR);
        assert_eq!(source.to_string(), expected_message);
    }

    fn assert_critical_stream_closed(error: StreamError, expected_message: &str) {
        let StreamError::Connection {
            source: crate::connection::ConnectionError::H3 { source },
        } = error
        else {
            panic!("expected h3 connection error");
        };
        assert_eq!(source.code(), Code::H3_CLOSED_CRITICAL_STREAM);
        assert_eq!(source.to_string(), expected_message);
    }

    struct ResetWrite;

    impl tokio::io::AsyncWrite for ResetWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::from(quic::StreamError::Reset {
                code: VarInt::from_u32(7),
            })))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
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
    fn qpack_factory_display_and_debug_are_stable() {
        let factory = QPackProtocolFactory::new();
        assert_eq!(factory.to_string(), "QPACK");
        assert_eq!(format!("{factory:?}"), "QPackProtocolFactory");
        assert_eq!(
            format!("{:?}", qpack_protocol()),
            "QPackLayer { encoder: \"...\", decoder: \"...\" }"
        );
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

    #[tokio::test]
    async fn qpack_stream_type_helpers_identify_encoder_and_decoder_streams() {
        let encoder_stream = UnidirectionalStream::initial_qpack_encoder_stream(tokio::io::sink())
            .await
            .expect("encoder stream");
        assert!(encoder_stream.is_qpack_encoder_stream());
        assert!(!encoder_stream.is_qpack_decoder_stream());

        let decoder_stream = UnidirectionalStream::initial_qpack_decoder_stream(tokio::io::sink())
            .await
            .expect("decoder stream");
        assert!(decoder_stream.is_qpack_decoder_stream());
        assert!(!decoder_stream.is_qpack_encoder_stream());
    }

    #[tokio::test]
    async fn qpack_initial_stream_helpers_write_expected_stream_types() {
        let (mut encoder_reader, encoder_writer) =
            quic::test::mock_stream_pair(VarInt::from_u32(0));
        let encoder_stream = UnidirectionalStream::initial_qpack_encoder_stream(SinkWriter::new(
            Box::pin(encoder_writer) as BoxQuicStreamWriter,
        ))
        .await
        .expect("encoder stream init");
        let mut encoder_writer = encoder_stream.into_inner();
        encoder_writer.flush_inner().await.expect("encoder flush");
        assert_eq!(
            encoder_reader
                .next()
                .await
                .expect("encoder bytes")
                .expect("encoder stream read"),
            Bytes::from_static(&[0x02]),
        );

        let (mut decoder_reader, decoder_writer) =
            quic::test::mock_stream_pair(VarInt::from_u32(0));
        let decoder_stream = UnidirectionalStream::initial_qpack_decoder_stream(SinkWriter::new(
            Box::pin(decoder_writer) as BoxQuicStreamWriter,
        ))
        .await
        .expect("decoder stream init");
        let mut decoder_writer = decoder_stream.into_inner();
        decoder_writer.flush_inner().await.expect("decoder flush");
        assert_eq!(
            decoder_reader
                .next()
                .await
                .expect("decoder bytes")
                .expect("decoder stream read"),
            Bytes::from_static(&[0x03]),
        );
    }

    #[tokio::test]
    async fn qpack_initial_stream_helpers_map_reset_to_critical_stream_closed() {
        let error = UnidirectionalStream::initial_qpack_encoder_stream(ResetWrite)
            .await
            .err()
            .expect("encoder stream reset should be critical");
        assert_critical_stream_closed(error, "qpack encoder stream closed unexpectedly");

        let error = UnidirectionalStream::initial_qpack_decoder_stream(ResetWrite)
            .await
            .err()
            .expect("decoder stream reset should be critical");
        assert_critical_stream_closed(error, "qpack decoder stream closed unexpectedly");
    }

    #[tokio::test]
    async fn qpack_test_helpers_cover_mock_connection_error_paths() {
        use dhttp_identity::identity::{LocalAuthority as _, RemoteAuthority as _};

        let local = TestLocalAuthority;
        assert_eq!(local.name(), "test.local");
        assert!(local.cert_chain().is_empty());
        let sign_error = local
            .sign(b"payload")
            .await
            .expect_err("unsupported key should fail");
        assert!(matches!(sign_error, SignError::UnsupportedKey));

        let remote = TestRemoteAuthority;
        assert_eq!(remote.name(), "test.remote");
        assert!(remote.cert_chain().is_empty());

        let conn = MockConnection::with_open_uni_available(false);
        quic::Lifecycle::close(&conn, Code::H3_NO_ERROR, Cow::Borrowed("ignored"));
        assert!(quic::Lifecycle::check(&conn).is_ok());
        let closed = quic::Lifecycle::closed(&conn).await;
        match closed {
            quic::ConnectionError::Transport { source } => {
                assert_eq!(source.reason, "connection closed");
            }
            error => panic!("unexpected close error: {error:?}"),
        }

        assert!(
            quic::WithLocalAuthority::local_authority(&conn)
                .await
                .expect("local authority query")
                .is_none()
        );
        assert!(
            quic::WithRemoteAuthority::remote_authority(&conn)
                .await
                .expect("remote authority query")
                .is_none()
        );

        assert!(quic::ManageStream::open_bi(&conn).await.is_err());
        assert!(quic::ManageStream::accept_bi(&conn).await.is_err());
        assert!(quic::ManageStream::accept_uni(&conn).await.is_err());
        assert!(quic::ManageStream::open_uni(&conn).await.is_err());
        assert_eq!(
            conn.stream_calls(),
            vec!["open_bi", "accept_bi", "accept_uni", "open_uni"]
        );

        let mut sink = instruction_sink::<EncoderInstruction>();
        sink.send(EncoderInstruction::SetDynamicTableCapacity { capacity: 1 })
            .await
            .expect("instruction sink accepts values");
    }

    #[tokio::test]
    async fn qpack_protocol_trait_access_and_connection_state_accessor_work() {
        let protocol = qpack_protocol();
        let protocol_ref: &dyn Protocol = &protocol;

        assert!(matches!(
            protocol_ref
                .accept_uni(peekable_uni_from_bytes(&[0x00]).await)
                .await
                .expect("trait object uni verdict"),
            StreamVerdict::Passed(_)
        ));
        assert!(matches!(
            protocol_ref
                .accept_bi(peekable_bi_stream())
                .await
                .expect("trait object bi verdict"),
            StreamVerdict::Passed(_)
        ));

        let conn = Arc::new(MockConnection::with_open_uni_available(true));
        let disabled_state = ConnectionState::new_for_test(conn.clone(), Arc::default());
        assert!(matches!(disabled_state.qpack(), Err(QPackProtocolDisabled)));

        let mut protocols = Protocols::new();
        protocols.insert(qpack_protocol());
        let protocols = Arc::new(protocols);
        let enabled_state = ConnectionState::new_for_test(conn, protocols.clone());
        assert!(std::ptr::eq(
            enabled_state.qpack().expect("qpack protocol should exist"),
            protocols
                .get::<QPackProtocol>()
                .expect("protocol registry should contain qpack"),
        ));
    }

    #[tokio::test]
    async fn qpack_protocol_accepts_encoder_and_decoder_unidirectional_streams() {
        let protocol = qpack_protocol();

        let encoder = peekable_uni_from_bytes(&[0x02]).await;
        assert!(matches!(
            protocol.accept_uni(encoder).await.expect("encoder verdict"),
            StreamVerdict::Accepted
        ));

        let decoder = peekable_uni_from_bytes(&[0x03]).await;
        assert!(matches!(
            protocol.accept_uni(decoder).await.expect("decoder verdict"),
            StreamVerdict::Accepted
        ));
    }

    #[tokio::test]
    async fn qpack_protocol_passes_unknown_or_incomplete_unidirectional_streams() {
        let protocol = qpack_protocol();

        let unknown = peekable_uni_from_bytes(&[0x00, b'h']).await;
        assert!(matches!(
            protocol.accept_uni(unknown).await.expect("unknown verdict"),
            StreamVerdict::Passed(_)
        ));

        let incomplete = peekable_uni_from_bytes(&[]).await;
        assert!(matches!(
            protocol
                .accept_uni(incomplete)
                .await
                .expect("incomplete verdict"),
            StreamVerdict::Passed(_)
        ));
    }

    #[tokio::test]
    async fn qpack_protocol_rejects_duplicate_instruction_streams_with_specific_errors() {
        let protocol = qpack_protocol();

        let first_encoder = peekable_uni_from_bytes(&[0x02]).await;
        assert!(matches!(
            protocol
                .accept_uni(first_encoder)
                .await
                .expect("first encoder verdict"),
            StreamVerdict::Accepted
        ));
        let second_encoder = peekable_uni_from_bytes(&[0x02]).await;
        let error = match protocol.accept_uni(second_encoder).await {
            Ok(_) => panic!("duplicate encoder should fail"),
            Err(error) => error,
        };
        assert_duplicate_stream_creation(error, "qpack encoder stream already exists");

        let first_decoder = peekable_uni_from_bytes(&[0x03]).await;
        assert!(matches!(
            protocol
                .accept_uni(first_decoder)
                .await
                .expect("first decoder verdict"),
            StreamVerdict::Accepted
        ));
        let second_decoder = peekable_uni_from_bytes(&[0x03]).await;
        let error = match protocol.accept_uni(second_decoder).await {
            Ok(_) => panic!("duplicate decoder should fail"),
            Err(error) => error,
        };
        assert_duplicate_stream_creation(error, "qpack decoder stream already exists");
    }

    #[tokio::test]
    async fn qpack_protocol_passes_bidirectional_streams_and_formats_disabled_error() {
        let protocol = qpack_protocol();
        assert!(matches!(
            protocol
                .accept_bi(peekable_bi_stream())
                .await
                .expect("bidi verdict"),
            StreamVerdict::Passed(_)
        ));

        assert_eq!(
            QPackProtocolDisabled.to_string(),
            "qpack protocol is disabled"
        );
    }

    #[tokio::test]
    async fn qpack_protocol_factory_init_requires_dhttp_protocol() {
        let conn = Arc::new(MockConnection::with_open_uni_available(true));
        let factory = QPackProtocolFactory::new();

        let error = factory
            .init(&conn, &Protocols::new())
            .await
            .expect_err("missing dhttp should fail init");

        let quic::ConnectionError::Application { source } = error else {
            panic!("expected application error");
        };
        assert_eq!(source.code, Code::H3_INTERNAL_ERROR);
        assert_eq!(
            source.reason,
            "DHttpLayer must be initialized before QPackLayer"
        );
        assert!(conn.stream_calls().is_empty());
    }

    #[tokio::test]
    async fn qpack_protocol_factory_product_trait_init_matches_inherent_init() {
        let conn = Arc::new(MockConnection::with_open_uni_available(true));
        let dhttp = DHttpProtocolFactory::default()
            .init(&conn)
            .await
            .expect("dhttp init");
        let mut protocols = Protocols::new();
        protocols.insert(dhttp);

        let protocol = ProductProtocol::init(&QPackProtocolFactory::new(), &conn, &protocols)
            .await
            .expect("trait init");

        tokio::task::yield_now().await;

        assert_eq!(conn.stream_calls(), vec!["open_uni"]);
        assert_eq!(
            format!("{protocol:?}"),
            "QPackLayer { encoder: \"...\", decoder: \"...\" }"
        );
    }

    #[tokio::test]
    async fn qpack_protocol_factory_routes_peer_encoder_stream_to_decoder_instruction_receiver() {
        let conn = Arc::new(MockConnection::with_open_uni_available_and_pending_close(
            true,
        ));
        let mut settings = Settings::default();
        settings.set(crate::qpack::settings::QpackMaxTableCapacity::setting(
            VarInt::from_u32(64),
        ));
        let mut dhttp = DHttpProtocolFactory::default()
            .init(&conn)
            .await
            .expect("dhttp init");
        Arc::get_mut(&mut dhttp.state)
            .expect("test dhttp state should be uniquely owned")
            .local_settings = Arc::new(settings);
        let mut protocols = Protocols::new();
        protocols.insert(dhttp);

        let protocol = QPackProtocolFactory::new()
            .init(&conn, &protocols)
            .await
            .expect("qpack init");

        let encoder_stream = peekable_uni_from_bytes(&[
            0x02, // QPACK encoder stream type
            0x3f, 0x21, // SetDynamicTableCapacity { capacity: 64 }
            0x41, b'x', // literal name "x"
            0x01, b'y', // literal value "y"
        ])
        .await;
        assert!(matches!(
            protocol
                .accept_uni(encoder_stream)
                .await
                .expect("encoder stream verdict"),
            StreamVerdict::Accepted
        ));

        protocol
            .decoder
            .receive_instruction_until(1)
            .await
            .expect("peer encoder instruction stream should reach qpack decoder");

        let state = protocol.decoder.state.lock().expect("decoder state lock");
        assert_eq!(state.dynamic_table.capacity, 64);
        assert_eq!(state.dynamic_table.inserted_count, 1);
        assert_eq!(
            state.dynamic_table.get(0).expect("inserted entry").name,
            Bytes::from_static(b"x")
        );
        assert_eq!(
            state.dynamic_table.get(0).expect("inserted entry").value,
            Bytes::from_static(b"y")
        );
    }

    #[tokio::test]
    async fn qpack_protocol_factory_init_is_lazy_until_qpack_streams_are_used() {
        let conn = Arc::new(MockConnection::with_open_uni_available(true));
        let dhttp = DHttpProtocolFactory::default()
            .init(&conn)
            .await
            .expect("dhttp init");
        let mut protocols = Protocols::new();
        protocols.insert(dhttp);

        let protocol = QPackProtocolFactory::new()
            .init(&conn, &protocols)
            .await
            .expect("qpack init");

        assert_eq!(conn.stream_calls(), vec!["open_uni"]);

        {
            let mut state = protocol.encoder.state.lock().await;
            state.emit(EncoderInstruction::SetDynamicTableCapacity { capacity: 1 });
        }
        protocol
            .encoder
            .flush_instructions()
            .await
            .expect("encoder flush opens stream");

        {
            let mut state = protocol.decoder.state.lock().expect("decoder state lock");
            state
                .pending_instructions
                .push_back(DecoderInstruction::SectionAcknowledgment { stream_id: 7 });
        }
        protocol
            .decoder
            .flush_instructions()
            .await
            .expect("decoder flush opens stream");

        assert_eq!(
            conn.stream_calls(),
            vec!["open_uni", "open_uni", "open_uni"]
        );
    }

    #[tokio::test]
    async fn qpack_protocol_factory_init_propagates_qpack_stream_open_errors_when_used() {
        let conn = Arc::new(MockConnection::with_open_uni_available(false));
        let dhttp = {
            let openable = Arc::new(MockConnection::with_open_uni_available(true));
            DHttpProtocolFactory::default()
                .init(&openable)
                .await
                .expect("dhttp init")
        };
        let mut protocols = Protocols::new();
        protocols.insert(dhttp);

        let protocol = QPackProtocolFactory::new()
            .init(&conn, &protocols)
            .await
            .expect("qpack init");

        {
            let mut state = protocol.encoder.state.lock().await;
            state.emit(EncoderInstruction::SetDynamicTableCapacity { capacity: 1 });
        }
        let encoder_error = protocol
            .encoder
            .flush_instructions()
            .await
            .expect_err("encoder flush should surface open_uni failure");
        assert!(matches!(encoder_error, StreamError::Connection { .. }));

        {
            let mut state = protocol.decoder.state.lock().expect("decoder state lock");
            state
                .pending_instructions
                .push_back(DecoderInstruction::SectionAcknowledgment { stream_id: 9 });
        }
        let decoder_error = protocol
            .decoder
            .flush_instructions()
            .await
            .expect_err("decoder flush should surface open_uni failure");
        assert!(matches!(decoder_error, StreamError::Connection { .. }));

        assert_eq!(conn.stream_calls(), vec!["open_uni", "open_uni"]);
    }
}
