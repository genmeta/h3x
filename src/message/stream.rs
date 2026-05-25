use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{SinkExt, TryStreamExt};
use snafu::Snafu;

use crate::{
    codec::{EncodeError, EncodeExt, SinkWriter, StreamReader},
    connection::{self, ConnectionGoaway, ConnectionState, LifecycleExt},
    dhttp::{
        frame::{
            Frame,
            stream::{FrameStream, ReadableFrame},
        },
        protocol::{
            AcceptRawMessageStreamError, BoxDynQuicStreamReader, BoxDynQuicStreamWriter,
            DHttpProtocol, InitialRawMessageStreamError,
        },
    },
    error::{Code, H3FrameDecodeError, H3FrameUnexpected},
    qpack::{
        algorithm::{DynamicCompressAlgo, HuffmanAlways},
        encoder::{EncodeHeaderSectionError, Encoder},
        field::{FieldLine, FieldSection},
        protocol::{QPackDecoder, QPackEncoder, QPackProtocolDisabled},
    },
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    varint::{self, VarInt},
};

pub(crate) mod guard;
#[cfg(feature = "hyper")]
pub(crate) mod hyper;
pub(crate) mod unfold;

pub use self::unfold::{
    read::{BoxMessageStreamReader, ReadMessageStream},
    write::{BoxMessageStreamWriter, WriteMessageStream},
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
pub enum MessageStreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
    #[snafu(display(
        "header section too large to fit into a single frame, maybe too many header fields"
    ))]
    HeaderTooLarge,
    #[snafu(display(
        "trailer section too large to fit into a single frame, maybe too many header fields"
    ))]
    TrailerTooLarge,
    #[snafu(display("data frame payload too large, try smaller chunk size"))]
    DataFrameTooLarge { source: varint::err::Overflow },
    #[snafu(display("http/3 message from peer is malformed"))]
    MalformedIncomingMessage,
    #[snafu(display("message send previously failed"))]
    MessageSendFailed,
}

#[derive(Debug, Snafu)]
#[snafu(display("data frame payload too large, try smaller chunk size"))]
struct DataFrameTooLargeStreamError {
    source: varint::err::Overflow,
}

impl crate::error::H3StreamError for DataFrameTooLargeStreamError {
    fn code(&self) -> Code {
        Code::H3_FRAME_ERROR
    }
}

impl From<quic::ConnectionError> for MessageStreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl From<varint::err::Overflow> for MessageStreamError {
    fn from(source: varint::err::Overflow) -> Self {
        Self::DataFrameTooLarge { source }
    }
}

impl From<MessageStreamError> for io::Error {
    fn from(error: MessageStreamError) -> Self {
        use io::ErrorKind;

        let kind = match &error {
            // Delegate to the underlying QUIC stream error's kind mapping.
            MessageStreamError::Quic { .. } => None,
            MessageStreamError::Goaway { .. } => Some(ErrorKind::ConnectionAborted),
            MessageStreamError::MalformedIncomingMessage => Some(ErrorKind::InvalidData),
            MessageStreamError::MessageSendFailed => Some(ErrorKind::BrokenPipe),
            MessageStreamError::HeaderTooLarge
            | MessageStreamError::TrailerTooLarge
            | MessageStreamError::DataFrameTooLarge { .. } => Some(ErrorKind::InvalidInput),
        };
        match kind {
            Some(kind) => io::Error::new(kind, error),
            None => match error {
                MessageStreamError::Quic { source } => io::Error::from(source),
                _ => unreachable!("non-Quic variants always resolve to a concrete kind"),
            },
        }
    }
}

pub struct ReadStream {
    pub(super) stream: FrameStream<BoxDynQuicStreamReader>,
    pub(super) qpack_decoder: Arc<QPackDecoder>,
    pub(super) state: ConnectionState<dyn quic::DynConnection>,
}

impl ReadStream {
    pub fn new(
        stream: StreamReader<BoxDynQuicStreamReader>,
        qpack_decoder: Arc<QPackDecoder>,
        state: ConnectionState<dyn quic::DynConnection>,
    ) -> Self {
        let frame_stream = FrameStream::new(stream);
        Self {
            stream: frame_stream,
            qpack_decoder,
            state,
        }
    }

    pub fn connection(&self) -> &Arc<dyn quic::DynConnection> {
        self.state.quic()
    }

    pub async fn peer_goaway_covers(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;
        let state = self.state.clone();

        Ok(async move {
            let conn = state.quic().clone();
            let error = conn.closed();
            let dhttp_state = state
                .protocols()
                .get::<DHttpProtocol>()
                .unwrap()
                .state
                .clone();
            tokio::select! {
                biased;
                _goaway = dhttp_state.peer_goaway_covers(stream_id) => Ok(()),
                error = error => Err(error),
            }
        })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        let peer_goaway = self.peer_goaway_covers().await?;
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(error) => Err(self.handle_stream_error(error).await.into()),
            },
            goaway = peer_goaway => match goaway {
                Ok(()) => {
                    // FIXME: which code should be used?
                    _ = self.stream.stop(Code::H3_NO_ERROR.into()).await;
                    Err(ConnectionGoaway::Peer.into())
                }
                Err(error) => Err(error.into())
            }
        }
    }

    /// Resolve a stream-level H3 error into a `quic::StreamError`, performing
    /// the correct side effect for each variant:
    ///
    /// - `Connection` — delegate to [`LifecycleExt::handle_connection_error`]
    ///   so that a fresh H3 connection-scope violation closes the QUIC
    ///   connection.
    /// - `Reset` — nothing to do locally; the peer already reset the stream.
    /// - `H3` — a freshly detected stream-scope protocol violation; issue
    ///   `STOP_SENDING` on this reader so the peer observes the abort.
    pub async fn handle_stream_error(
        &mut self,
        error: connection::StreamError,
    ) -> quic::StreamError {
        match error {
            connection::StreamError::Connection { source } => self
                .state
                .quic()
                .as_ref()
                .handle_connection_error(source)
                .await
                .into(),
            connection::StreamError::Reset { code } => quic::StreamError::Reset { code },
            connection::StreamError::H3 { source } => {
                let code = source.code().into_inner();
                _ = self.stream.stop(code).await;
                quic::StreamError::Reset { code }
            }
        }
    }

    pub async fn peek_frame(
        &mut self,
    ) -> Option<Result<ReadableFrame<'_, BoxDynQuicStreamReader>, connection::StreamError>> {
        loop {
            match Pin::new(&mut self.stream).frame() {
                None => match Pin::new(&mut self.stream).next_unreserved_frame().await? {
                    Ok(_next_frame) => continue,
                    Err(error) => return Some(Err(error)),
                },
                Some(Ok(frame))
                    if frame.r#type() == Frame::HEADERS_FRAME_TYPE
                        || frame.r#type() == Frame::DATA_FRAME_TYPE =>
                {
                    // avoid rust bc bug
                    return Pin::new(&mut self.stream).frame();
                }
                Some(Ok(_frame)) => {
                    return Some(Err(H3FrameUnexpected::UnexpectedFrameType.into()));
                }
                Some(Err(error)) => return Some(Err(error)),
            }
        }
    }

    pub async fn read_data_frame_chunk(
        &mut self,
    ) -> Result<Option<Bytes>, connection::StreamError> {
        loop {
            match self.peek_frame().await {
                Some(Ok(mut frame)) if frame.r#type() == Frame::DATA_FRAME_TYPE => {
                    match frame.try_next().await {
                        Ok(Some(bytes)) => return Ok(Some(bytes)),
                        Ok(None) => {
                            Pin::new(&mut self.stream).consume_current_frame().await?;
                            continue;
                        }
                        Err(error) => {
                            let error = error.into_stream_error(|error| {
                                H3FrameDecodeError { source: error }.into()
                            });
                            return Err(error);
                        }
                    }
                }
                Some(Ok(..)) | None => return Ok(None),
                Some(Err(error)) => return Err(error),
            }
        }
    }

    pub async fn read_header_frame(
        &mut self,
    ) -> Result<Option<FieldSection>, connection::StreamError> {
        match self.peek_frame().await {
            Some(Ok(frame)) if frame.r#type() == Frame::HEADERS_FRAME_TYPE => {
                let Some(frame) = Pin::new(&mut self.stream).frame() else {
                    return Ok(None);
                };
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => return Err(error),
                };
                match self.qpack_decoder.decode(frame).await {
                    Ok(field_section) => {
                        Pin::new(&mut self.stream).consume_current_frame().await?;
                        Ok(Some(field_section))
                    }
                    Err(error) => Err(error),
                }
            }
            Some(Ok(..)) | None => Ok(None),
            Some(Err(error)) => Err(error),
        }
    }

    pub async fn read_data_chunk(&mut self) -> Result<Option<Bytes>, MessageStreamError> {
        self.try_stream_io(async |this| this.read_data_frame_chunk().await)
            .await
    }

    pub async fn read_header(&mut self) -> Result<Option<FieldSection>, MessageStreamError> {
        self.try_stream_io(async |this| this.read_header_frame().await)
            .await
    }

    pub async fn stop(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.stop(code.into_inner()).await?))
            .await
    }

    pub fn take(&mut self) -> Self {
        let taken = self.stream.inner_mut().take();
        Self {
            stream: FrameStream::new(StreamReader::new(taken)),
            qpack_decoder: self.qpack_decoder.clone(),
            state: self.state.clone(),
        }
    }
}

impl quic::GetStreamId for ReadStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl quic::StopStream for ReadStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stop(cx, code)
    }
}

pub struct WriteStream {
    pub(super) stream: SinkWriter<BoxDynQuicStreamWriter>,
    pub(super) qpack_encoder: Arc<QPackEncoder>,
    pub(super) state: ConnectionState<dyn quic::DynConnection>,
}

pub const DEFAULT_COMPRESS_ALGO: DynamicCompressAlgo<HuffmanAlways> =
    DynamicCompressAlgo::new(HuffmanAlways);

impl WriteStream {
    pub fn new(
        stream: SinkWriter<BoxDynQuicStreamWriter>,
        qpack_encoder: Arc<QPackEncoder>,
        state: ConnectionState<dyn quic::DynConnection>,
    ) -> Self {
        Self {
            stream,
            qpack_encoder,
            state,
        }
    }

    pub async fn write_frame(
        &mut self,
        frame: Frame<impl Buf + Send>,
    ) -> Result<(), connection::StreamError> {
        self.stream.encode_one(frame).await?;
        Ok(())
    }

    pub async fn write_data_frame(
        &mut self,
        data: impl Buf + Send,
    ) -> Result<(), connection::StreamError> {
        let frame = match Frame::new(Frame::DATA_FRAME_TYPE, data) {
            Ok(frame) => frame,
            Err(source) => return Err(DataFrameTooLargeStreamError { source }.into()),
        };
        self.write_frame(frame).await
    }

    pub async fn write_data(&mut self, data: impl Buf + Send) -> Result<(), MessageStreamError> {
        let frame = Frame::new(Frame::DATA_FRAME_TYPE, data)?;
        self.try_stream_io(async move |this| this.write_frame(frame).await)
            .await
    }

    pub async fn send_data(&mut self, data: impl Buf + Send) -> Result<(), MessageStreamError> {
        self.write_data(data).await
    }

    async fn peer_goaway_covers(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;
        let state = self.state.clone();

        Ok(async move {
            let conn = state.quic().clone();
            let error = conn.closed();
            let dhttp_state = state
                .protocols()
                .get::<DHttpProtocol>()
                .unwrap()
                .state
                .clone();
            tokio::select! {
                biased;
                _goaway = dhttp_state.peer_goaway_covers(stream_id) => Ok(()),
                error = error => Err(error),
            }
        })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        let peer_goaway = self.peer_goaway_covers().await?;
        let f = async move |this: &mut Self| {
            let value = f(this).await?;
            // ensure all data are written into the underlying QUIC stream
            this.stream.flush_buffer().await?;
            Ok(value)
        };
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(error) => Err(self.handle_stream_error(error).await.into()),
            },
            goaway = peer_goaway => match goaway {
                Ok(()) => {
                    // FIXME: which code should be used?
                    _ = self.stream.cancel(Code::H3_NO_ERROR.into()).await;
                    Err(ConnectionGoaway::Peer.into())
                }
                Err(error) => Err(error.into())
            }
        }
    }

    /// Resolve a stream-level H3 error into a `quic::StreamError`. See
    /// [`ReadStream::handle_stream_error`] for semantics; the difference is
    /// that `H3` errors issue `RESET_STREAM` (via `cancel`) on this writer
    /// instead of `STOP_SENDING`.
    pub async fn handle_stream_error(
        &mut self,
        error: connection::StreamError,
    ) -> quic::StreamError {
        match error {
            connection::StreamError::Connection { source } => self
                .state
                .quic()
                .as_ref()
                .handle_connection_error(source)
                .await
                .into(),
            connection::StreamError::Reset { code } => quic::StreamError::Reset { code },
            connection::StreamError::H3 { source } => {
                let code = source.code().into_inner();
                _ = self.stream.cancel(code).await;
                quic::StreamError::Reset { code }
            }
        }
    }

    pub async fn write_header_frame(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<Result<(), EncodeError>, connection::StreamError> {
        let algo = &DEFAULT_COMPRESS_ALGO;
        let stream = &mut self.stream;
        match Encoder::encode(&*self.qpack_encoder, field_lines, algo, stream).await {
            Ok(frame) => Ok(Ok(self.write_frame(frame).await?)),
            Err(EncodeHeaderSectionError::Encode { source }) => Ok(Err(source)),
            Err(EncodeHeaderSectionError::Stream { source }) => Err(source),
        }
    }

    pub async fn write_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        let result = self
            .try_stream_io(async move |this| this.write_header_frame(field_lines).await)
            .await?;

        // Flush encoder instructions (dynamic table insertions) to the encoder stream.
        // Encoder stream errors are connection-level: reset = connection error per RFC 9204.
        if let Err(error) = self.qpack_encoder.flush_instructions().await {
            let quic_error = self.handle_stream_error(error).await;
            return Err(quic_error.into());
        }

        match result {
            Ok(()) => Ok(()),
            Err(EncodeError::FramePayloadTooLarge) => Err(MessageStreamError::HeaderTooLarge),
            Err(EncodeError::HuffmanEncoding) => {
                unreachable!("FieldSection contain invalid header name/value, this is a bug")
            }
        }
    }

    pub async fn send_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        self.write_header(field_lines).await
    }

    pub async fn flush(&mut self) -> Result<(), MessageStreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.flush_inner().await?))
            .await
    }

    pub async fn close(&mut self) -> Result<(), MessageStreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.close().await?))
            .await
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.cancel(code.into_inner()).await?))
            .await
    }

    pub fn take(&mut self) -> Self {
        let taken = self.stream.sink_mut().take();
        Self {
            stream: SinkWriter::new(taken),
            qpack_encoder: self.qpack_encoder.clone(),
            state: self.state.clone(),
        }
    }
}

impl quic::GetStreamId for WriteStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl quic::CancelStream for WriteStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_cancel(cx, code)
    }
}

#[derive(Debug, Snafu, Clone)]
pub enum InitialMessageStreamError {
    #[snafu(transparent)]
    InitialRawStream {
        source: InitialRawMessageStreamError,
    },
    #[snafu(transparent)]
    QPackProtocolDisabled { source: QPackProtocolDisabled },
}

#[derive(Debug, Snafu, Clone)]
pub enum AcceptMessageStreamError {
    #[snafu(transparent)]
    AcceptRawStream { source: AcceptRawMessageStreamError },
    #[snafu(transparent)]
    QPackProtocolDisabled { source: QPackProtocolDisabled },
}

impl<C: quic::Connection> ConnectionState<C> {
    pub async fn initial_message_stream(
        &self,
    ) -> Result<(ReadStream, WriteStream), InitialMessageStreamError> {
        let state = self.erase();
        let qpack = self.qpack()?;
        let (reader, writer) = self.initial_raw_message_stream().await?;
        Ok((
            ReadStream::new(reader, qpack.decoder.clone(), state.clone()),
            WriteStream::new(writer, qpack.encoder.clone(), state),
        ))
    }

    pub async fn accept_message_stream(
        &self,
    ) -> Result<(ReadStream, WriteStream), AcceptMessageStreamError> {
        let state = self.erase();
        let qpack = self.qpack()?;
        let (reader, writer) = self.accept_raw_message_stream().await?;
        Ok((
            ReadStream::new(reader, qpack.decoder.clone(), state.clone()),
            WriteStream::new(writer, qpack.encoder.clone(), state),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use bytes::{Buf, Bytes};
    use futures::{Sink, SinkExt, Stream};

    use super::{MessageStreamError, ReadStream, WriteStream, guard};
    use crate::{
        codec::{SinkWriter, StreamReader},
        connection::{ConnectionState, StreamError, tests::MockConnection},
        dhttp::{goaway::Goaway, protocol::DHttpProtocol, settings::Settings},
        error::Code,
        message::test::{read_stream_for_test, write_stream_for_test},
        protocol::Protocols,
        qpack::protocol::{QPackDecoder, QPackEncoder},
        quic::{self, GetStreamIdExt},
        varint::VarInt,
    };

    #[test]
    fn io_error_kind_is_derived_per_variant() {
        use std::io::ErrorKind;

        fn assert_kind(error: MessageStreamError, expected: ErrorKind) {
            let repr = format!("{error:?}");
            let io_error = std::io::Error::from(error);
            assert_eq!(io_error.kind(), expected, "unexpected kind for {repr}");
        }

        assert_kind(MessageStreamError::HeaderTooLarge, ErrorKind::InvalidInput);
        assert_kind(MessageStreamError::TrailerTooLarge, ErrorKind::InvalidInput);
        assert_kind(
            MessageStreamError::DataFrameTooLarge {
                source: crate::varint::VarInt::from_u64(1 << 63)
                    .expect_err("value exceeds varint encoding"),
            },
            ErrorKind::InvalidInput,
        );
        assert_kind(
            MessageStreamError::MalformedIncomingMessage,
            ErrorKind::InvalidData,
        );
        assert_kind(
            MessageStreamError::Goaway {
                source: crate::connection::ConnectionGoaway::Peer,
            },
            ErrorKind::ConnectionAborted,
        );
        assert_kind(
            MessageStreamError::Quic {
                source: quic::StreamError::Reset {
                    code: VarInt::from_u32(0),
                },
            },
            ErrorKind::BrokenPipe,
        );
    }

    fn qpack_decoder_sink()
    -> Pin<Box<dyn Sink<crate::qpack::decoder::DecoderInstruction, Error = StreamError> + Send>>
    {
        Box::pin(
            futures::sink::drain::<crate::qpack::decoder::DecoderInstruction>()
                .sink_map_err(|never| match never {}),
        )
    }

    fn qpack_decoder_stream() -> Pin<
        Box<
            dyn Stream<Item = Result<crate::qpack::encoder::EncoderInstruction, StreamError>>
                + Send,
        >,
    > {
        Box::pin(futures::stream::empty::<
            Result<crate::qpack::encoder::EncoderInstruction, StreamError>,
        >())
    }

    fn qpack_encoder_sink()
    -> Pin<Box<dyn Sink<crate::qpack::encoder::EncoderInstruction, Error = StreamError> + Send>>
    {
        Box::pin(
            futures::sink::drain::<crate::qpack::encoder::EncoderInstruction>()
                .sink_map_err(|never| match never {}),
        )
    }

    fn qpack_encoder_stream() -> Pin<
        Box<
            dyn Stream<Item = Result<crate::qpack::decoder::DecoderInstruction, StreamError>>
                + Send,
        >,
    > {
        Box::pin(futures::stream::empty::<
            Result<crate::qpack::decoder::DecoderInstruction, StreamError>,
        >())
    }

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

    impl quic::CancelStream for TestWriteStream {
        fn poll_cancel(
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

    #[tokio::test]
    async fn read_stream_try_stream_io_aborts_when_peer_goaway_covers_stream() {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(erased, Arc::new(protocols));

        let reader = StreamReader::new(guard::GuardedQuicReader::new(Box::pin(TestReadStream {
            stream_id: VarInt::from_u32(10),
        })
            as crate::codec::BoxReadStream));
        let mut read_stream = ReadStream::new(
            reader,
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state.clone(),
        );

        state
            .dhttp()
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(9)))
            .expect("peer goaway should be accepted");

        let result = read_stream
            .try_stream_io(async move |_this| {
                futures::future::pending::<Result<(), crate::connection::StreamError>>().await
            })
            .await;

        assert!(matches!(
            result,
            Err(super::MessageStreamError::Goaway {
                source: crate::connection::ConnectionGoaway::Peer
            })
        ));
    }

    #[tokio::test]
    async fn write_stream_try_stream_io_aborts_when_peer_goaway_covers_stream() {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(erased, Arc::new(protocols));

        let writer = SinkWriter::new(guard::GuardedQuicWriter::new(Box::pin(TestWriteStream {
            stream_id: VarInt::from_u32(12),
        })
            as crate::codec::BoxWriteStream));
        let mut write_stream = WriteStream::new(
            writer,
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state.clone(),
        );

        state
            .dhttp()
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(11)))
            .expect("peer goaway should be accepted");

        let result = write_stream
            .try_stream_io(async move |_this| {
                futures::future::pending::<Result<(), crate::connection::StreamError>>().await
            })
            .await;

        assert!(matches!(
            result,
            Err(super::MessageStreamError::Goaway {
                source: crate::connection::ConnectionGoaway::Peer
            })
        ));
    }

    #[tokio::test]
    async fn test_read_stream_new() {
        let stream_id = VarInt::from_u32(42);
        let mut rs = read_stream_for_test(stream_id);
        let got = rs.stream_id().await.expect("stream_id should resolve");
        assert_eq!(got, stream_id);
    }

    #[tokio::test]
    async fn test_read_stream_connection() {
        let rs = read_stream_for_test(VarInt::from_u32(0));
        let conn = rs.connection();
        assert!(
            std::sync::Arc::strong_count(conn) >= 1,
            "connection should return a valid Arc"
        );
    }

    #[tokio::test]
    async fn test_read_stream_peer_goaway_covers() {
        let mut rs = read_stream_for_test(VarInt::from_u32(0));
        let covers = rs
            .peer_goaway_covers()
            .await
            .expect("peer_goaway_covers should resolve without error");
        drop(covers);
    }

    #[tokio::test]
    async fn read_data_frame_chunk_returns_result_option_stream_error() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let result: Result<Option<Bytes>, StreamError> = stream.read_data_frame_chunk().await;

        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_header_frame_returns_result_option_stream_error() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let result: Result<Option<crate::qpack::field::FieldSection>, StreamError> =
            stream.read_header_frame().await;

        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn high_level_read_methods_return_message_stream_error() {
        let mut stream = read_stream_for_test(VarInt::from_u32(0));

        let data: Result<Option<Bytes>, MessageStreamError> = stream.read_data_chunk().await;
        let header: Result<Option<crate::qpack::field::FieldSection>, MessageStreamError> =
            stream.read_header().await;

        assert!(data.unwrap().is_none());
        assert!(header.unwrap().is_none());
    }

    #[tokio::test]
    async fn write_data_frame_returns_connection_stream_error() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let result: Result<(), StreamError> =
            stream.write_data_frame(Bytes::from_static(b"hello")).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn write_data_returns_message_stream_error() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let result: Result<(), MessageStreamError> =
            stream.write_data(Bytes::from_static(b"hello")).await;

        assert!(result.is_ok());
    }

    struct OversizedBuf;

    impl Buf for OversizedBuf {
        fn remaining(&self) -> usize {
            (VarInt::MAX.into_inner() as usize) + 1
        }

        fn chunk(&self) -> &[u8] {
            &[]
        }

        fn advance(&mut self, _cnt: usize) {
            unreachable!("oversized payload should fail before writing")
        }
    }

    #[tokio::test]
    async fn write_data_oversized_payload_returns_data_frame_too_large() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let result = stream.write_data(OversizedBuf).await;

        assert!(matches!(
            result,
            Err(MessageStreamError::DataFrameTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn send_data_alias_delegates_to_write_data() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let result = stream.send_data(Bytes::from_static(b"hello")).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_read_stream_stop() {
        let mut rs = read_stream_for_test(VarInt::from_u32(0));
        rs.stop(Code::H3_NO_ERROR)
            .await
            .expect("stop should succeed on mock");
    }
}
