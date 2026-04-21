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
            DHttpState, InitialRawMessageStreamError,
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
#[derive(Debug, Snafu)]
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
    #[snafu(display("HTTP/3 message from peer is malformed"))]
    MalformedIncomingMessage,
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
    pub(super) connection: Arc<dyn quic::DynLifecycle + Send + Sync>,
    dhttp_state: Arc<DHttpState>,
}

impl ReadStream {
    pub fn new(
        stream: StreamReader<BoxDynQuicStreamReader>,
        qpack_decoder: Arc<QPackDecoder>,
        connection: Arc<dyn quic::DynLifecycle + Send + Sync>,
        dhttp_state: Arc<DHttpState>,
    ) -> Self {
        let frame_stream = FrameStream::new(stream);
        Self {
            stream: frame_stream,
            qpack_decoder,
            connection,
            dhttp_state,
        }
    }

    pub async fn peer_goaway_covers(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;
        let dhttp_state = self.dhttp_state.clone();
        let conn = self.connection.clone();

        Ok(async move {
            let error = conn.closed();
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
                .connection
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
    ) -> Option<Result<Bytes, connection::StreamError>> {
        loop {
            match self.peek_frame().await {
                Some(Ok(mut frame)) if frame.r#type() == Frame::DATA_FRAME_TYPE => {
                    match frame.try_next().await {
                        Ok(Some(bytes)) => return Some(Ok(bytes)),
                        Ok(None) => {
                            _ = Pin::new(&mut self.stream).consume_current_frame().await;
                            continue;
                        }
                        Err(error) => {
                            let error = error.into_stream_error(|error| {
                                H3FrameDecodeError { source: error }.into()
                            });
                            return Some(Err(error));
                        }
                    }
                }
                Some(Ok(..)) | None => return None,
                Some(Err(error)) => return Some(Err(error)),
            }
        }
    }

    pub async fn read_header_frame(
        &mut self,
    ) -> Option<Result<FieldSection, connection::StreamError>> {
        match self.peek_frame().await {
            Some(Ok(frame)) if frame.r#type() == Frame::HEADERS_FRAME_TYPE => {
                let frame = match Pin::new(&mut self.stream).frame()? {
                    Ok(frame) => frame,
                    Err(error) => return Some(Err(error)),
                };
                match self.qpack_decoder.decode(frame).await {
                    Ok(field_section) => {
                        _ = Pin::new(&mut self.stream).consume_current_frame().await;
                        Some(Ok(field_section))
                    }
                    Err(error) => Some(Err(error)),
                }
            }
            Some(Ok(..)) | None => None,
            Some(Err(error)) => Some(Err(error)),
        }
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
            connection: self.connection.clone(),
            dhttp_state: self.dhttp_state.clone(),
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
    pub(super) connection: Arc<dyn quic::DynLifecycle + Send + Sync>,
    dhttp_state: Arc<DHttpState>,
}

pub const DEFAULT_COMPRESS_ALGO: DynamicCompressAlgo<HuffmanAlways> =
    DynamicCompressAlgo::new(HuffmanAlways);

impl WriteStream {
    pub fn new(
        stream: SinkWriter<BoxDynQuicStreamWriter>,
        qpack_encoder: Arc<QPackEncoder>,
        connection: Arc<dyn quic::DynLifecycle + Send + Sync>,
        dhttp_state: Arc<DHttpState>,
    ) -> Self {
        Self {
            stream,
            qpack_encoder,
            connection,
            dhttp_state,
        }
    }

    pub async fn send_frame(
        &mut self,
        frame: Frame<impl Buf + Send>,
    ) -> Result<(), quic::StreamError> {
        self.stream.encode_one(frame).await
    }

    async fn peer_goaway_covers(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;
        let dhttp_state = self.dhttp_state.clone();
        let conn = self.connection.clone();

        Ok(async move {
            let error = conn.closed();
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
                .connection
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

    pub async fn send_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        let algo = &DEFAULT_COMPRESS_ALGO;
        let result = self
            .try_stream_io(async move |this| {
                let stream = &mut this.stream;
                match Encoder::encode(&*this.qpack_encoder, field_lines, algo, stream).await {
                    Ok(frame) => Ok(Ok(this.send_frame(frame).await?)),
                    Err(EncodeHeaderSectionError::Encode { source }) => Ok(Err(source)),
                    Err(EncodeHeaderSectionError::Stream { source }) => Err(source),
                }
            })
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
            connection: self.connection.clone(),
            dhttp_state: self.dhttp_state.clone(),
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
        let qpack = self.qpack()?;
        let dhttp = self.dhttp();
        let (reader, writer) = self.initial_raw_message_stream().await?;
        Ok((
            ReadStream::new(
                reader,
                qpack.decoder.clone(),
                self.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
                dhttp.state.clone(),
            ),
            WriteStream::new(
                writer,
                qpack.encoder.clone(),
                self.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
                dhttp.state.clone(),
            ),
        ))
    }

    pub async fn accept_message_stream(
        &self,
    ) -> Result<(ReadStream, WriteStream), AcceptMessageStreamError> {
        let qpack = self.qpack()?;
        let dhttp = self.dhttp();
        let (reader, writer) = self.accept_raw_message_stream().await?;
        Ok((
            ReadStream::new(
                reader,
                qpack.decoder.clone(),
                self.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
                dhttp.state.clone(),
            ),
            WriteStream::new(
                writer,
                qpack.encoder.clone(),
                self.quic().clone() as Arc<dyn quic::DynLifecycle + Send + Sync>,
                dhttp.state.clone(),
            ),
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

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream};

    use super::{MessageStreamError, ReadStream, WriteStream, guard};
    use crate::{
        codec::{SinkWriter, StreamReader},
        connection::{ConnectionState, StreamError, tests::MockConnection},
        dhttp::{goaway::Goaway, protocol::DHttpProtocol, settings::Settings},
        protocol::Protocols,
        qpack::protocol::{QPackDecoder, QPackEncoder},
        quic,
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
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let connection: Arc<dyn quic::DynLifecycle + Send + Sync> = quic.clone();

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));

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
            connection,
            state.dhttp().state.clone(),
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
        let quic = Arc::new(MockConnection::new());
        let erased_connection: Arc<dyn quic::DynConnection> = quic.clone();
        let connection: Arc<dyn quic::DynLifecycle + Send + Sync> = quic.clone();

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased_connection));
        let state = ConnectionState::new_for_test(quic.clone(), Arc::new(protocols));

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
            connection,
            state.dhttp().state.clone(),
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
}
