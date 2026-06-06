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
        protocol::{AcceptRawMessageStreamError, DHttpProtocol, InitialRawMessageStreamError},
    },
    error::{Code, H3FrameDecodeError, H3FrameUnexpected},
    qpack::{
        algorithm::{DynamicCompressAlgo, HuffmanAlways},
        decoder::QPackMessageStreamReader,
        encoder::{EncodeHeaderSectionError, Encoder},
        field::{FieldLine, FieldSection},
        protocol::{QPackDecoder, QPackEncoder, QPackProtocolDisabled},
    },
    quic::{self, GetStreamIdExt, ResetStreamExt, StopStreamExt},
    varint::{self, VarInt},
};

pub(crate) mod guard;
#[cfg(feature = "hyper")]
pub mod hyper;
pub mod unfold;

pub type BoxMessageReader<
    S = dyn crate::stream::ReadStream<
        Bytes,
        MessageStreamError,
        quic::StreamError,
        quic::StreamError,
    > + Send,
> = Pin<Box<S>>;

pub type BoxMessageWriter<
    S = dyn crate::stream::WriteStream<
        Bytes,
        MessageStreamError,
        quic::StreamError,
        quic::StreamError,
    > + Send,
> = Pin<Box<S>>;

impl quic::GetStreamId
    for dyn crate::stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + Send
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        crate::stream::GetStreamId::poll_stream_id(self, cx)
    }
}

impl quic::StopStream
    for dyn crate::stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + Send
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        crate::stream::StopStream::poll_stop(self, cx, code)
    }
}

impl quic::GetStreamId
    for dyn crate::stream::WriteStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + Send
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        crate::stream::GetStreamId::poll_stream_id(self, cx)
    }
}

impl quic::ResetStream
    for dyn crate::stream::WriteStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + Send
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        crate::stream::ResetStream::poll_reset(self, cx, code)
    }
}

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
    #[snafu(display("http/3 message to send is malformed"))]
    MalformedOutgoingMessage,
    #[snafu(display("message send previously failed"))]
    MessageSendFailed,
    #[snafu(display("message writer is closed"))]
    MessageWriterClosed,
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
            MessageStreamError::MalformedOutgoingMessage => Some(ErrorKind::InvalidInput),
            MessageStreamError::MessageSendFailed | MessageStreamError::MessageWriterClosed => {
                Some(ErrorKind::BrokenPipe)
            }
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

pub struct MessageReader {
    pub(super) stream: FrameStream<guard::GuardQuicReader>,
    pub(super) qpack_decoder: Arc<QPackDecoder>,
    pub(super) state: ConnectionState<dyn quic::DynConnection>,
}

impl MessageReader {
    pub fn new(
        stream_id: VarInt,
        stream: StreamReader<guard::GuardQuicReader>,
        qpack_decoder: Arc<QPackDecoder>,
        state: ConnectionState<dyn quic::DynConnection>,
    ) -> Self {
        let decoder = qpack_decoder.clone();
        let stream =
            stream.map_stream(move |guarded| {
                let mut stream = guard::GuardQuicReader::new(Box::pin(
                    QPackMessageStreamReader::new(stream_id, guarded.into_inner(), decoder),
                ));
                stream.set_stream_id(stream_id);
                stream
            });
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

    pub async fn peek_frame(
        &mut self,
    ) -> Option<Result<ReadableFrame<'_, guard::GuardQuicReader>, connection::StreamError>> {
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
        self.try_stream_read(async |this| this.read_data_frame_chunk().await)
            .await
    }

    pub async fn read_header(&mut self) -> Result<Option<FieldSection>, MessageStreamError> {
        self.try_stream_read(async |this| this.read_header_frame().await)
            .await
    }

    pub async fn stop(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.try_stream_read(async move |this| Ok(this.stream.stop(code.into_inner()).await?))
            .await
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

    pub async fn try_stream_read<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        let peer_goaway = self.peer_goaway_covers().await?;
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(error) => Err(MessageStreamError::Quic {
                    source: self.handle_stream_error(error).await,
                }),
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
            connection::StreamError::Connection { source } => {
                let source = self
                    .state
                    .quic()
                    .as_ref()
                    .handle_connection_error(source)
                    .await;
                self.stream
                    .inner_mut()
                    .mark_connection_closed(source.clone());
                source.into()
            }
            connection::StreamError::Reset { code } => {
                self.stream.inner_mut().mark_reset(code);
                quic::StreamError::Reset { code }
            }
            connection::StreamError::H3 { source } => {
                let code = source.code().into_inner();
                _ = self.stream.stop(code).await;
                quic::StreamError::Reset { code }
            }
        }
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

impl quic::GetStreamId for MessageReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl quic::StopStream for MessageReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stop(cx, code)
    }
}

impl crate::stream::GetStreamId<quic::StreamError> for MessageReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        quic::GetStreamId::poll_stream_id(self, cx)
    }
}

impl crate::stream::StopStream<quic::StreamError> for MessageReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        quic::StopStream::poll_stop(self, cx, code)
    }
}

pub struct MessageWriter {
    pub(super) stream: SinkWriter<guard::GuardQuicWriter>,
    pub(super) qpack_encoder: Arc<QPackEncoder>,
    pub(super) state: ConnectionState<dyn quic::DynConnection>,
}

pub const DEFAULT_COMPRESS_ALGO: DynamicCompressAlgo<HuffmanAlways> =
    DynamicCompressAlgo::new(HuffmanAlways);

impl MessageWriter {
    pub fn new(
        stream: SinkWriter<guard::GuardQuicWriter>,
        qpack_encoder: Arc<QPackEncoder>,
        state: ConnectionState<dyn quic::DynConnection>,
    ) -> Self {
        Self {
            stream,
            qpack_encoder,
            state,
        }
    }

    fn ensure_write_open(&self) -> Result<(), MessageStreamError> {
        match self.stream.sink().state_snapshot() {
            guard::QuicWriterStateSnapshot::Open => Ok(()),
            guard::QuicWriterStateSnapshot::Closed => Err(MessageStreamError::MessageWriterClosed),
            guard::QuicWriterStateSnapshot::Reset { code } => Err(MessageStreamError::Quic {
                source: quic::StreamError::Reset { code },
            }),
            guard::QuicWriterStateSnapshot::ConnectionClosed { source } => {
                Err(MessageStreamError::Quic {
                    source: quic::StreamError::Connection { source },
                })
            }
            guard::QuicWriterStateSnapshot::Taken => {
                panic!("message writer used after being taken, this is a bug")
            }
        }
    }

    pub async fn write_frame(
        &mut self,
        frame: Frame<impl Buf + Send>,
    ) -> Result<(), MessageStreamError> {
        self.try_stream_write(async move |this| {
            this.stream.encode_one(frame).await?;
            Ok(())
        })
        .await
    }

    pub async fn write_data_frame(
        &mut self,
        data: impl Buf + Send,
    ) -> Result<(), MessageStreamError> {
        let frame = Frame::new(Frame::DATA_FRAME_TYPE, data)?;
        self.write_frame(frame).await
    }

    pub async fn write_header_frame(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        let result = self
            .try_stream_write(async move |this| {
                let algo = &DEFAULT_COMPRESS_ALGO;
                match Encoder::encode(&*this.qpack_encoder, field_lines, algo, &mut this.stream)
                    .await
                {
                    Ok(frame) => {
                        this.stream.encode_one(frame).await?;
                        Ok(Ok(()))
                    }
                    Err(EncodeHeaderSectionError::Encode { source }) => Ok(Err(source)),
                    Err(EncodeHeaderSectionError::Stream { source }) => Err(source),
                }
            })
            .await?;

        match result {
            Ok(()) => Ok(()),
            Err(EncodeError::FramePayloadTooLarge) => Err(MessageStreamError::HeaderTooLarge),
            Err(EncodeError::HuffmanEncoding) => {
                unreachable!("FieldSection contain invalid header name/value, this is a bug")
            }
        }
    }

    pub async fn write_data(&mut self, data: impl Buf + Send) -> Result<(), MessageStreamError> {
        self.write_data_frame(data).await
    }

    pub async fn write_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        self.write_header_frame(field_lines).await?;

        // Flush encoder instructions (dynamic table insertions) to the encoder stream.
        // Encoder stream errors are connection-level: reset = connection error per RFC 9204.
        if let Err(error) = self.qpack_encoder.flush_instructions().await {
            let quic_error = self.handle_stream_error(error).await;
            return Err(MessageStreamError::Quic { source: quic_error });
        }

        Ok(())
    }

    pub async fn send_data(&mut self, data: impl Buf + Send) -> Result<(), MessageStreamError> {
        self.write_data(data).await
    }

    pub async fn send_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), MessageStreamError> {
        self.write_header(field_lines).await
    }

    pub async fn flush(&mut self) -> Result<(), MessageStreamError> {
        self.try_stream_write(async move |this| Ok(this.stream.flush_inner().await?))
            .await
    }

    pub async fn close(&mut self) -> Result<(), MessageStreamError> {
        self.try_stream_write(async move |this| Ok(this.stream.close().await?))
            .await
    }

    pub async fn reset(&mut self, code: Code) -> Result<(), MessageStreamError> {
        self.try_stream_write(async move |this| Ok(this.stream.reset(code.into_inner()).await?))
            .await
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

    pub async fn try_stream_write<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        self.ensure_write_open()?;
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
                Err(error) => Err(MessageStreamError::Quic {
                    source: self.handle_stream_error(error).await,
                }),
            },
            goaway = peer_goaway => match goaway {
                Ok(()) => {
                    // FIXME: which code should be used?
                    _ = self.stream.reset(Code::H3_NO_ERROR.into()).await;
                    Err(ConnectionGoaway::Peer.into())
                }
                Err(error) => Err(error.into())
            }
        }
    }

    /// Resolve a stream-level H3 error into a `quic::StreamError`. See
    /// [`MessageReader::handle_stream_error`] for semantics; the difference is
    /// that `H3` errors issue `RESET_STREAM` (via `reset`) on this writer
    /// instead of `STOP_SENDING`.
    pub async fn handle_stream_error(
        &mut self,
        error: connection::StreamError,
    ) -> quic::StreamError {
        match error {
            connection::StreamError::Connection { source } => {
                let source = self
                    .state
                    .quic()
                    .as_ref()
                    .handle_connection_error(source)
                    .await;
                self.stream
                    .sink_mut()
                    .mark_connection_closed(source.clone());
                source.into()
            }
            connection::StreamError::Reset { code } => {
                self.stream.sink_mut().mark_reset(code);
                quic::StreamError::Reset { code }
            }
            connection::StreamError::H3 { source } => {
                let code = source.code().into_inner();
                _ = self.stream.reset(code).await;
                quic::StreamError::Reset { code }
            }
        }
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

impl quic::GetStreamId for MessageWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl quic::ResetStream for MessageWriter {
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_reset(cx, code)
    }
}

impl crate::stream::GetStreamId<quic::StreamError> for MessageWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        quic::GetStreamId::poll_stream_id(self, cx)
    }
}

impl crate::stream::ResetStream<quic::StreamError> for MessageWriter {
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        quic::ResetStream::poll_reset(self, cx, code)
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
    ) -> Result<(MessageReader, MessageWriter), InitialMessageStreamError> {
        let state = self.erase();
        let qpack = self.qpack()?;
        let (mut reader, writer) = self.initial_raw_message_stream().await?;
        let stream_id = reader.stream_id().await.map_err(|source| {
            InitialMessageStreamError::InitialRawStream {
                source: InitialRawMessageStreamError::ResponseStream { source },
            }
        })?;
        Ok((
            MessageReader::new(stream_id, reader, qpack.decoder.clone(), state.clone()),
            MessageWriter::new(writer, qpack.encoder.clone(), state),
        ))
    }

    pub async fn accept_message_stream(
        &self,
    ) -> Result<(MessageReader, MessageWriter), AcceptMessageStreamError> {
        let state = self.erase();
        let qpack = self.qpack()?;
        let (mut reader, writer) = self.accept_raw_message_stream().await?;
        let stream_id = reader.stream_id().await.map_err(|source| {
            AcceptMessageStreamError::AcceptRawStream {
                source: AcceptRawMessageStreamError::RequestStream { source },
            }
        })?;
        Ok((
            MessageReader::new(stream_id, reader, qpack.decoder.clone(), state.clone()),
            MessageWriter::new(writer, qpack.encoder.clone(), state),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::{Buf, Bytes};
    use futures::{Sink, SinkExt, Stream, future::poll_fn};
    use tokio::{sync::mpsc, time::timeout};

    use super::{MessageReader, MessageStreamError, MessageWriter, guard};
    use crate::{
        codec::{
            BoxPeekableStreamReader, BoxStreamWriter, PeekableStreamReader, SinkWriter,
            StreamReader,
        },
        connection::{ConnectionState, StreamError, tests::MockConnection},
        dhttp::{
            goaway::Goaway,
            message::test::{read_stream_for_test, write_stream_for_test},
            protocol::DHttpProtocol,
            settings::Settings,
        },
        error::Code,
        protocol::{Protocol, Protocols, StreamVerdict},
        qpack::protocol::{QPackDecoder, QPackEncoder, QPackProtocolFactory},
        quic::{self, GetStreamId, GetStreamIdExt, ResetStream, StopStream},
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
            MessageStreamError::MalformedOutgoingMessage,
            ErrorKind::InvalidInput,
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

    #[derive(Debug)]
    struct StreamIdErrorReadStream {
        error: quic::StreamError,
    }

    impl quic::GetStreamId for StreamIdErrorReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Err(self.get_mut().error.clone()))
        }
    }

    impl quic::StopStream for StreamIdErrorReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for StreamIdErrorReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let _ = self;
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct StreamIdErrorWriteStream {
        error: quic::StreamError,
    }

    impl quic::GetStreamId for StreamIdErrorWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Err(self.get_mut().error.clone()))
        }
    }

    impl quic::ResetStream for StreamIdErrorWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for StreamIdErrorWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            let _ = self;
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TrackedReadStream {
        stream_id: VarInt,
        stop_tx: mpsc::UnboundedSender<VarInt>,
    }

    impl quic::GetStreamId for TrackedReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl quic::StopStream for TrackedReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.get_mut()
                .stop_tx
                .send(code)
                .expect("tracked reader receiver should still be alive");
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TrackedReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let _ = self;
            Poll::Ready(None)
        }
    }

    #[derive(Debug)]
    struct TrackedWriteStream {
        stream_id: VarInt,
        reset_tx: mpsc::UnboundedSender<VarInt>,
    }

    impl quic::GetStreamId for TrackedWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl quic::ResetStream for TrackedWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.get_mut()
                .reset_tx
                .send(code)
                .expect("tracked writer receiver should still be alive");
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for TrackedWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            let _ = self;
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let _ = self;
            Poll::Ready(Ok(()))
        }
    }

    fn state_without_qpack(quic: Arc<MockConnection>) -> ConnectionState<MockConnection> {
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased));
        ConnectionState::new_for_test(quic, Arc::new(protocols))
    }

    fn transport_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: reason.into(),
            },
        }
    }

    async fn state_with_qpack(quic: Arc<MockConnection>) -> ConnectionState<MockConnection> {
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased));
        let qpack = QPackProtocolFactory::new()
            .init(&quic, &protocols)
            .await
            .expect("qpack protocol should initialize for tests");
        protocols.insert(qpack);
        ConnectionState::new_for_test(quic, Arc::new(protocols))
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
            PeekableStreamReader::new(StreamReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            SinkWriter::new(Box::pin(writer) as crate::quic::BoxQuicStreamWriter),
        )
    }

    async fn read_stream_with_bytes(stream_id: u32, bytes: &[u8]) -> MessageReader {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test stream bytes");
        writer.close().await.expect("close test stream writer");

        MessageReader::new(
            VarInt::from_u32(stream_id),
            StreamReader::new(guard::GuardQuicReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state_without_qpack(Arc::new(MockConnection::new())).erase(),
        )
    }

    fn paired_message_streams(stream_id: u32) -> (MessageReader, MessageWriter) {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        let read_stream = MessageReader::new(
            VarInt::from_u32(stream_id),
            StreamReader::new(guard::GuardQuicReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state_without_qpack(Arc::new(MockConnection::new())).erase(),
        );
        let write_stream = MessageWriter::new(
            SinkWriter::new(guard::GuardQuicWriter::new(
                Box::pin(writer) as crate::quic::BoxQuicStreamWriter
            )),
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state_without_qpack(Arc::new(MockConnection::new())).erase(),
        );

        (read_stream, write_stream)
    }

    #[tokio::test]
    async fn read_stream_try_stream_read_aborts_when_peer_goaway_covers_stream() {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(erased, Arc::new(protocols));

        let reader = StreamReader::new(guard::GuardQuicReader::new(Box::pin(TestReadStream {
            stream_id: VarInt::from_u32(10),
        })
            as crate::quic::BoxQuicStreamReader));
        let mut read_stream = MessageReader::new(
            VarInt::from_u32(10),
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
            .try_stream_read(async move |_this| {
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
    async fn write_stream_try_stream_write_aborts_when_peer_goaway_covers_stream() {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());

        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(erased, Arc::new(protocols));

        let writer = SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TestWriteStream {
            stream_id: VarInt::from_u32(12),
        })
            as crate::quic::BoxQuicStreamWriter));
        let mut write_stream = MessageWriter::new(
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
            .try_stream_write(async move |_this| {
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
    async fn initial_message_stream_requires_qpack_protocol() {
        let state = state_without_qpack(Arc::new(MockConnection::new()));

        let result = state.initial_message_stream().await;

        assert!(matches!(
            result,
            Err(super::InitialMessageStreamError::QPackProtocolDisabled { .. })
        ));
    }

    #[tokio::test]
    async fn initial_message_stream_wraps_initial_raw_stream_errors() {
        let quic = Arc::new(MockConnection::new());
        let state = state_with_qpack(quic).await;

        let result = state.initial_message_stream().await;

        assert!(matches!(
            result,
            Err(super::InitialMessageStreamError::InitialRawStream {
                source: crate::dhttp::protocol::InitialRawMessageStreamError::Connection { .. }
            })
        ));
    }

    #[tokio::test]
    async fn initial_message_stream_wraps_successful_raw_streams() {
        let quic = Arc::new(MockConnection::new());
        quic.enable_stream_ops();
        let state = state_with_qpack(quic).await;

        let (mut reader, mut writer) = state
            .initial_message_stream()
            .await
            .expect("initial message stream should open");

        assert_eq!(
            reader.stream_id().await.expect("reader stream id"),
            VarInt::from_u32(0)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer stream id"),
            VarInt::from_u32(0)
        );
        assert_eq!(state.max_initialized_stream_id(), Some(VarInt::from_u32(0)));
    }

    #[tokio::test]
    async fn accept_message_stream_requires_qpack_protocol() {
        let state = state_without_qpack(Arc::new(MockConnection::new()));

        let result = state.accept_message_stream().await;

        assert!(matches!(
            result,
            Err(super::AcceptMessageStreamError::QPackProtocolDisabled { .. })
        ));
    }

    #[tokio::test]
    async fn accept_message_stream_wraps_goaway_rejections() {
        let quic = Arc::new(MockConnection::new());
        let state = state_with_qpack(quic).await;
        state
            .dhttp()
            .local_goaway
            .set(Goaway::new(VarInt::from_u32(12)));
        assert!(matches!(
            state
                .dhttp()
                .accept_bi(test_peekable_bi_stream_with_bytes(12, &[0x01]).await)
                .await
                .expect("request stream should be routed"),
            StreamVerdict::Accepted
        ));

        let result = state.accept_message_stream().await;

        assert!(matches!(
            result,
            Err(super::AcceptMessageStreamError::AcceptRawStream {
                source: crate::dhttp::protocol::AcceptRawMessageStreamError::Goaway {
                    source: crate::connection::ConnectionGoaway::Local
                }
            })
        ));
    }

    #[tokio::test]
    async fn accept_message_stream_wraps_successful_raw_streams() {
        let quic = Arc::new(MockConnection::new());
        let state = state_with_qpack(quic).await;
        assert!(matches!(
            state
                .dhttp()
                .accept_bi(test_peekable_bi_stream_with_bytes(6, &[0x01]).await)
                .await
                .expect("request stream should be routed"),
            StreamVerdict::Accepted
        ));

        let (mut reader, mut writer) = state
            .accept_message_stream()
            .await
            .expect("accepted message stream should wrap raw streams");

        assert_eq!(
            reader.stream_id().await.expect("reader stream id"),
            VarInt::from_u32(6)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer stream id"),
            VarInt::from_u32(6)
        );
        assert_eq!(state.max_received_stream_id(), Some(VarInt::from_u32(6)));
    }

    #[tokio::test]
    async fn read_stream_stop_emits_qpack_stream_cancellation() {
        let stream_id = VarInt::from_u32(24);
        let stop_code = VarInt::from_u32(25);
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let decoder = Arc::new(QPackDecoder::new(
            Arc::new(Settings::default()),
            qpack_decoder_sink(),
            qpack_decoder_stream(),
        ));
        let (reader, _writer) = quic::test::mock_stream_pair(stream_id);
        let mut stream = MessageReader::new(
            stream_id,
            StreamReader::new(guard::GuardQuicReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            decoder.clone(),
            state,
        );

        poll_fn(|cx| Pin::new(&mut stream).poll_stop(cx, stop_code))
            .await
            .expect("read stream stop should complete");

        assert_eq!(
            decoder
                .state
                .lock()
                .expect("lock is not poisoned")
                .pending_instructions
                .back(),
            Some(
                &crate::qpack::decoder::DecoderInstruction::StreamCancellation {
                    stream_id: stream_id.into_inner()
                }
            )
        );
    }

    #[tokio::test]
    async fn read_stream_peer_goaway_future_returns_connection_error_when_connection_closes() {
        let quic = Arc::new(MockConnection::new());
        let state = state_without_qpack(quic.clone()).erase();
        let reader = StreamReader::new(guard::GuardQuicReader::new(Box::pin(TestReadStream {
            stream_id: VarInt::from_u32(2),
        })
            as crate::quic::BoxQuicStreamReader));
        let mut stream = MessageReader::new(
            VarInt::from_u32(2),
            reader,
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state,
        );
        quic.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "peer closed".into(),
            },
        });

        let result = stream
            .peer_goaway_covers()
            .await
            .expect("stream id should resolve")
            .await;

        assert!(matches!(
            result,
            Err(quic::ConnectionError::Transport { .. })
        ));
    }

    #[tokio::test]
    async fn write_stream_peer_goaway_future_returns_connection_error_when_connection_closes() {
        let quic = Arc::new(MockConnection::new());
        let state = state_without_qpack(quic.clone()).erase();
        let writer = SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TestWriteStream {
            stream_id: VarInt::from_u32(3),
        })
            as crate::quic::BoxQuicStreamWriter));
        let mut stream = MessageWriter::new(
            writer,
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );
        quic.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "peer closed".into(),
            },
        });

        let result = stream
            .peer_goaway_covers()
            .await
            .expect("stream id should resolve")
            .await;

        assert!(matches!(
            result,
            Err(quic::ConnectionError::Transport { .. })
        ));
    }

    #[tokio::test]
    async fn read_stream_try_stream_read_uses_constructor_stream_id() {
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let reader = StreamReader::new(guard::GuardQuicReader::new(Box::pin(
            StreamIdErrorReadStream {
                error: quic::StreamError::Reset {
                    code: VarInt::from_u32(91),
                },
            },
        )
            as crate::quic::BoxQuicStreamReader));
        let mut stream = MessageReader::new(
            VarInt::from_u32(91),
            reader,
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state,
        );
        stream
            .state
            .dhttp()
            .apply_peer_goaway(Goaway::new(VarInt::from_u32(90)))
            .expect("peer goaway should be accepted");

        let result: Result<(), MessageStreamError> = stream
            .try_stream_read(async |_this| {
                futures::future::pending::<Result<(), crate::connection::StreamError>>().await
            })
            .await;

        assert!(matches!(
            result,
            Err(MessageStreamError::Goaway {
                source: crate::connection::ConnectionGoaway::Peer
            })
        ));
    }

    #[tokio::test]
    async fn write_stream_try_stream_write_surfaces_stream_id_errors() {
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let reset_code = VarInt::from_u32(92);
        let writer = SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(
            StreamIdErrorWriteStream {
                error: quic::StreamError::Reset { code: reset_code },
            },
        )
            as crate::quic::BoxQuicStreamWriter));
        let mut stream = MessageWriter::new(
            writer,
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );

        let result: Result<(), MessageStreamError> = stream
            .try_stream_write(async |_this| panic!("closure should not run when stream id fails"))
            .await;

        assert!(matches!(
            result,
            Err(MessageStreamError::Quic {
                source: quic::StreamError::Reset { code }
            }) if code == reset_code
        ));
    }

    #[test]
    fn message_stream_error_conversions_cover_connection_and_send_failure_variants() {
        use std::io::ErrorKind;

        let error = MessageStreamError::from(transport_error("connection conversion"));
        assert!(matches!(
            error,
            MessageStreamError::Quic {
                source: quic::StreamError::Connection { .. }
            }
        ));

        let io_error = std::io::Error::from(MessageStreamError::MessageSendFailed);
        assert_eq!(io_error.kind(), ErrorKind::BrokenPipe);
    }

    #[test]
    fn message_stream_error_io_kind_delegates_quic_connection_errors() {
        use std::io::ErrorKind;

        let io_error =
            std::io::Error::from(MessageStreamError::from(transport_error("io conversion")));

        assert_eq!(io_error.kind(), ErrorKind::BrokenPipe);
        assert!(io_error.to_string().contains("io conversion"));
    }

    #[tokio::test]
    async fn oversized_write_data_frame_reports_message_error() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let error = stream
            .write_data_frame(OversizedBuf)
            .await
            .expect_err("oversized frame should fail before writing");

        assert!(matches!(
            error,
            MessageStreamError::DataFrameTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn read_data_frame_chunk_errors_when_data_payload_missing() {
        let mut stream = read_stream_with_bytes(23, &[0x00, 0x03]).await;

        let error = stream
            .read_data_frame_chunk()
            .await
            .expect_err("missing DATA payload should fail immediately");

        assert!(matches!(
            error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn truncated_data_frame_reports_error_after_streaming_available_chunk() {
        let mut data_stream = read_stream_with_bytes(23, &[0x00, 0x03, b'a']).await;
        // DATA frame bodies are streamed as chunks arrive; an EOF shorter
        // than the declared frame length is detected when the frame is polled
        // again.
        let data_error = data_stream
            .read_data_frame_chunk()
            .await
            .expect("first truncated DATA chunk is yielded before frame EOF is known");
        assert_eq!(data_error, Some(Bytes::from_static(b"a")));
        let data_error = data_stream
            .read_data_frame_chunk()
            .await
            .expect_err("truncated DATA payload should fail when the frame is resumed");
        assert!(matches!(
            data_error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn malformed_frame_header_is_reported_by_peek_header_path() {
        let mut header_stream = read_stream_with_bytes(24, &[0x00]).await;
        let header_error = header_stream
            .read_header_frame()
            .await
            .expect_err("truncated frame header should fail while peeking");
        assert!(matches!(
            header_error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn peek_frame_replays_stored_frame_decode_error() {
        let mut stream = read_stream_with_bytes(28, &[0x00]).await;

        let first = stream
            .peek_frame()
            .await
            .expect("malformed frame should produce an error");
        let first = first.err().expect("truncated frame header should fail");
        assert!(matches!(
            first,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_ERROR
        ));

        let replayed = stream
            .peek_frame()
            .await
            .expect("stored frame error should still be visible");
        let replayed = replayed
            .err()
            .expect("stored decode error should be replayed");
        assert!(matches!(
            replayed,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_ERROR
        ));
    }

    #[tokio::test]
    async fn read_header_frame_returns_none_when_next_frame_is_data() {
        let mut stream = read_stream_with_bytes(25, &[0x00, 0x03, b'a', b'b', b'c']).await;

        assert!(
            stream
                .read_header_frame()
                .await
                .expect("DATA frame should be valid")
                .is_none()
        );
    }

    #[tokio::test]
    async fn try_stream_read_and_write_surface_connection_close_from_goaway_future() {
        let read_quic = Arc::new(MockConnection::new());
        let read_state = state_without_qpack(read_quic.clone()).erase();
        read_quic.set_terminal_error(transport_error("read try_stream_read connection close"));
        let reader = StreamReader::new(guard::GuardQuicReader::new(Box::pin(TestReadStream {
            stream_id: VarInt::from_u32(26),
        })
            as crate::quic::BoxQuicStreamReader));
        let mut read_stream = MessageReader::new(
            VarInt::from_u32(26),
            reader,
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            read_state,
        );
        let read_result = read_stream
            .try_stream_read(async |_this| {
                futures::future::pending::<Result<(), StreamError>>().await
            })
            .await;
        assert!(matches!(
            read_result,
            Err(MessageStreamError::Quic {
                source: quic::StreamError::Connection { .. }
            })
        ));

        let write_quic = Arc::new(MockConnection::new());
        let write_state = state_without_qpack(write_quic.clone()).erase();
        write_quic.set_terminal_error(transport_error("write try_stream_write connection close"));
        let writer = SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TestWriteStream {
            stream_id: VarInt::from_u32(27),
        })
            as crate::quic::BoxQuicStreamWriter));
        let mut write_stream = MessageWriter::new(
            writer,
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            write_state,
        );
        let write_result = write_stream
            .try_stream_write(async |_this| {
                futures::future::pending::<Result<(), StreamError>>().await
            })
            .await;
        assert!(matches!(
            write_result,
            Err(MessageStreamError::Quic {
                source: quic::StreamError::Connection { .. }
            })
        ));
    }

    #[tokio::test]
    async fn stream_read_and_write_error_branches_delegate_connection_errors_to_lifecycle() {
        let read_quic = Arc::new(MockConnection::new());
        let read_state = state_without_qpack(read_quic.clone()).erase();
        let terminal_error = transport_error("read lifecycle closed");
        read_quic.set_terminal_error(terminal_error.clone());
        let mut read_stream = read_stream_for_test(VarInt::from_u32(28));
        read_stream.state = read_state;

        let read_error = read_stream
            .try_stream_read(async |_this| {
                Err::<(), _>(StreamError::Connection {
                    source: crate::error::H3FrameUnexpected::UnexpectedFrameType.into(),
                })
            })
            .await;
        assert!(matches!(
            read_error,
            Err(MessageStreamError::Quic {
                source: quic::StreamError::Connection {
                    source: quic::ConnectionError::Transport { source }
                }
            }) if source.reason == "read lifecycle closed"
        ));
        assert!(
            read_quic.close_calls().is_empty(),
            "already-closed connections should return their terminal error without closing again"
        );

        let write_quic = Arc::new(MockConnection::new());
        let write_state = state_without_qpack(write_quic.clone()).erase();
        let terminal_error = transport_error("write lifecycle closed");
        write_quic.set_terminal_error(terminal_error.clone());
        let mut write_stream = write_stream_for_test(VarInt::from_u32(29));
        write_stream.state = write_state;

        let write_error = write_stream
            .try_stream_write(async |_this| {
                Err::<(), _>(StreamError::Connection {
                    source: crate::error::H3FrameUnexpected::UnexpectedFrameType.into(),
                })
            })
            .await;
        assert!(matches!(
            write_error,
            Err(MessageStreamError::Quic {
                source: quic::StreamError::Connection {
                    source: quic::ConnectionError::Transport { source }
                }
            }) if source.reason == "write lifecycle closed"
        ));
        assert!(
            write_quic.close_calls().is_empty(),
            "already-closed connections should return their terminal error without closing again"
        );
    }

    #[tokio::test]
    async fn simple_test_stream_helpers_poll_to_ready() {
        let mut reader = TestReadStream {
            stream_id: VarInt::from_u32(30),
        };
        assert!(
            poll_fn(|cx| Pin::new(&mut reader).poll_next(cx))
                .await
                .is_none()
        );

        let mut stream_id_error_reader = StreamIdErrorReadStream {
            error: quic::StreamError::Reset {
                code: VarInt::from_u32(31),
            },
        };
        assert!(
            poll_fn(|cx| Pin::new(&mut stream_id_error_reader).poll_next(cx))
                .await
                .is_none()
        );
        poll_fn(|cx| Pin::new(&mut stream_id_error_reader).poll_stop(cx, VarInt::from_u32(0)))
            .await
            .expect("stream-id-error reader stop should still be ready");

        let mut tracked_reader = TrackedReadStream {
            stream_id: VarInt::from_u32(32),
            stop_tx: mpsc::unbounded_channel().0,
        };
        assert!(
            poll_fn(|cx| Pin::new(&mut tracked_reader).poll_next(cx))
                .await
                .is_none()
        );

        let mut writer = TestWriteStream {
            stream_id: VarInt::from_u32(33),
        };
        poll_fn(|cx| Pin::new(&mut writer).poll_ready(cx))
            .await
            .expect("test writer should be ready");
        Pin::new(&mut writer)
            .start_send(Bytes::from_static(b"x"))
            .expect("test writer should accept bytes");
        poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
            .await
            .expect("test writer should flush");
        poll_fn(|cx| Pin::new(&mut writer).poll_close(cx))
            .await
            .expect("test writer should close");

        let mut stream_id_error_writer = StreamIdErrorWriteStream {
            error: quic::StreamError::Reset {
                code: VarInt::from_u32(34),
            },
        };
        poll_fn(|cx| Pin::new(&mut stream_id_error_writer).poll_reset(cx, VarInt::from_u32(0)))
            .await
            .expect("stream-id-error writer reset should be ready");
        poll_fn(|cx| Pin::new(&mut stream_id_error_writer).poll_ready(cx))
            .await
            .expect("stream-id-error writer should be ready");
        Pin::new(&mut stream_id_error_writer)
            .start_send(Bytes::from_static(b"x"))
            .expect("stream-id-error writer should accept bytes");
        poll_fn(|cx| Pin::new(&mut stream_id_error_writer).poll_flush(cx))
            .await
            .expect("stream-id-error writer should flush");
        poll_fn(|cx| Pin::new(&mut stream_id_error_writer).poll_close(cx))
            .await
            .expect("stream-id-error writer should close");

        let (reset_tx, _reset_rx) = mpsc::unbounded_channel();
        let mut tracked_writer = TrackedWriteStream {
            stream_id: VarInt::from_u32(35),
            reset_tx,
        };
        poll_fn(|cx| Pin::new(&mut tracked_writer).poll_ready(cx))
            .await
            .expect("tracked writer should be ready");
        Pin::new(&mut tracked_writer)
            .start_send(Bytes::from_static(b"x"))
            .expect("tracked writer should accept bytes");
        poll_fn(|cx| Pin::new(&mut tracked_writer).poll_flush(cx))
            .await
            .expect("tracked writer should flush");
        poll_fn(|cx| Pin::new(&mut tracked_writer).poll_close(cx))
            .await
            .expect("tracked writer should close");
    }

    #[tokio::test]
    async fn read_data_frame_chunk_skips_reserved_and_empty_frames_before_payload() {
        let mut stream = read_stream_with_bytes(
            16,
            &[
                0x21, 0x00, // reserved frame
                0x00, 0x00, // empty DATA frame
                0x00, 0x03, b'a', b'b', b'c',
            ],
        )
        .await;

        assert_eq!(
            stream
                .read_data_frame_chunk()
                .await
                .expect("payload chunk should decode"),
            Some(Bytes::from_static(b"abc"))
        );
        assert_eq!(
            stream
                .read_data_frame_chunk()
                .await
                .expect("stream should end cleanly after payload"),
            None
        );
    }

    #[tokio::test]
    async fn read_data_frame_chunk_reports_unexpected_frame_types() {
        let mut stream = read_stream_with_bytes(17, &[0x04, 0x00]).await;

        let error = stream
            .read_data_frame_chunk()
            .await
            .expect_err("settings frame on request stream should be rejected");

        assert!(matches!(
            error,
            StreamError::Connection {
                source: crate::connection::ConnectionError::H3 { source }
            } if source.code() == Code::H3_FRAME_UNEXPECTED
        ));
    }

    #[tokio::test]
    async fn read_header_frame_decodes_empty_headers_and_then_eof() {
        let (mut reader, mut writer) = paired_message_streams(18);
        writer
            .write_header(std::iter::empty::<crate::qpack::field::FieldLine>())
            .await
            .expect("empty header section should encode");
        writer.close().await.expect("writer should close cleanly");

        let header = reader
            .read_header_frame()
            .await
            .expect("header frame should decode")
            .expect("header frame should be present");
        assert!(header.is_empty());
        assert!(
            reader
                .read_header_frame()
                .await
                .expect("stream should end cleanly")
                .is_none()
        );
    }

    #[tokio::test]
    async fn read_and_write_stream_traits_delegate_to_inner_streams() {
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let stop_code = VarInt::from_u32(51);
        let reset_code = VarInt::from_u32(52);
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel();
        let mut reader = MessageReader::new(
            VarInt::from_u32(19),
            StreamReader::new(guard::GuardQuicReader::new(Box::pin(TrackedReadStream {
                stream_id: VarInt::from_u32(19),
                stop_tx,
            })
                as crate::quic::BoxQuicStreamReader)),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state.clone(),
        );
        let mut writer = MessageWriter::new(
            SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TrackedWriteStream {
                stream_id: VarInt::from_u32(20),
                reset_tx,
            })
                as crate::quic::BoxQuicStreamWriter)),
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut reader).poll_stream_id(cx))
                .await
                .expect("reader stream id"),
            VarInt::from_u32(19)
        );
        poll_fn(|cx| Pin::new(&mut reader).poll_stop(cx, stop_code))
            .await
            .expect("reader stop");
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("reader stop should be observed")
                .expect("stop code should be sent"),
            stop_code,
        );

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut writer).poll_stream_id(cx))
                .await
                .expect("writer stream id"),
            VarInt::from_u32(20)
        );
        poll_fn(|cx| Pin::new(&mut writer).poll_reset(cx, reset_code))
            .await
            .expect("writer reset");
        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("writer reset should be observed")
                .expect("reset code should be sent"),
            reset_code,
        );
    }

    #[tokio::test]
    async fn handle_stream_error_resets_writer_and_stops_reader_streams() {
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel();
        let mut reader = MessageReader::new(
            VarInt::from_u32(21),
            StreamReader::new(guard::GuardQuicReader::new(Box::pin(TrackedReadStream {
                stream_id: VarInt::from_u32(21),
                stop_tx,
            })
                as crate::quic::BoxQuicStreamReader)),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state.clone(),
        );
        let mut writer = MessageWriter::new(
            SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TrackedWriteStream {
                stream_id: VarInt::from_u32(22),
                reset_tx,
            })
                as crate::quic::BoxQuicStreamWriter)),
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );

        let read_error = reader
            .handle_stream_error(crate::error::H3MessageError::MissingHeaderSection.into())
            .await;
        let write_error = writer
            .handle_stream_error(crate::error::H3MessageError::MissingHeaderSection.into())
            .await;

        assert!(matches!(
            read_error,
            quic::StreamError::Reset { code } if code == VarInt::from(Code::H3_MESSAGE_ERROR)
        ));
        assert!(matches!(
            write_error,
            quic::StreamError::Reset { code } if code == VarInt::from(Code::H3_MESSAGE_ERROR)
        ));
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("reader stop should be observed")
                .expect("stop code should be sent"),
            VarInt::from(Code::H3_MESSAGE_ERROR),
        );
        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("writer reset should be observed")
                .expect("reset code should be sent"),
            VarInt::from(Code::H3_MESSAGE_ERROR),
        );
    }

    #[tokio::test]
    async fn handle_stream_error_passthrough_variants_do_not_reset_streams() {
        let state = state_without_qpack(Arc::new(MockConnection::new())).erase();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel();
        let mut reader = MessageReader::new(
            VarInt::from_u32(30),
            StreamReader::new(guard::GuardQuicReader::new(Box::pin(TrackedReadStream {
                stream_id: VarInt::from_u32(30),
                stop_tx,
            })
                as crate::quic::BoxQuicStreamReader)),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state.clone(),
        );
        let mut writer = MessageWriter::new(
            SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TrackedWriteStream {
                stream_id: VarInt::from_u32(31),
                reset_tx,
            })
                as crate::quic::BoxQuicStreamWriter)),
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );

        let reset_code = VarInt::from_u32(32);
        let read_error = reader
            .handle_stream_error(StreamError::Reset { code: reset_code })
            .await;
        let write_error = writer
            .handle_stream_error(StreamError::Reset { code: reset_code })
            .await;

        assert!(matches!(
            read_error,
            quic::StreamError::Reset { code } if code == reset_code
        ));
        assert!(matches!(
            write_error,
            quic::StreamError::Reset { code } if code == reset_code
        ));
        assert!(
            stop_rx.try_recv().is_err(),
            "peer reset should not trigger STOP_SENDING"
        );
        assert!(
            reset_rx.try_recv().is_err(),
            "peer reset should not trigger RESET_STREAM"
        );
    }

    #[tokio::test]
    async fn handle_stream_error_quic_connection_errors_return_source_without_close() {
        let read_quic = Arc::new(MockConnection::new());
        let write_quic = Arc::new(MockConnection::new());
        let mut reader = read_stream_for_test(VarInt::from_u32(33));
        let mut writer = write_stream_for_test(VarInt::from_u32(34));
        reader.state = state_without_qpack(read_quic.clone()).erase();
        writer.state = state_without_qpack(write_quic.clone()).erase();

        let read_error = reader
            .handle_stream_error(StreamError::Connection {
                source: crate::connection::ConnectionError::Quic {
                    source: transport_error("read passthrough"),
                },
            })
            .await;
        let write_error = writer
            .handle_stream_error(StreamError::Connection {
                source: crate::connection::ConnectionError::Quic {
                    source: transport_error("write passthrough"),
                },
            })
            .await;

        assert!(matches!(
            read_error,
            quic::StreamError::Connection {
                source: quic::ConnectionError::Transport { source }
            } if source.reason == "read passthrough"
        ));
        assert!(matches!(
            write_error,
            quic::StreamError::Connection {
                source: quic::ConnectionError::Transport { source }
            } if source.reason == "write passthrough"
        ));
        assert!(read_quic.close_calls().is_empty());
        assert!(write_quic.close_calls().is_empty());
    }

    #[tokio::test]
    async fn read_stream_take_transfers_drop_cleanup_to_taken_wrapper() {
        let quic = Arc::new(MockConnection::new());
        let state = state_without_qpack(quic).erase();
        let (stop_tx, mut stop_rx) = mpsc::unbounded_channel();
        let mut stream = MessageReader::new(
            VarInt::from_u32(14),
            StreamReader::new(guard::GuardQuicReader::new(Box::pin(TrackedReadStream {
                stream_id: VarInt::from_u32(14),
                stop_tx,
            })
                as crate::quic::BoxQuicStreamReader)),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state,
        );

        let mut taken = stream.take();
        assert_eq!(
            taken.stream_id().await.expect("taken stream id"),
            VarInt::from_u32(14)
        );

        drop(stream);
        assert!(
            timeout(Duration::from_millis(50), stop_rx.recv())
                .await
                .is_err()
        );

        drop(taken);
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("taken read stream drop should stop")
                .expect("stop code should be sent"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn write_stream_take_transfers_drop_cleanup_to_taken_wrapper() {
        let quic = Arc::new(MockConnection::new());
        let state = state_without_qpack(quic).erase();
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel();
        let mut stream = MessageWriter::new(
            SinkWriter::new(guard::GuardQuicWriter::new(Box::pin(TrackedWriteStream {
                stream_id: VarInt::from_u32(15),
                reset_tx,
            })
                as crate::quic::BoxQuicStreamWriter)),
            Arc::new(QPackEncoder::new(
                Arc::new(Settings::default()),
                qpack_encoder_sink(),
                qpack_encoder_stream(),
            )),
            state,
        );

        let mut taken = stream.take();
        assert_eq!(
            taken.stream_id().await.expect("taken stream id"),
            VarInt::from_u32(15)
        );

        drop(stream);
        assert!(
            timeout(Duration::from_millis(50), reset_rx.recv())
                .await
                .is_err()
        );

        drop(taken);
        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("taken write stream drop should reset")
                .expect("reset code should be sent"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn write_after_close_fast_fails_without_polling_inner_stream() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        stream.close().await.expect("initial close should succeed");
        let error = stream
            .write_data(Bytes::from_static(b"after close"))
            .await
            .expect_err("write after close should fail at message layer");

        assert!(matches!(error, MessageStreamError::MessageWriterClosed));
    }

    #[tokio::test]
    async fn reader_stop_does_not_close_receive_side() {
        let mut stream = read_stream_with_bytes(41, &[0x00, 0x03, b'a', b'b', b'c']).await;

        stream
            .stop(Code::H3_NO_ERROR)
            .await
            .expect("stop should not close receive side");

        assert_eq!(
            stream
                .read_data_frame_chunk()
                .await
                .expect("stopped reader should still yield buffered data"),
            Some(Bytes::from_static(b"abc"))
        );
        assert_eq!(
            stream
                .read_data_frame_chunk()
                .await
                .expect("reader should close only after EOF"),
            None
        );
    }

    #[tokio::test]
    async fn write_stream_flush_close_reset_and_header_aliases_succeed_on_mock_stream() {
        let mut header_stream = write_stream_for_test(VarInt::from_u32(0));
        header_stream
            .write_header(std::iter::empty())
            .await
            .expect("empty header section should encode");

        let mut send_header_stream = write_stream_for_test(VarInt::from_u32(0));
        send_header_stream
            .send_header(std::iter::empty())
            .await
            .expect("send_header should delegate to write_header");

        let mut flush_close_stream = write_stream_for_test(VarInt::from_u32(0));
        flush_close_stream
            .flush()
            .await
            .expect("flush should succeed");
        flush_close_stream
            .close()
            .await
            .expect("close should succeed");

        let mut reset_stream = write_stream_for_test(VarInt::from_u32(0));
        reset_stream
            .reset(Code::H3_NO_ERROR)
            .await
            .expect("reset should succeed");
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
    async fn write_data_frame_returns_message_stream_error() {
        let mut stream = write_stream_for_test(VarInt::from_u32(0));

        let result: Result<(), MessageStreamError> =
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

#[cfg(test)]
pub mod test;
