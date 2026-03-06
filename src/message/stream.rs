use std::{
    io, mem,
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, future};
use snafu::Snafu;

use crate::{
    codec::{EncodeError, EncodeExt, SinkWriter, StreamReader},
    connection::{self, ConnectionGoaway, ConnectionState, QuicConnection},
    dhttp::{
        frame::{
            Frame,
            stream::{FrameStream, ReadableFrame},
        },
        goaway::Goaway,
        protocol::{
            AcceptRawMessageStreamError, BoxDynQuicStreamReader, BoxDynQuicStreamWriter,
            DHttpState, InitialRawMessageStreamError,
        },
    },
    error::Code,
    qpack::{
        algorithm::{HuffmanAlways, StaticCompressAlgo},
        encoder::EncodeHeaderSectionError,
        field::{FieldLine, FieldSection},
        protocol::{QPackDecoder, QPackEncoder, QPackProtocolDisabled},
    },
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    varint::VarInt,
};

#[cfg(feature = "hyper")]
pub(crate) mod hyper;
pub(crate) mod unfold;

fn stream_used_after_dropped() -> ! {
    panic!("message stream is used after dropped, this is a bug")
}

pub struct DestroiedStream;

impl Sink<Bytes> for DestroiedStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        stream_used_after_dropped()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }
}

impl Stream for DestroiedStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        stream_used_after_dropped()
    }
}

impl quic::CancelStream for DestroiedStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::StopStream for DestroiedStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::GetStreamId for DestroiedStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        stream_used_after_dropped()
    }
}

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
    DataFrameTooLarge,
    #[snafu(display("HTTP/3 message form peer is malformed"))]
    MalformedIncomingMessage,
}

impl From<quic::ConnectionError> for MessageStreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl From<MessageStreamError> for io::Error {
    fn from(error: MessageStreamError) -> Self {
        io::Error::other(error)
    }
}

pub struct ReadStream {
    pub(super) stream: FrameStream<BoxDynQuicStreamReader>,
    pub(super) qpack_decoder: Arc<QPackDecoder>,
    pub(super) connection: Arc<QuicConnection<dyn quic::Close + Send + Sync>>,
    dhttp_state: Arc<DHttpState>,
}

impl ReadStream {
    pub fn new(
        stream: StreamReader<BoxDynQuicStreamReader>,
        qpack_decoder: Arc<QPackDecoder>,
        connection: Arc<QuicConnection<dyn quic::Close + Send + Sync>>,
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

    pub async fn peer_goaway(
        &mut self,
    ) -> Result<
        impl Future<Output = Result<Goaway, quic::ConnectionError>> + use<>,
        quic::StreamError,
    > {
        let stream_id = self.stream.stream_id().await?;

        // Upon receipt of a GOAWAY frame, if the client has already sent
        // requests with a stream ID greater than or equal to the identifier
        // contained in the GOAWAY frame, those requests will not be
        // processed. Clients can safely retry unprocessed requests on a
        // different HTTP connection. A client that is unable to retry
        // requests loses all requests that are in flight when the server
        // closes the connection.
        let effective_peer_goaway = self
            .dhttp_state
            .peer_goaway
            .watch()
            .filter(move |goaway| future::ready(stream_id >= goaway.stream_id()));
        let error = self.connection.error();

        Ok(async move {
            let mut effective_peer_goaway = pin!(effective_peer_goaway.fuse());
            tokio::select! {
                biased;
                goaway = effective_peer_goaway.select_next_some() => Ok(goaway),
                error = error => Err(error),
            }
        })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        let peer_goaway = self.peer_goaway().await?;
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(connection::StreamError::Quic { source }) => Err(source.into()),
                // message from peer is malformed
                Err(connection::StreamError::Code { source }) if source.code().is_known_stream_error() => {
                    _ = self.stream.stop(source.code().into_inner()).await;
                    Err(quic::StreamError::Reset { code: source.code().into_inner() }.into())
                },
                Err(error) => Err(self.connection.handle_stream_error(error).await.into()),
            },
            goaway = peer_goaway => match goaway {
                Ok(_goaway) => {
                    // FIXME: which code should be used?
                    _ = self.stream.stop(Code::H3_NO_ERROR.into()).await;
                    Err(ConnectionGoaway::Peer.into())
                }
                Err(error) => Err(error.into())
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
                Some(Ok(_frame)) => return Some(Err(Code::H3_FRAME_UNEXPECTED.into())),
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
                            let error = error
                                .map_decode_error(|error| Code::H3_FRAME_ERROR.with(error).into());
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
        let stream = FrameStream::new(StreamReader::new(Box::pin(DestroiedStream) as Pin<Box<_>>));
        Self {
            stream: mem::replace(&mut self.stream, stream),
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
    pub(super) connection: Arc<QuicConnection<dyn quic::Close + Send + Sync>>,
    dhttp_state: Arc<DHttpState>,
}

pub const DEFAULT_COMPRESS_ALGO: StaticCompressAlgo<HuffmanAlways> =
    StaticCompressAlgo::new(HuffmanAlways);

impl WriteStream {
    pub fn new(
        stream: SinkWriter<BoxDynQuicStreamWriter>,
        qpack_encoder: Arc<QPackEncoder>,
        connection: Arc<QuicConnection<dyn quic::Close + Send + Sync>>,
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

    async fn peer_goaway(
        &mut self,
    ) -> Result<
        impl Future<Output = Result<Goaway, quic::ConnectionError>> + use<>,
        quic::StreamError,
    > {
        let stream_id = self.stream.stream_id().await?;

        // Upon receipt of a GOAWAY frame, if the client has already sent
        // requests with a stream ID greater than or equal to the identifier
        // contained in the GOAWAY frame, those requests will not be
        // processed. Clients can safely retry unprocessed requests on a
        // different HTTP connection. A client that is unable to retry
        // requests loses all requests that are in flight when the server
        // closes the connection.
        let effective_peer_goaway = self
            .dhttp_state
            .peer_goaway
            .watch()
            .filter(move |goaway| future::ready(stream_id >= goaway.stream_id()));
        let error = self.connection.error();

        Ok(async move {
            let mut effective_peer_goaway = pin!(effective_peer_goaway.fuse());
            tokio::select! {
                biased;
                goaway = effective_peer_goaway.select_next_some() => Ok(goaway),
                error = error => Err(error),
            }
        })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, MessageStreamError> {
        let peer_goaway = self.peer_goaway().await?;
        let f = async move |this: &mut Self| {
            let value = f(this).await?;
            // ensure all data are written into the underlying QUIC stream
            this.stream.flush_buffer().await?;
            Ok(value)
        };
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(error) => Err(self.connection.handle_stream_error(error).await.into()),
            },
            goaway = peer_goaway => match goaway {
                Ok(_goaway) => {
                    // FIXME: which code should be used?
                    _ = self.stream.cancel(Code::H3_NO_ERROR.into()).await;
                    Err(ConnectionGoaway::Peer.into())
                }
                Err(error) => Err(error.into())
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
                match this.qpack_encoder.encode(field_lines, algo, stream).await {
                    Ok(frame) => Ok(Ok(this.send_frame(frame).await?)),
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
        let stream = SinkWriter::new(Box::pin(DestroiedStream) as Pin<Box<_>>);
        Self {
            stream: mem::replace(&mut self.stream, stream),
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
                self.quic_connection().clone(),
                dhttp.state.clone(),
            ),
            WriteStream::new(
                writer,
                qpack.encoder.clone(),
                self.quic_connection().clone(),
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
                self.quic_connection().clone(),
                dhttp.state.clone(),
            ),
            WriteStream::new(
                writer,
                qpack.encoder.clone(),
                self.quic_connection().clone(),
                dhttp.state.clone(),
            ),
        ))
    }
}
