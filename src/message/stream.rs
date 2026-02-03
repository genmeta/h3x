use std::{
    io, mem,
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, future};
use http::HeaderMap;
use snafu::Snafu;

use crate::{
    buflist::{BufList, Cursor},
    codec::{EncodeError, EncodeExt, SinkWriter, StreamReader},
    connection::{self, ConnectionGoaway, ConnectionState, QPackDecoder, QPackEncoder},
    error::Code,
    frame::{
        Frame,
        stream::{FrameStream, ReadableFrame},
    },
    message::{Body, Message, MessageStage},
    qpack::{
        algorithm::{HuffmanAlways, StaticCompressAlgo},
        encoder::EncodeHeaderSectionError,
        field::{FieldLine, FieldSection, MalformedHeaderSection, malformed_header_section},
    },
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    varint::VarInt,
};

#[cfg(feature = "hyper")]
pub(crate) mod hyper;
mod unfold;

fn message_used_after_dropped() -> ! {
    unreachable!("Message used after destroyed, this is a bug");
}

pub struct DestroiedStream;

impl Sink<Bytes> for DestroiedStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        message_used_after_dropped()
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        message_used_after_dropped()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        message_used_after_dropped()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        message_used_after_dropped()
    }
}

impl Stream for DestroiedStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        message_used_after_dropped()
    }
}

impl quic::CancelStream for DestroiedStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        message_used_after_dropped()
    }
}

impl quic::StopStream for DestroiedStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        message_used_after_dropped()
    }
}

impl quic::GetStreamId for DestroiedStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        message_used_after_dropped()
    }
}

#[derive(Debug, Snafu)]
pub enum StreamError {
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
    #[snafu(display("HTTP/3 Message form peer is malformed"))]
    MalformedIncomingMessage,
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl From<StreamError> for io::Error {
    fn from(error: StreamError) -> Self {
        let kind = match error {
            StreamError::Quic { .. } => io::ErrorKind::BrokenPipe,
            StreamError::Goaway { .. } => io::ErrorKind::Other,
            StreamError::MalformedIncomingMessage => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, error)
    }
}

#[derive(Debug, Snafu)]
pub enum ReadToStringError {
    #[snafu(transparent)]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Utf8 { source: std::string::FromUtf8Error },
}

type BoxQuicStream = Pin<Box<dyn quic::ReadStream + Send>>;

pub struct ReadStream {
    stream: FrameStream<BoxQuicStream>,
    qpack_decoder: Arc<QPackDecoder>,
    connection: Arc<ConnectionState<dyn quic::Close + Send + Sync>>,
}

impl ReadStream {
    pub fn new(
        stream: Pin<Box<dyn quic::ReadStream + Send>>,
        qpack_decoder: Arc<QPackDecoder>,
        connection: Arc<ConnectionState<dyn quic::Close + Send + Sync>>,
    ) -> Self {
        let frame_stream = FrameStream::new(StreamReader::new(stream));
        Self {
            stream: frame_stream,
            qpack_decoder,
            connection,
        }
    }

    pub async fn peer_goaway(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;

        // Upon receipt of a GOAWAY frame, if the client has already sent
        // requests with a stream ID greater than or equal to the identifier
        // contained in the GOAWAY frame, those requests will not be
        // processed. Clients can safely retry unprocessed requests on a
        // different HTTP connection. A client that is unable to retry
        // requests loses all requests that are in flight when the server
        // closes the connection.
        let peer_goaway = self.connection.peer_goawaies().filter_map(move |result| {
            future::ready(match result {
                Ok(goaway) if stream_id >= goaway.stream_id() => Some(Ok(())),
                Ok(..) => None,
                Err(error) => Some(Err(error)),
            })
        });

        // TODO: Is there any better way to move ownership of the stream than async block?.
        Ok(async move { pin!(peer_goaway).fuse().select_next_some().await })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, StreamError> {
        let peer_goaway = self.peer_goaway().await?;
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
                Err(connection::StreamError::Quic { source }) => Err(source.into()),
                // message from peer is malformed
                Err(connection::StreamError::Code { source }) if source.code().is_known_stream_error() => {
                    _ = self.stream.stop(source.code().into_inner()).await;
                    Err(StreamError::MalformedIncomingMessage)
                },
                Err(error) => Err(self.connection.handle_error(error).await.into()),
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

    pub async fn peek_frame(
        &mut self,
    ) -> Option<Result<ReadableFrame<'_, BoxQuicStream>, connection::StreamError>> {
        loop {
            match self.stream.frame() {
                None => match self.stream.next_unreserved_frame().await? {
                    Ok(_next_frame) => continue,
                    Err(error) => return Some(Err(error)),
                },
                Some(Ok(frame))
                    if frame.r#type() == Frame::HEADERS_FRAME_TYPE
                        || frame.r#type() == Frame::DATA_FRAME_TYPE =>
                {
                    // avoid rust bc bug
                    return self.stream.frame();
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
                            _ = self.stream.consume_current_frame().await;
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
                let frame = match self.stream.frame()? {
                    Ok(frame) => frame,
                    Err(error) => return Some(Err(error)),
                };
                match self.qpack_decoder.decode(frame).await {
                    Ok(field_section) => {
                        _ = self.stream.consume_current_frame().await;
                        Some(Ok(field_section))
                    }
                    Err(error) => Some(Err(error)),
                }
            }
            Some(Ok(..)) | None => None,
            Some(Err(error)) => Some(Err(error)),
        }
    }

    pub async fn try_message_io<T>(
        &mut self,
        message: &mut Message,
        f: impl AsyncFnOnce(&mut Self, &mut Message) -> Result<T, connection::StreamError>,
    ) -> Result<T, StreamError> {
        self.try_stream_io(async move |this| {
            let result = f(this, message).await;
            if let Err(connection::StreamError::Code { source }) = &result
                && source.code().is_known_stream_error()
            {
                message.set_malformed();
            }
            result
        })
        .await
    }

    pub async fn read_message_header<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<&'e FieldSection, StreamError> {
        match message.stage {
            MessageStage::Header => {}
            // header already read
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => {
                return Ok(&message.header);
            }
            MessageStage::Malformed => {
                return Err(StreamError::MalformedIncomingMessage);
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.header = self
            .try_message_io(message, async |this, message| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    } else {
                        return Err(Code::H3_MESSAGE_ERROR.into());
                    }
                };

                field_section.check_pseudo()?;
                if message.header.is_request_header() {
                    if !field_section.is_request_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                } else {
                    debug_assert!(message.header.is_response_header());
                    if !field_section.is_response_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                }
                Ok(field_section)
            })
            .await?;

        // check header complete/valid

        if message.is_interim_response() {
            message.stage = MessageStage::Header;
        } else {
            message.stage = MessageStage::Body;
        }
        Ok(&message.header)
    }

    pub async fn read_message_body_chunk(
        &mut self,
        message: &mut Message,
    ) -> Option<Result<Bytes, StreamError>> {
        match message.stage {
            MessageStage::Header => {
                while message.stage == MessageStage::Header {
                    match self.read_message_header(message).await {
                        Ok(..) => (),
                        Err(error) => return Some(Err(error)),
                    }
                }
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                match &mut message.body {
                    Body::Streaming { .. } => return None,
                    Body::Chunked { buflist } => {
                        if buflist.has_remaining() {
                            return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                        }
                    }
                };
            }
            MessageStage::Malformed => return Some(Err(StreamError::MalformedIncomingMessage)),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let try_read_next_chunk = self.try_message_io(message, async |this, message| {
            match this.read_data_frame_chunk().await.transpose()? {
                Some(chunk) => Ok(Some(chunk)),
                None => {
                    if this.peek_frame().await.transpose()?.is_some() {
                        message.stage = MessageStage::Trailer
                    } else {
                        message.stage = MessageStage::Complete
                    }
                    Ok(None)
                }
            }
        });

        match try_read_next_chunk.await {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn read_message_full_body<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<impl Buf + 'e, StreamError> {
        enum Buffer<'e> {
            Owned(BufList),
            Borrow(&'e mut Cursor<BufList>),
        }

        impl Buf for Buffer<'_> {
            fn remaining(&self) -> usize {
                match self {
                    Buffer::Owned(b) => b.remaining(),
                    Buffer::Borrow(b) => b.remaining(),
                }
            }

            fn has_remaining(&self) -> bool {
                match self {
                    Buffer::Owned(b) => b.has_remaining(),
                    Buffer::Borrow(b) => b.has_remaining(),
                }
            }

            fn chunk(&self) -> &[u8] {
                match self {
                    Buffer::Owned(b) => b.chunk(),
                    Buffer::Borrow(b) => b.chunk(),
                }
            }

            fn chunks_vectored<'a>(&'a self, dst: &mut [std::io::IoSlice<'a>]) -> usize {
                match self {
                    Buffer::Owned(b) => b.chunks_vectored(dst),
                    Buffer::Borrow(b) => b.chunks_vectored(dst),
                }
            }

            fn advance(&mut self, cnt: usize) {
                match self {
                    Buffer::Owned(b) => b.advance(cnt),
                    Buffer::Borrow(b) => b.advance(cnt),
                }
            }

            fn copy_to_bytes(&mut self, len: usize) -> bytes::Bytes {
                match self {
                    Buffer::Owned(b) => b.copy_to_bytes(len),
                    Buffer::Borrow(b) => b.copy_to_bytes(len),
                }
            }
        }

        match &mut message.body {
            Body::Streaming { .. } => {
                let mut buflist = BufList::new();
                while let Some(body_part) =
                    self.read_message_body_chunk(message).await.transpose()?
                {
                    buflist.write(body_part);
                }
                Ok(Buffer::Owned(buflist))
            }
            Body::Chunked { .. } => {
                while let Some(body_part) =
                    self.read_message_body_chunk(message).await.transpose()?
                {
                    message.chunked_body().expect("checked").write(body_part);
                }
                Ok(Buffer::Borrow(message.chunked_body().expect("checked")))
            }
        }
    }

    pub async fn read_message_body_to_bytes(
        &mut self,
        message: &mut Message,
    ) -> Result<Bytes, StreamError> {
        let mut bytes = self.read_message_full_body(message).await?;
        Ok(bytes.copy_to_bytes(bytes.remaining()))
    }

    pub async fn read_message_body_to_string(
        &mut self,
        message: &mut Message,
    ) -> Result<String, ReadToStringError> {
        // TODO: preallocate buffer with content-length
        let mut vec = vec![];
        while let Some(bytes) = self.read_message(message).await.transpose()? {
            vec.extend_from_slice(&bytes);
        }
        Ok(String::from_utf8(vec)?)
    }

    pub async fn read_message(
        &mut self,
        message: &mut Message,
    ) -> Option<Result<Bytes, StreamError>> {
        loop {
            match &mut message.body {
                Body::Streaming { .. } => return self.read_message_body_chunk(message).await,
                Body::Chunked { buflist } => {
                    if buflist.has_remaining() {
                        return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                    }
                    match self.read_message_body_chunk(message).await? {
                        Ok(body_part) => {
                            message.chunked_body().expect("checked").write(body_part);
                            continue;
                        }
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        }
    }

    pub async fn read_message_trailer<'e>(
        &mut self,
        message: &'e mut Message,
    ) -> Result<&'e HeaderMap, StreamError> {
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                match &message.body {
                    Body::Streaming { .. } => {
                        // read and discard body
                        while let Some(_body_part) =
                            self.read_message_body_chunk(message).await.transpose()?
                        {
                        }
                    }
                    Body::Chunked { .. } => {
                        self.read_message_full_body(message).await?;
                    }
                }
            }
            MessageStage::Trailer => {}
            MessageStage::Complete => return Ok(message.trailers()),
            MessageStage::Malformed => return Err(StreamError::MalformedIncomingMessage),
            MessageStage::Dropped => message_used_after_dropped(),
        }

        message.trailer = self
            .try_message_io(message, async |this, _| {
                let Some(field_section) = this.read_header_frame().await.transpose()? else {
                    if this.peek_frame().await.transpose()?.is_some() {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    } else {
                        // no trailer
                        return Ok(FieldSection::trailer(HeaderMap::new()));
                    }
                };

                if !field_section.is_trailer() {
                    return Err(MalformedHeaderSection::PseudoHeaderInTrailer.into());
                }
                Ok(field_section)
            })
            .await?;

        debug_assert!(self.stream.frame().is_none());
        message.stage = MessageStage::Complete;

        Ok(message.trailers())
    }

    pub async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        self.stream.stop(code).await
    }

    pub fn take(&mut self) -> Self {
        let stream = FrameStream::new(StreamReader::new(Box::pin(DestroiedStream) as Pin<Box<_>>));
        Self {
            stream: mem::replace(&mut self.stream, stream),
            qpack_decoder: self.qpack_decoder.clone(),
            connection: self.connection.clone(),
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

pub struct WriteStream {
    stream: SinkWriter<Pin<Box<dyn quic::WriteStream + Send>>>,
    qpack_encoder: Arc<QPackEncoder>,
    connection: Arc<ConnectionState<dyn quic::Close + Send + Sync>>,
}

pub const DEFAULT_COMPRESS_ALGO: StaticCompressAlgo<HuffmanAlways> =
    StaticCompressAlgo::new(HuffmanAlways);

impl WriteStream {
    pub fn new(
        stream: Pin<Box<dyn quic::WriteStream + Send>>,
        qpack_encoder: Arc<QPackEncoder>,
        connection: Arc<ConnectionState<dyn quic::Close + Send + Sync>>,
    ) -> Self {
        let stream = SinkWriter::new(stream);
        Self {
            stream,
            qpack_encoder,
            connection,
        }
    }

    async fn send_frame(&mut self, frame: Frame<impl Buf>) -> Result<(), quic::StreamError> {
        self.stream.encode_one(frame).await
    }

    async fn peer_goaway(
        &mut self,
    ) -> Result<impl Future<Output = Result<(), quic::ConnectionError>> + use<>, quic::StreamError>
    {
        let stream_id = self.stream.stream_id().await?;

        // Upon receipt of a GOAWAY frame, if the client has already sent
        // requests with a stream ID greater than or equal to the identifier
        // contained in the GOAWAY frame, those requests will not be
        // processed. Clients can safely retry unprocessed requests on a
        // different HTTP connection. A client that is unable to retry
        // requests loses all requests that are in flight when the server
        // closes the connection.
        let peer_goaway = self.connection.peer_goawaies().filter_map(move |result| {
            future::ready(match result {
                Ok(goaway) if stream_id >= goaway.stream_id() => Some(Ok(())),
                Ok(..) => None,
                Err(error) => Some(Err(error)),
            })
        });

        // TODO: Is there any better way to move ownership of the stream than async block?.
        Ok(async move { pin!(peer_goaway).fuse().select_next_some().await })
    }

    pub async fn try_stream_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, StreamError> {
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
                Err(error) => Err(self.connection.handle_error(error).await.into()),
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

    pub async fn send_header(
        &mut self,
        field_lines: impl IntoIterator<Item = FieldLine> + Send,
    ) -> Result<(), StreamError> {
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
            Err(EncodeError::FramePayloadTooLarge) => Err(StreamError::HeaderTooLarge),
            Err(EncodeError::HuffmanEncoding) => {
                unreachable!("FieldSection contain invalid header name/value, this is a bug")
            }
        }
    }

    pub async fn send_message_header(&mut self, message: &mut Message) -> Result<(), StreamError> {
        match message.stage {
            MessageStage::Header => {}
            // header already sent
            MessageStage::Body | MessageStage::Trailer | MessageStage::Complete => return Ok(()),
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        self.send_header(message.header.iter()).await?;
        if message.is_interim_response() {
            message.stage = MessageStage::Header;
        } else {
            message.stage = MessageStage::Body;
        }

        Ok(())
    }

    pub async fn send_data(&mut self, data: impl Buf) -> Result<(), StreamError> {
        let frame =
            Frame::new(Frame::DATA_FRAME_TYPE, data).map_err(|_| StreamError::DataFrameTooLarge)?;
        self.try_stream_io(async |this| Ok(this.send_frame(frame).await?))
            .await
    }

    pub async fn send_message_streaming_body(
        &mut self,
        message: &mut Message,
        content: impl Buf,
    ) -> Result<(), StreamError> {
        // if message.is_interim_response() {
        //     // malformed message
        // }
        // message.enable_streaming()?; // violate of set_body call

        match message.stage {
            MessageStage::Header => {
                self.send_message_header(message).await?;
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                /* this will cause H3_FRAME_UNEXPECTED error */
            }
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let len = content.remaining();
        self.send_data(content).await?;
        *message
            .streaming_body()
            .expect("call send_streaming_body on chunked body, this is a bug") += len as u64;

        Ok(())
    }

    pub async fn send_message_chunked_body(
        &mut self,
        message: &mut Message,
    ) -> Result<(), StreamError> {
        // if message.is_interim_response() {
        //     // malformed message
        // }

        match message.stage {
            MessageStage::Header => {
                self.send_message_header(message).await?;
                debug_assert_eq!(message.stage, MessageStage::Body);
            }
            MessageStage::Body => {}
            MessageStage::Trailer | MessageStage::Complete => {
                /* this will cause H3_FRAME_UNEXPECTED error */
            }
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        let Body::Chunked { buflist } = &mut message.body else {
            unreachable!("Call send_chunked_body on non-chunked body, this is a bug");
        };

        while buflist.has_remaining() {
            let bytes = buflist.copy_to_bytes(buflist.chunk().len());
            let frame = Frame::new(Frame::DATA_FRAME_TYPE, bytes)
                .map_err(|_| StreamError::DataFrameTooLarge)?;
            self.try_stream_io(async |this| Ok(this.send_frame(frame).await?))
                .await?;
        }

        message.stage = MessageStage::Trailer;
        Ok(())
    }

    pub async fn send_message_trailer(&mut self, message: &mut Message) -> Result<(), StreamError> {
        // prepare
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                if message.is_chunked() {
                    self.send_message_chunked_body(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Trailer);
                } else {
                    self.send_message_header(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Body);
                    // no body or streaming body already sent
                }
            }
            MessageStage::Trailer => {}
            MessageStage::Complete => return Ok(()),
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        // TODO: check FieldLines size
        let field_lines = message.trailer.iter();
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
            Ok(()) => {
                message.stage = MessageStage::Complete;
                Ok(())
            }
            Err(error) => match error {
                EncodeError::FramePayloadTooLarge => Err(StreamError::TrailerTooLarge),
                EncodeError::HuffmanEncoding => {
                    unreachable!("FieldSection contain invalid header name/value, this is a bug")
                }
            },
        }
    }

    pub async fn send_message(&mut self, message: &mut Message) -> Result<(), StreamError> {
        match message.stage {
            MessageStage::Header | MessageStage::Body => {
                if message.header().is_empty() {
                    return Ok(());
                }
                if message.is_chunked() {
                    self.send_message_chunked_body(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Trailer);
                } else {
                    self.send_message_header(message).await?;
                    if message.is_interim_response() {
                        debug_assert!(message.stage == MessageStage::Header);
                    } else {
                        debug_assert!(message.stage == MessageStage::Body);
                    }
                }

                if !message.trailers().is_empty() {
                    self.send_message_trailer(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Complete)
                }
            }
            MessageStage::Trailer => {
                if !message.trailers().is_empty() {
                    self.send_message_trailer(message).await?;
                    debug_assert_eq!(message.stage, MessageStage::Complete)
                } else {
                    // no trailer to send
                }
            }
            MessageStage::Complete => {}
            MessageStage::Malformed => {
                return self.cancel(Code::H3_REQUEST_CANCELLED).await;
            }
            MessageStage::Dropped => message_used_after_dropped(),
        }

        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), StreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.flush_inner().await?))
            .await
    }

    pub async fn flush_message(&mut self, message: &mut Message) -> Result<(), StreamError> {
        self.send_message(message).await?;
        self.flush().await
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.close().await?))
            .await
    }

    pub async fn close_message(&mut self, message: &mut Message) -> Result<(), StreamError> {
        self.send_message(message).await?;
        self.close().await
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), StreamError> {
        self.try_stream_io(async move |this| Ok(this.stream.cancel(code.into_inner()).await?))
            .await
    }

    pub fn take(&mut self) -> Self {
        let stream = SinkWriter::new(Box::pin(DestroiedStream) as Pin<Box<_>>);
        Self {
            stream: mem::replace(&mut self.stream, stream),
            qpack_encoder: self.qpack_encoder.clone(),
            connection: self.connection.clone(),
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
