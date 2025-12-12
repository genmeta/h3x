use std::{
    io, mem,
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, future};
use http::HeaderMap;
use snafu::{ResultExt, Snafu};

use super::Body;
use crate::{
    buflist::{BufList, Cursor},
    codec::{EncodeExt, SinkWriter, StreamReader},
    connection::{
        self, ConnectionGoaway, ConnectionState, InitialRequestStreamError, QPackDecoder,
        QPackEncoder,
    },
    entity::{Entity, EntityStage, IllegalEntityOperator, SendMalformedPseudoHeaderSnafu},
    error::Code,
    frame::{Frame, stream::FrameStream},
    qpack::{
        algorithm::{HuffmanAlways, StaticCompressAlgo},
        field_section::{FieldSection, MalformedHeaderSection, malformed_header_section},
    },
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    varint::VarInt,
};

pub struct MockStream;

impl Sink<Bytes> for MockStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        panic!("Stream used after dropped");
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        panic!("Stream used after dropped");
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        panic!("Stream used after dropped");
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        panic!("Stream used after dropped");
    }
}

impl Stream for MockStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        panic!("Stream used after dropped");
    }
}

impl quic::CancelStream for MockStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        panic!("Stream used after dropped");
    }
}

impl quic::StopStream for MockStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        panic!("Stream used after dropped");
    }
}

impl quic::GetStreamId for MockStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        panic!("Stream used after dropped");
    }
}

#[derive(Debug, Snafu)]
pub enum StreamError {
    #[snafu(transparent)]
    Quic { source: quic::StreamError },
    #[snafu(transparent)]
    Goaway { source: ConnectionGoaway },
    #[snafu(transparent)]
    IllegalEntityOperator { source: IllegalEntityOperator },
}

impl From<quic::ConnectionError> for StreamError {
    fn from(value: quic::ConnectionError) -> Self {
        Self::Quic {
            source: value.into(),
        }
    }
}

impl From<InitialRequestStreamError> for StreamError {
    fn from(error: InitialRequestStreamError) -> Self {
        match error {
            InitialRequestStreamError::Quic { source } => Self::Quic { source },
            InitialRequestStreamError::Goaway { source } => Self::Goaway { source },
        }
    }
}

impl From<StreamError> for io::Error {
    fn from(error: StreamError) -> Self {
        let kind = match error {
            StreamError::Quic { .. } => io::ErrorKind::BrokenPipe,
            StreamError::Goaway { .. } => io::ErrorKind::Other,
            StreamError::IllegalEntityOperator { .. } => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, error)
    }
}

pub struct ReadStream {
    stream: FrameStream<Pin<Box<dyn quic::ReadStream + Send>>>,
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

    pub async fn try_io<T>(
        &mut self,
        f: impl AsyncFnOnce(&mut Self) -> Result<T, connection::StreamError>,
    ) -> Result<T, StreamError> {
        let peer_goaway = self.peer_goaway().await?;
        tokio::select! {
            result = f(self) => match result {
                Ok(value) => Ok(value),
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

    pub async fn read_header<'e>(
        &mut self,
        entity: &'e mut Entity,
    ) -> Result<&'e FieldSection, StreamError> {
        match entity.stage {
            EntityStage::Header => {}
            // header already read
            EntityStage::Body | EntityStage::Trailer | EntityStage::Complete => {
                return Ok(&entity.header);
            }
        }

        entity.header = self
            .try_io(async |this| {
                let frame = match this.stream.next_unreserved_frame().await.transpose()? {
                    Some(frame) if frame.r#type() != Frame::HEADERS_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(frame) => frame,
                    None => return Err(Code::H3_MESSAGE_ERROR.into()),
                };
                let header = this.qpack_decoder.decode(frame).await?;

                this.stream.consume_current_frame().await?;
                debug_assert!(this.stream.frame().is_none());

                header.check_pseudo()?;
                if entity.header.is_request_header() {
                    if !header.is_request_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                } else {
                    debug_assert!(entity.header.is_response_header());
                    if !header.is_response_header() {
                        malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail()?;
                    }
                }
                Ok(header)
            })
            .await?;

        // check header complete/valid

        if entity.is_interim_response() {
            entity.stage = EntityStage::Header;
        } else {
            entity.stage = EntityStage::Body;
        }
        Ok(&entity.header)
    }

    async fn read_next_body(&mut self, entity: &mut Entity) -> Option<Result<Bytes, StreamError>> {
        match entity.stage {
            EntityStage::Header => {
                while entity.stage == EntityStage::Header {
                    match self.read_header(entity).await {
                        Ok(..) => (),
                        Err(error) => return Some(Err(error)),
                    }
                }
                debug_assert_eq!(entity.stage, EntityStage::Body);
            }
            EntityStage::Body => {}
            EntityStage::Trailer | EntityStage::Complete => {
                match &mut entity.body {
                    Body::Streaming { .. } => return None,
                    Body::Chunked { buflist } => {
                        if buflist.has_remaining() {
                            return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                        }
                    }
                };
            }
        }

        let try_read_next_body = self.try_io(async |this| {
            loop {
                match this.stream.frame().transpose()? {
                    None => match this.stream.next_unreserved_frame().await.transpose()? {
                        Some(_next_frame) => continue,
                        None => {
                            debug_assert!(this.stream.frame().is_none());
                            entity.stage = EntityStage::Complete;
                            return Ok(None);
                        }
                    },
                    Some(frame) if frame.r#type() == Frame::HEADERS_FRAME_TYPE => {
                        debug_assert!(this.stream.frame().is_some_and(|frame| {
                            frame.is_ok_and(|frame| frame.r#type() == Frame::HEADERS_FRAME_TYPE)
                        }));
                        entity.stage = EntityStage::Trailer;
                        return Ok(None);
                    }
                    Some(frame) if frame.r#type() != Frame::DATA_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(mut frame) => match frame.try_next().await {
                        Ok(Some(bytes)) => return Ok(Some(bytes)),
                        Ok(None) => {
                            this.stream.consume_current_frame().await?;
                            debug_assert!(this.stream.frame().is_none());
                            continue;
                        }
                        Err(error) => {
                            let error = error
                                .map_decode_error(|error| Code::H3_FRAME_ERROR.with(error).into());
                            return Err(error);
                        }
                    },
                };
            }
        });

        match try_read_next_body.await {
            Ok(Some(bytes)) => Some(Ok(bytes)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }

    pub async fn read_all<'e>(
        &mut self,
        entity: &'e mut Entity,
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

        match &mut entity.body {
            Body::Streaming { .. } => {
                let mut buflist = BufList::new();
                while let Some(body_part) = self.read_next_body(entity).await.transpose()? {
                    buflist.write(body_part);
                }
                Ok(Buffer::Owned(buflist))
            }
            Body::Chunked { .. } => {
                while let Some(body_part) = self.read_next_body(entity).await.transpose()? {
                    entity.chunked_body().expect("Checked").write(body_part);
                }
                Ok(Buffer::Borrow(entity.chunked_body().expect("Checked")))
            }
        }
    }

    pub async fn read(&mut self, entity: &mut Entity) -> Option<Result<Bytes, StreamError>> {
        loop {
            match &mut entity.body {
                Body::Streaming { .. } => return self.read_next_body(entity).await,
                Body::Chunked { buflist } => {
                    if buflist.has_remaining() {
                        return Some(Ok(buflist.copy_to_bytes(buflist.chunk().len())));
                    }
                    match self.read_next_body(entity).await? {
                        Ok(body_part) => {
                            entity.chunked_body().expect("Checked").write(body_part);
                            continue;
                        }
                        Err(error) => return Some(Err(error)),
                    }
                }
            }
        }
    }

    pub async fn read_trailer<'e>(
        &mut self,
        entity: &'e mut Entity,
    ) -> Result<&'e HeaderMap, StreamError> {
        match entity.stage {
            EntityStage::Header | EntityStage::Body => {
                match &entity.body {
                    Body::Streaming { .. } => {
                        // read and discard body
                        while let Some(_body_part) =
                            self.read_next_body(entity).await.transpose()?
                        {}
                    }
                    Body::Chunked { .. } => {
                        self.read_all(entity).await?;
                    }
                }
            }
            EntityStage::Trailer => {}
            EntityStage::Complete => return Ok(entity.trailers()),
        }

        entity.trailer = self
            .try_io(async |this| {
                let frame = match this.stream.frame().transpose()? {
                    Some(frame) if frame.r#type() != Frame::HEADERS_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(frame) => frame,
                    // no trailer
                    None => return Ok(FieldSection::trailer(HeaderMap::new())),
                };

                let trailer = this.qpack_decoder.decode(frame).await?;
                if !trailer.is_trailer() {
                    return Err(MalformedHeaderSection::PseudoHeadersInTrailer.into());
                }
                this.stream.consume_current_frame().await?;
                Ok(trailer)
            })
            .await?;

        debug_assert!(self.stream.frame().is_none());
        entity.stage = EntityStage::Complete;

        Ok(entity.trailers())
    }

    pub async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        self.stream.stop(code).await
    }

    pub fn take(&mut self) -> Self {
        let mock_stream = FrameStream::new(StreamReader::new(Box::pin(MockStream) as Pin<Box<_>>));
        Self {
            stream: mem::replace(&mut self.stream, mock_stream),
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

const DEFAULT_COMPRESS_ALGO: StaticCompressAlgo<HuffmanAlways> =
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

    pub async fn try_io<T>(
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

    pub async fn send_header(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        match entity.stage {
            EntityStage::Header => {}
            // header already sent
            EntityStage::Body | EntityStage::Trailer | EntityStage::Complete => return Ok(()),
        }

        entity
            .header
            .check_pseudo()
            .context(SendMalformedPseudoHeaderSnafu)?;

        let field_lines = entity.header.iter();
        let algo = &DEFAULT_COMPRESS_ALGO;
        self.try_io(async move |this| {
            let stream = &mut this.stream;
            let frame = this.qpack_encoder.encode(field_lines, algo, stream).await?;
            this.send_frame(frame).await?;
            Ok(())
        })
        .await?;

        if entity.is_interim_response() {
            entity.stage = EntityStage::Header
        } else {
            entity.stage = EntityStage::Body
        }
        Ok(())
    }

    pub async fn send_streaming_body(
        &mut self,
        entity: &mut Entity,
        mut content: impl Buf,
    ) -> Result<(), StreamError> {
        entity
            .header
            .check_pseudo()
            .context(SendMalformedPseudoHeaderSnafu)?;
        if entity.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse.into());
        }
        entity.enable_streaming()?;

        match entity.stage {
            EntityStage::Header => {
                self.send_header(entity).await?;
                debug_assert_eq!(entity.stage, EntityStage::Body);
            }
            EntityStage::Body => {}
            EntityStage::Trailer | EntityStage::Complete => {
                return Err(IllegalEntityOperator::ModifyBodyAfterSent.into());
            }
        }

        while content.has_remaining() {
            let bytes = content.copy_to_bytes(content.chunk().len());
            let frame = Frame::new(Frame::DATA_FRAME_TYPE, bytes)
                .map_err(|_| IllegalEntityOperator::DataFramePayloadTooLarge)?;
            self.try_io(async |this| Ok(this.send_frame(frame).await?))
                .await?;
        }

        Ok(())
    }

    pub async fn send_chunked_body(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        entity
            .header
            .check_pseudo()
            .context(SendMalformedPseudoHeaderSnafu)?;
        if entity.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse.into());
        }

        match entity.stage {
            EntityStage::Header => {
                self.send_header(entity).await?;
                debug_assert_eq!(entity.stage, EntityStage::Body);
            }
            EntityStage::Body => {}
            EntityStage::Trailer | EntityStage::Complete => {
                return Err(IllegalEntityOperator::ModifyBodyAfterSent.into());
            }
        }

        let Body::Chunked { buflist } = &mut entity.body else {
            return Err(IllegalEntityOperator::ModifyBodyAfterSent.into());
        };

        while buflist.has_remaining() {
            let bytes = buflist.copy_to_bytes(buflist.chunk().len());
            let frame = Frame::new(Frame::DATA_FRAME_TYPE, bytes)
                .map_err(|_| IllegalEntityOperator::DataFramePayloadTooLarge)?;
            self.try_io(async |this| Ok(this.send_frame(frame).await?))
                .await?;
        }

        entity.stage = EntityStage::Trailer;
        Ok(())
    }

    pub async fn send_trailer(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        if entity.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse.into());
        }
        // prepare
        match entity.stage {
            EntityStage::Header | EntityStage::Body => {
                if entity.is_chunked() {
                    self.send_chunked_body(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Trailer);
                } else {
                    self.send_header(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Body);
                    // no body or streaming body already sent
                }
            }
            EntityStage::Trailer => {}
            EntityStage::Complete => return Ok(()),
        }

        // TODO: check FieldLines size
        let field_lines = entity.trailer.iter();
        let algo = &DEFAULT_COMPRESS_ALGO;
        self.try_io(async move |this| {
            let stream = &mut this.stream;
            let frame = this.qpack_encoder.encode(field_lines, algo, stream).await?;
            this.send_frame(frame).await?;
            Ok(())
        })
        .await?;
        entity.stage = EntityStage::Complete;

        Ok(())
    }

    async fn send_pending_sections(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        match entity.stage {
            EntityStage::Header | EntityStage::Body => {
                if entity.is_chunked() {
                    self.send_chunked_body(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Trailer);
                } else {
                    self.send_header(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Body);
                }
            }
            EntityStage::Trailer => {
                if !entity.trailers().is_empty() {
                    self.send_trailer(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Complete)
                } else {
                    // no trailer to send
                }
            }
            EntityStage::Complete => {}
        }

        Ok(())
    }

    pub async fn flush(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        self.send_pending_sections(entity).await?;
        self.try_io(async move |this| Ok(this.stream.flush_inner().await?))
            .await
    }

    pub async fn close(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        self.send_pending_sections(entity).await?;
        self.try_io(async move |this| Ok(this.stream.close().await?))
            .await?;
        Ok(())
    }

    pub async fn cancel(&mut self, code: VarInt) -> Result<(), StreamError> {
        self.try_io(async move |this| Ok(this.stream.cancel(code).await?))
            .await
    }

    pub fn take(&mut self) -> Self {
        let mock_stream = SinkWriter::new(Box::pin(MockStream) as Pin<Box<_>>);
        Self {
            stream: mem::replace(&mut self.stream, mock_stream),
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
