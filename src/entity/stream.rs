use std::{
    io, mem,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures::{Sink, SinkExt, Stream, StreamExt, TryStreamExt, future};
use http::HeaderMap;
use snafu::Snafu;

use super::Body;
use crate::{
    buflist::{BufList, Cursor},
    codec::{EncodeExt, SinkWriter, StreamReader},
    connection::{self, ConnectionState, QPackDecoder, QPackEncoder},
    entity::{Entity, EntityStage, IllegalEntityOperator},
    error::Code,
    frame::{Frame, stream::FrameStream},
    qpack::{
        algorithm::{HuffmanAlways, StaticCompressAlgo},
        field_section::FieldSection,
    },
    quic::{
        self, CancelStream, CancelStreamExt, GetStreamId, GetStreamIdExt, StopSending,
        StopSendingExt,
    },
    varint::VarInt,
};

pub struct MockStream;

impl Sink<Bytes> for MockStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unreachable!()
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        unreachable!()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unreachable!()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        unreachable!()
    }
}

impl Stream for MockStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        unreachable!()
    }
}

impl CancelStream for MockStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        unreachable!()
    }
}

impl StopSending for MockStream {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        unreachable!()
    }
}

impl GetStreamId for MockStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        unreachable!()
    }
}

#[derive(Debug, Snafu)]
pub enum StreamError {
    #[snafu(transparent)]
    Quic {
        source: quic::StreamError,
    },
    Goaway,
    #[snafu(transparent)]
    IllegalEntityOperator {
        source: IllegalEntityOperator,
    },
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
            StreamError::Goaway => io::ErrorKind::ConnectionRefused,
            StreamError::IllegalEntityOperator { .. } => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, error)
    }
}

pub struct ReadStream {
    stream: FrameStream<Pin<Box<dyn quic::ReadStream + Send>>>,
    decoder: Arc<QPackDecoder>,
    connection: Arc<ConnectionState<dyn quic::Close + Unpin + Send>>,
}

impl ReadStream {
    pub fn new(
        stream: Pin<Box<dyn quic::ReadStream + Send>>,
        decoder: Arc<QPackDecoder>,
        connection: Arc<ConnectionState<dyn quic::Close + Unpin + Send>>,
    ) -> Self {
        let stream = FrameStream::new(StreamReader::new(stream));
        Self {
            stream,
            decoder,
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

        // TODO: Is there any better way to move ownership of the stream.
        Ok(async move { peer_goaway.boxed().fuse().select_next_some().await })
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
                    _ = self.stream.stop_sending(Code::H3_NO_ERROR.into()).await;
                    Err(StreamError::Goaway)
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
            .try_io(async move |this| {
                let frame = match this.stream.next_unreserved_frame().await.transpose()? {
                    Some(frame) if frame.r#type() != Frame::HEADERS_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(frame) => frame,
                    None => {
                        let error = Code::H3_MESSAGE_ERROR.into();
                        return Err(this.connection.handle_error(error).await.into());
                    }
                };
                this.decoder.decode(frame).await
            })
            .await?;

        if entity.is_interim_response() {
            entity.stage = EntityStage::Header
        } else {
            entity.stage = EntityStage::Body
        }
        Ok(&entity.header)
    }

    async fn read_next_body(&mut self, entity: &mut Entity) -> Option<Result<Bytes, StreamError>> {
        match entity.stage {
            EntityStage::Header => {
                while entity.is_interim_response() {
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
                    Body::Streaming => return None,
                    Body::Chunked(cursor) => {
                        if cursor.has_remaining() {
                            return Some(Ok(cursor.copy_to_bytes(cursor.chunk().len())));
                        }
                    }
                };
            }
        }

        self.try_io(async move |this| {
            loop {
                match this.stream.frame().transpose()? {
                    Some(frame) if frame.r#type() == Frame::HEADERS_FRAME_TYPE => {
                        entity.stage = EntityStage::Trailer;
                        return Ok(None);
                    }
                    Some(frame) if frame.r#type() != Frame::DATA_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(mut frame) => match frame.try_next().await {
                        Ok(Some(bytes)) => return Ok(Some(bytes)),
                        Ok(None) => {
                            this.stream.decode_next_unreserved_frame().await;
                            continue;
                        }
                        Err(error) => {
                            return Err(error.map_decode_error(|error| {
                                Code::H3_FRAME_ERROR.with(error).into()
                            }));
                        }
                    },
                    None => {
                        entity.stage = EntityStage::Complete;
                        return Ok(None);
                    }
                };
            }
        })
        .await
        .transpose()
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
            Body::Streaming => {
                let mut buflist = BufList::new();
                loop {
                    let Some(next) = self.read_next_body(entity).await else {
                        break;
                    };
                    buflist.write(next?);
                }
                Ok(Buffer::Owned(buflist))
            }
            Body::Chunked(..) => {
                loop {
                    let Some(next) = self.read_next_body(entity).await else {
                        break;
                    };
                    entity.chunked_body().expect("Check above").write(next?);
                }
                Ok(Buffer::Borrow(entity.chunked_body().expect("Check above")))
            }
        }
    }

    pub async fn read(&mut self, entity: &mut Entity) -> Option<Result<Bytes, StreamError>> {
        match &entity.body {
            Body::Streaming => self.read_next_body(entity).await,
            Body::Chunked(..) => match self.read_all(entity).await {
                Ok(body) if !body.has_remaining() => None,
                Ok(mut body) => Some(Ok(body.copy_to_bytes(body.chunk().len()))),
                Err(error) => Some(Err(error)),
            },
        }
    }

    pub async fn read_trailer<'e>(
        &mut self,
        entity: &'e mut Entity,
    ) -> Result<&'e HeaderMap, StreamError> {
        match entity.stage {
            EntityStage::Header | EntityStage::Body => {
                // consume the full body
                if entity.is_streaming() {
                    // read and discard body
                    while let Some(next) = self.read_next_body(entity).await {
                        next?;
                    }
                } else {
                    // read and buffer body
                    self.read_all(entity).await?;
                }
                debug_assert_eq!(entity.stage, EntityStage::Trailer);
            }
            EntityStage::Trailer => {}
            EntityStage::Complete => return Ok(entity.trailers()),
        }

        entity.trailer = self
            .try_io(async |this| {
                let frame = match this.stream.next_unreserved_frame().await.transpose()? {
                    Some(frame) if frame.r#type() != Frame::HEADERS_FRAME_TYPE => {
                        return Err(Code::H3_FRAME_UNEXPECTED.into());
                    }
                    Some(frame) => frame,
                    None => return Err(Code::H3_MESSAGE_ERROR.into()),
                };

                if entity.is_interim_response() {
                    return Err(Code::H3_FRAME_UNEXPECTED.into());
                }

                this.decoder.decode(frame).await
            })
            .await?;

        entity.stage = EntityStage::Complete;

        Ok(entity.trailers())
    }

    pub async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        self.stop_sending(code).await
    }

    pub fn take(&mut self) -> Self {
        let mock_stream = FrameStream::new(StreamReader::new(Box::pin(MockStream) as Pin<Box<_>>));
        Self {
            stream: mem::replace(&mut self.stream, mock_stream),
            decoder: self.decoder.clone(),
            connection: self.connection.clone(),
        }
    }
}

impl StopSending for ReadStream {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stop_sending(cx, code)
    }
}

pub struct WriteStream {
    stream: SinkWriter<Pin<Box<dyn quic::WriteStream + Send>>>,
    encoder: Arc<QPackEncoder>,
    connection: Arc<ConnectionState<dyn quic::Close + Unpin + Send>>,
}

const DEFAULT_COMPRESS_ALGO: StaticCompressAlgo<HuffmanAlways> =
    StaticCompressAlgo::new(HuffmanAlways);

impl WriteStream {
    pub fn new(
        stream: Pin<Box<dyn quic::WriteStream + Send>>,
        encoder: Arc<QPackEncoder>,
        connection: Arc<ConnectionState<dyn quic::Close + Unpin + Send>>,
    ) -> Self {
        let stream = SinkWriter::new(stream);
        Self {
            stream,
            encoder,
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

        // TODO: Is there any better way to move ownership of the stream.
        Ok(async move { peer_goaway.boxed().fuse().select_next_some().await })
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
                    _ = self.stream.cancel(Code::H3_NO_ERROR.into()).await;
                    Err(StreamError::Goaway)
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

        if !entity.is_header_complete() {
            return Err(IllegalEntityOperator::SendIncompleteHeader.into());
        }

        let field_lines = entity.header.iter();
        let algo = &DEFAULT_COMPRESS_ALGO;
        self.try_io(async move |this| {
            let stream = &mut this.stream;
            let frame = this.encoder.encode(field_lines, algo, stream).await?;
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
        if entity.is_interim_response() {
            return Err(IllegalEntityOperator::SendBodyOrTrailerForInterimResponse.into());
        }

        entity.enbale_streaming()?;

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

        let Body::Chunked(content) = &mut entity.body else {
            return Err(IllegalEntityOperator::ModifyBodyAfterSent.into());
        };

        while content.has_remaining() {
            let bytes = content.copy_to_bytes(content.chunk().len());
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
                if matches!(entity.body, Body::Chunked(..)) {
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
            let frame = this.encoder.encode(field_lines, algo, stream).await?;
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
                if matches!(entity.body, Body::Chunked(..)) {
                    self.send_chunked_body(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Trailer);
                } else {
                    self.send_header(entity).await?;
                    debug_assert_eq!(entity.stage, EntityStage::Body);
                    // no body or streaming body already sent
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
        self.try_io(async move |this| Ok(this.stream.flush().await?))
            .await
    }

    pub async fn close(&mut self, entity: &mut Entity) -> Result<(), StreamError> {
        if entity.is_interim_response() {
            return Err(IllegalEntityOperator::MissingFinalResponse.into());
        }
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
            encoder: self.encoder.clone(),
            connection: self.connection.clone(),
        }
    }
}
