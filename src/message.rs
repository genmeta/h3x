use std::{
    error::Error,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures::{SinkExt, TryStreamExt, stream};
use http::{Request, Response, request, response};
use http_body_util::{BodyExt, StreamBody, combinators::UnsyncBoxBody};

use crate::{
    codec::{
        BufSinkWriter, FixedLengthReader,
        error::{DecodeStreamError, EncodeStreamError},
        util::{DecodeFrom, EncodeInto},
    },
    connection::{BoxStreamReader, QPackDecoder, QPackEncoder, State},
    error::{ApplicationError, Code, HasErrorCode, StreamError},
    frame::Frame,
    qpack::{
        field_section::FieldSection,
        strategy::{HuffmanAlways, StaticEncoder},
    },
    quic::{CancelStream, CancelStreamExt, GetStreamId, GetStreamIdExt, QuicConnect, StopSending},
    varint::{VarInt, err},
};

pub struct MessageWriter<C: QuicConnect + Unpin> {
    conenction_state: Arc<State<C>>,
    encoder: Arc<QPackEncoder>,
    stream: BufSinkWriter<Pin<Box<C::StreamWriter>>>,
}

impl<C: QuicConnect + Unpin> EncodeInto<&mut MessageWriter<C>> for request::Parts {
    async fn encode_into(self, writer: &mut MessageWriter<C>) -> Result<(), EncodeStreamError> {
        writer.send_header(self.try_into()?).await
    }
}

impl<C: QuicConnect + Unpin> EncodeInto<&mut MessageWriter<C>> for response::Parts {
    async fn encode_into(self, writer: &mut MessageWriter<C>) -> Result<(), EncodeStreamError> {
        writer.send_header(self.try_into()?).await
    }
}

impl<C: QuicConnect + Unpin, B: Buf> EncodeInto<&mut MessageWriter<C>> for http_body::Frame<B> {
    async fn encode_into(self, writer: &mut MessageWriter<C>) -> Result<(), EncodeStreamError> {
        match self.into_data() {
            Ok(bytes) => writer.send_data([bytes]).await,
            Err(frame) => match frame.into_trailers() {
                Ok(tailers) => writer.send_header(tailers.into()).await,
                Err(_) => panic!("currently, only data and trailers can be sent"),
            },
        }
    }
}

impl<C, B> EncodeInto<&mut MessageWriter<C>> for Request<B>
where
    C: QuicConnect + Unpin,
    B: http_body::Body<Data: Buf, Error: Error>,
{
    async fn encode_into(self, writer: &mut MessageWriter<C>) -> Result<(), EncodeStreamError> {
        let (parts, body) = self.into_parts();
        parts.encode_into(writer).await?;
        tokio::pin!(body);
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => frame.encode_into(writer).await?,
                Err(_error) => writer.cancel(Code::H3_NO_ERROR.into_inner()).await?,
            }
        }
        Ok(())
    }
}

impl<C, B> EncodeInto<&mut MessageWriter<C>> for Response<B>
where
    C: QuicConnect + Unpin,
    B: http_body::Body<Data: Buf, Error: Error>,
{
    async fn encode_into(self, writer: &mut MessageWriter<C>) -> Result<(), EncodeStreamError> {
        let (parts, body) = self.into_parts();
        parts.encode_into(writer).await?;

        tokio::pin!(body);
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => frame.encode_into(writer).await?,
                Err(_error) => writer.cancel(Code::H3_NO_ERROR.into_inner()).await?,
            }
        }

        Ok(())
    }
}

impl<C: QuicConnect + Unpin> MessageWriter<C> {
    pub fn new(
        conenction_state: Arc<State<C>>,
        encoder: Arc<QPackEncoder>,
        stream: BufSinkWriter<Pin<Box<C::StreamWriter>>>,
    ) -> Self {
        Self {
            conenction_state,
            encoder,
            stream,
        }
    }

    async fn handle_error(&self, error: &(impl HasErrorCode + ?Sized)) -> StreamError {
        self.conenction_state.close(error);
        self.conenction_state.error().await.into()
    }

    async fn handle_encode_stream_error(&self, error: EncodeStreamError) -> StreamError {
        self.conenction_state
            .handle_encode_stream_error(
                error.map_encode_error(|encode_error| {
                    Code::H3_FRAME_ERROR.with(encode_error).into()
                }),
            )
            .await
    }

    async fn send_header(&mut self, field_section: FieldSection) -> Result<(), EncodeStreamError> {
        const STRATEGY: StaticEncoder<HuffmanAlways> = StaticEncoder::new(HuffmanAlways);
        let stream = &mut self.stream;
        let frame = self
            .encoder
            .encode(field_section, &STRATEGY, stream)
            .await?;
        tokio::try_join!(
            frame.encode_into(&mut self.stream),
            self.encoder.flush_instructions()
        )?;
        Ok(())
    }

    pub async fn send_data<P, B>(&mut self, payload: P) -> Result<(), EncodeStreamError>
    where
        for<'c> &'c P: IntoIterator<Item = &'c B>,
        P: IntoIterator<Item = B>,
        B: Buf,
    {
        let frame =
            Frame::new(Frame::DATA_FRAME_TYPE, payload).expect("DATA frame paylod too large");
        frame.encode_into(&mut self.stream).await
    }

    pub async fn send_request<B>(&mut self, request: Request<B>) -> Result<(), StreamError>
    where
        B: http_body::Body<Data: Buf, Error: Error>,
    {
        match request.encode_into(self).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.handle_encode_stream_error(error).await),
        }
    }

    pub async fn send_response<B>(&mut self, response: Response<B>) -> Result<(), StreamError>
    where
        B: http_body::Body<Data: Buf, Error: Error>,
    {
        match response.encode_into(self).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.handle_encode_stream_error(error).await),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), StreamError> {
        self.stream.close().await
    }
}

impl<C: QuicConnect + Unpin> GetStreamId for MessageWriter<C> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_stream_id(cx)
    }
}

impl<C: QuicConnect + Unpin> CancelStream for MessageWriter<C> {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        Pin::new(&mut self.get_mut().stream).poll_cancel(cx, code)
    }
}

// TODO: stop_sending when receiving the final message
pub struct MessageReader<C: QuicConnect> {
    connecttion_state: Arc<State<C>>,
    decoder: Arc<QPackDecoder>,
    frame: Option<Frame<FixedLengthReader<BoxStreamReader<C>>>>,
    stream_id: VarInt,
    final_message_received: bool,
}

impl<C: QuicConnect + Unpin> DecodeFrom<&mut MessageReader<C>> for response::Parts {
    async fn decode_from(reader: &mut MessageReader<C>) -> Result<Self, DecodeStreamError> {
        let header_frame = reader.frame.as_mut().unwrap();
        if header_frame.r#type() != Frame::HEADERS_FRAME_TYPE {
            return Err(Code::H3_FRAME_UNEXPECTED.into());
        }

        let field_section = reader.decoder.decode(header_frame).await?;
        Ok(field_section.try_into()?)
    }
}

impl<C: QuicConnect + Unpin> DecodeFrom<&mut MessageReader<C>> for request::Parts {
    async fn decode_from(reader: &mut MessageReader<C>) -> Result<Self, DecodeStreamError> {
        let header_frame = reader.frame.as_mut().unwrap();
        if header_frame.r#type() != Frame::HEADERS_FRAME_TYPE {
            return Err(Code::H3_FRAME_UNEXPECTED.into());
        }

        let field_section = reader.decoder.decode(header_frame).await?;
        Ok(field_section.try_into()?)
    }
}

impl<C: QuicConnect + Unpin> DecodeFrom<&mut MessageReader<C>> for http_body::Frame<Bytes> {
    async fn decode_from(reader: &mut MessageReader<C>) -> Result<Self, DecodeStreamError> {
        let frame = reader.frame.as_mut().unwrap();
        match frame.r#type() {
            Frame::DATA_FRAME_TYPE => {
                let bytes = frame.try_next().await?.unwrap();
                Ok(http_body::Frame::data(bytes))
            }
            Frame::HEADERS_FRAME_TYPE => {
                let field_section = reader.decoder.decode(frame).await?;
                let trailers = field_section.try_into_trailers()?;
                Ok(http_body::Frame::trailers(trailers))
            }
            _ => Err(Code::H3_FRAME_UNEXPECTED.into()),
        }
    }
}

impl<C> DecodeFrom<&mut MessageReader<C>> for Request<UnsyncBoxBody<Bytes, StreamError>>
where
    C: QuicConnect + Send + Unpin + 'static,
    C::StreamReader: Send + Sync,
{
    async fn decode_from(reader: &mut MessageReader<C>) -> Result<Self, DecodeStreamError> {
        let parts = request::Parts::decode_from(reader).await?;
        let body = reader.final_message_body().boxed_unsync();
        Ok(Request::from_parts(parts, body))
    }
}

impl<C> DecodeFrom<&mut MessageReader<C>> for Response<UnsyncBoxBody<Bytes, StreamError>>
where
    C: QuicConnect + Send + Unpin + 'static,
    C::StreamReader: Send + Sync,
{
    async fn decode_from(reader: &mut MessageReader<C>) -> Result<Self, DecodeStreamError> {
        let parts = response::Parts::decode_from(reader).await?;
        let body = match parts.status.is_informational() {
            true => http_body_util::Empty::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
            false => reader.final_message_body().boxed_unsync(),
        };
        Ok(Response::from_parts(parts, body))
    }
}

// TODO: handle PUSH
impl<C> MessageReader<C>
where
    C: QuicConnect + Unpin,
{
    pub(crate) async fn new(
        connecttion_state: Arc<State<C>>,
        decoder: Arc<QPackDecoder>,
        mut stream: BoxStreamReader<C>,
    ) -> Result<Self, StreamError> {
        let stream_id = stream.stream_id().await?;
        let frame = match Frame::decode_from(stream).await {
            Ok(frame) => frame,
            Err(DecodeStreamError::Code { source }) => {
                connecttion_state.close(source.as_ref());
                return Err(connecttion_state.error().await.into());
            }
            Err(DecodeStreamError::Decode { .. }) => unreachable!(),
            Err(DecodeStreamError::Stream { source }) => return Err(source),
        };
        Ok(Self {
            connecttion_state,
            decoder,
            frame: Some(frame),
            stream_id,
            final_message_received: false,
        })
    }

    async fn handle_error(&self, error: &(impl HasErrorCode + ?Sized)) -> StreamError {
        self.connecttion_state.close(error);
        self.connecttion_state.error().await.into()
    }

    async fn handle_decode_stream_error(&self, error: DecodeStreamError) -> StreamError {
        self.connecttion_state
            .handle_decode_stream_error(
                error.map_decode_error(|decode_error| {
                    Code::H3_MESSAGE_ERROR.with(decode_error).into()
                }),
            )
            .await
    }

    pub async fn next_frame(
        &mut self,
    ) -> Option<Result<&mut Frame<FixedLengthReader<BoxStreamReader<C>>>, StreamError>> {
        loop {
            let frame = self.frame.take()?;

            if frame.r#type() != Frame::HEADERS_FRAME_TYPE
                && frame.r#type() != Frame::DATA_FRAME_TYPE
                && !frame.is_reversed_frame()
            {
                return Some(Err(self.handle_error(&Code::H3_FRAME_UNEXPECTED).await));
            }

            if frame.payload().remaining() == 0 || frame.is_reversed_frame() {
                match frame.into_next_frame().await.transpose() {
                    Ok(frame) => {
                        self.frame = frame;
                        continue;
                    }
                    Err(error) => return Some(Err(self.handle_decode_stream_error(error).await)),
                }
            }

            self.frame = Some(frame);
            return self.frame.as_mut().map(Ok);
        }
    }

    fn final_message_body(
        &mut self,
    ) -> impl http_body::Body<Data = Bytes, Error = StreamError> + use<C> {
        self.final_message_received = true;
        let body = Self {
            connecttion_state: self.connecttion_state.clone(),
            decoder: self.decoder.clone(),
            frame: self.frame.take(),
            stream_id: self.stream_id,
            final_message_received: self.final_message_received,
        };

        StreamBody::new(stream::unfold(body, |mut body| async move {
            match body.next_frame().await? {
                Ok(_frame) => {}
                Err(error) => return Some((Err(error), body)),
            };

            match http_body::Frame::decode_from(&mut body).await {
                Ok(frame) => Some((Ok(frame), body)),
                Err(error) => {
                    let error = body.handle_decode_stream_error(error).await;
                    Some((Err(error), body))
                }
            }
        }))
    }

    pub async fn read_request(
        mut self,
    ) -> Result<Request<UnsyncBoxBody<Bytes, StreamError>>, StreamError>
    where
        C: Send + 'static,
        C::StreamReader: Send + Sync,
    {
        match self.next_frame().await.transpose()? {
            Some(_frame) => {}
            None => return Err(self.handle_error(&Code::H3_FRAME_UNEXPECTED).await),
        }
        match Request::decode_from(&mut self).await {
            Ok(request) => Ok(request),
            Err(error) => Err(self.handle_decode_stream_error(error).await),
        }
    }

    pub async fn read_response(
        &mut self,
    ) -> Option<Result<Response<UnsyncBoxBody<Bytes, StreamError>>, StreamError>>
    where
        C: Send + 'static,
        C::StreamReader: Send + Sync,
    {
        let final_message_received = self.final_message_received;
        match self.next_frame().await {
            Some(Ok(_frame)) => {}
            Some(Err(error)) => return Some(Err(error)),
            None if !final_message_received => {
                return Some(Err(self.handle_error(&Code::H3_FRAME_UNEXPECTED).await));
            }
            None => return None,
        }
        match Response::decode_from(self).await {
            Ok(response) => Some(Ok(response)),
            Err(error) => Some(Err(self.handle_decode_stream_error(error).await)),
        }
    }
}

impl<C: QuicConnect + Unpin> GetStreamId for MessageReader<C> {
    fn poll_stream_id(self: Pin<&mut Self>, _: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<C: QuicConnect + Unpin> StopSending for MessageReader<C> {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        if let Some(frame) = self.get_mut().frame.as_mut() {
            ready!(Pin::new(frame).poll_stop_sending(cx, code)?)
        }
        Poll::Ready(Ok(()))
    }
}
