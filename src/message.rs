use std::{
    error::Error as StdError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use futures::{SinkExt, TryStreamExt, stream};
use http::{Request, Response, request, response};
use http_body_util::{BodyExt, StreamBody, combinators::UnsyncBoxBody};

use crate::{
    codec::{Decode, DecodeExt, Encode, EncodeExt, FixedLengthReader, SinkWriter},
    connection::{BoxStreamReader, QPackDecoder, QPackEncoder, State},
    error::{Code, Error, StreamError},
    frame::Frame,
    qpack::{
        algorithm::{HuffmanAlways, StaticEncoder},
        field_section::FieldSection,
    },
    quic::{CancelStream, CancelStreamExt, GetStreamId, GetStreamIdExt, QuicConnect, StopSending},
    varint::VarInt,
};

pub struct MessageWriter<C: QuicConnect + Unpin> {
    conenction_state: Arc<State<C>>,
    encoder: Arc<QPackEncoder>,
    stream: SinkWriter<Pin<Box<C::StreamWriter>>>,
}

impl<C: QuicConnect + Unpin> Encode<request::Parts> for &mut MessageWriter<C> {
    type Output = ();

    type Error = Error;

    async fn encode(self, parts: request::Parts) -> Result<Self::Output, Self::Error> {
        self.send_header(parts.try_into()?).await
    }
}

impl<C: QuicConnect + Unpin> Encode<response::Parts> for &mut MessageWriter<C> {
    type Output = ();

    type Error = Error;

    async fn encode(self, parts: response::Parts) -> Result<Self::Output, Self::Error> {
        self.send_header(parts.try_into()?).await
    }
}

impl<C: QuicConnect + Unpin, B: Buf> Encode<http_body::Frame<B>> for &mut MessageWriter<C> {
    type Output = ();

    type Error = Error;

    async fn encode(self, frame: http_body::Frame<B>) -> Result<Self::Output, Self::Error> {
        match frame.into_data() {
            Ok(bytes) => self.send_data(bytes).await.map_err(Error::from),
            Err(frame) => match frame.into_trailers() {
                Ok(tailers) => self.send_header(tailers.into()).await,
                Err(_) => panic!("currently, only data and trailers can be sent"),
            },
        }
    }
}

impl<C, B> Encode<Request<B>> for &mut MessageWriter<C>
where
    C: QuicConnect + Unpin,
    B: http_body::Body<Data: Buf, Error: StdError>,
{
    type Output = ();

    type Error = Error;

    async fn encode(self, request: Request<B>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        self.encode(parts).await?;
        tokio::pin!(body);
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => self.encode(frame).await?,
                Err(_error) => self.cancel(Code::H3_NO_ERROR.into_inner()).await?,
            }
        }
        Ok(())
    }
}

impl<C, B> Encode<Response<B>> for &mut MessageWriter<C>
where
    C: QuicConnect + Unpin,
    B: http_body::Body<Data: Buf, Error: StdError>,
{
    type Output = ();

    type Error = Error;

    async fn encode(self, request: Response<B>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        self.encode(parts).await?;
        tokio::pin!(body);
        while let Some(frame) = body.frame().await {
            match frame {
                Ok(frame) => self.encode(frame).await?,
                Err(_error) => self.cancel(Code::H3_NO_ERROR.into_inner()).await?,
            }
        }
        Ok(())
    }
}

impl<C: QuicConnect + Unpin> MessageWriter<C> {
    pub fn new(
        conenction_state: Arc<State<C>>,
        encoder: Arc<QPackEncoder>,
        stream: SinkWriter<Pin<Box<C::StreamWriter>>>,
    ) -> Self {
        Self {
            conenction_state,
            encoder,
            stream,
        }
    }

    async fn send_header(&mut self, field_section: FieldSection) -> Result<(), Error> {
        const STRATEGY: StaticEncoder<HuffmanAlways> = StaticEncoder::new(HuffmanAlways);
        let stream = &mut self.stream;
        let frame = self
            .encoder
            .encode(field_section, &STRATEGY, stream)
            .await?;
        self.stream.encode_one(frame).await?;
        Ok(())
    }

    pub async fn send_data(&mut self, payload: impl Buf) -> Result<(), StreamError> {
        let frame =
            Frame::new(Frame::DATA_FRAME_TYPE, payload).expect("DATA frame paylod too large");
        self.stream.encode_one(frame).await
    }

    pub async fn send_request<B>(&mut self, request: Request<B>) -> Result<(), StreamError>
    where
        B: http_body::Body<Data: Buf, Error: StdError>,
    {
        match self.encode_one(request).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.conenction_state.handle_error(error).await),
        }
    }

    pub async fn send_response<B>(&mut self, response: Response<B>) -> Result<(), StreamError>
    where
        B: http_body::Body<Data: Buf, Error: StdError>,
    {
        match self.encode_one(response).await {
            Ok(()) => Ok(()),
            Err(error) => Err(self.conenction_state.handle_error(error).await),
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

impl<C: QuicConnect + Unpin> Decode<request::Parts> for &mut MessageReader<C> {
    type Error = Error;

    async fn decode(self) -> Result<request::Parts, Self::Error> {
        let header_frame = self.frame.as_mut().unwrap();
        if header_frame.r#type() != Frame::HEADERS_FRAME_TYPE {
            return Err(Code::H3_FRAME_UNEXPECTED.into());
        }

        let field_section = self.decoder.decode(header_frame).await?;
        Ok(field_section.try_into()?)
    }
}

impl<C: QuicConnect + Unpin> Decode<response::Parts> for &mut MessageReader<C> {
    type Error = Error;

    async fn decode(self) -> Result<response::Parts, Self::Error> {
        let header_frame = self.frame.as_mut().unwrap();
        if header_frame.r#type() != Frame::HEADERS_FRAME_TYPE {
            return Err(Code::H3_FRAME_UNEXPECTED.into());
        }

        let field_section = self.decoder.decode(header_frame).await?;
        Ok(field_section.try_into()?)
    }
}

impl<C: QuicConnect + Unpin> Decode<http_body::Frame<Bytes>> for &mut MessageReader<C> {
    type Error = Error;

    async fn decode(self) -> Result<http_body::Frame<Bytes>, Self::Error> {
        let frame = self.frame.as_mut().unwrap();
        match frame.r#type() {
            Frame::DATA_FRAME_TYPE => {
                let bytes = frame
                    .try_next()
                    .await
                    .map_err(|error| {
                        error.map_decode_error(|error| Code::H3_FRAME_ERROR.with(error).into())
                    })?
                    .unwrap();
                Ok(http_body::Frame::data(bytes))
            }
            Frame::HEADERS_FRAME_TYPE => {
                let field_section = self.decoder.decode(frame).await?;
                let trailers = field_section.try_into_trailers()?;
                Ok(http_body::Frame::trailers(trailers))
            }
            _ => Err(Code::H3_FRAME_UNEXPECTED.into()),
        }
    }
}

impl<C> Decode<Request<UnsyncBoxBody<Bytes, StreamError>>> for &mut MessageReader<C>
where
    C: QuicConnect + Send + Unpin + 'static,
    C::StreamReader: Send + Sync,
{
    type Error = Error;

    async fn decode(self) -> Result<Request<UnsyncBoxBody<Bytes, StreamError>>, Self::Error> {
        let parts = self.decode_one::<request::Parts>().await?;
        let body = self.final_message_body().boxed_unsync();
        Ok(Request::from_parts(parts, body))
    }
}

impl<C> Decode<Response<UnsyncBoxBody<Bytes, StreamError>>> for &mut MessageReader<C>
where
    C: QuicConnect + Send + Unpin + 'static,
    C::StreamReader: Send + Sync,
{
    type Error = Error;

    async fn decode(self) -> Result<Response<UnsyncBoxBody<Bytes, StreamError>>, Self::Error> {
        let parts = self.decode_one::<response::Parts>().await?;
        let body = match parts.status.is_informational() {
            true => http_body_util::Empty::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
            false => self.final_message_body().boxed_unsync(),
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
        let frame = match stream.into_decoded::<Frame<_>>().await {
            Ok(frame) => frame,
            Err(error) => return Err(connecttion_state.handle_error(error).await),
        };
        Ok(Self {
            connecttion_state,
            decoder,
            frame: Some(frame),
            stream_id,
            final_message_received: false,
        })
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
                let error = Code::H3_FRAME_UNEXPECTED;
                return Some(Err(self.connecttion_state.handle_error(error.into()).await));
            }

            if frame.payload().remaining() == 0 || frame.is_reversed_frame() {
                match frame.into_next_frame().await.transpose() {
                    Ok(frame) => {
                        self.frame = frame;
                        continue;
                    }
                    Err(error) => {
                        return Some(Err(self.connecttion_state.handle_error(error).await));
                    }
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

            match body.decode_one::<http_body::Frame<_>>().await {
                Ok(frame) => Some((Ok(frame), body)),
                Err(error) => {
                    let error = body.connecttion_state.handle_error(error).await;
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
            None => {
                let error = Code::H3_FRAME_UNEXPECTED.into();
                return Err(self.connecttion_state.handle_error(error).await);
            }
        }
        match self.decode_one::<Request<_>>().await {
            Ok(request) => Ok(request),
            Err(error) => Err(self.connecttion_state.handle_error(error).await),
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
                let error = Code::H3_MESSAGE_ERROR.into();
                return Some(Err(self.connecttion_state.handle_error(error).await));
            }
            None => return None,
        }
        match self.decode_one::<Response<_>>().await {
            Ok(response) => Some(Ok(response)),
            Err(error) => Some(Err(self.connecttion_state.handle_error(error).await)),
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
