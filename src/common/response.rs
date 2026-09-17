use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{
    Read, Write,
    body::{Body, ContentType},
    head,
    head::ResponseHead,
    message::{self, Message},
};
use crate::{
    ArcQpack, ArcWndBuf, ErrorCode, Result,
    protocol::{
        frame::{self, Frame, FrameType, H3Frame, Headers, Write as _},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub struct Response<IO, B> {
    pub(crate) message: Message<ResponseHead, Body<IO, B>>,
}

impl<IO, B> From<Message<ResponseHead, Body<IO, B>>> for Response<IO, B> {
    fn from(message: Message<ResponseHead, Body<IO, B>>) -> Self {
        Self { message }
    }
}

impl<IO, B> message::ReadResponse for Response<IO, B> {
    fn status(&self) -> StatusCode {
        self.message.status()
    }

    fn headers(&self) -> HeaderMap {
        self.message.headers()
    }
}

impl<B> message::WriteResponse for Response<Write, B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.message.set_status(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.message.set_header(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.message.append_header(name, value);
        self
    }
}

impl<IO, B: Clone> Response<IO, B> {
    /// Transfer application ownership to a directional body handle.
    pub fn into_body(self) -> Body<IO, B> {
        self.message.into_body()
    }
}

/// Construct an outgoing message using the standard HTTP builder and body storage.
impl<B> From<http::Response<B>> for Response<Write, B> {
    fn from(message: http::Response<B>) -> Self {
        let (parts, body) = message.into_parts();
        Message::from_parts(parts.into(), Body::new(body)).into()
    }
}

/// Preserve metadata and body direction when returning to the standard HTTP type.
impl<IO, B: Clone> From<Response<IO, B>> for http::Response<Body<IO, B>> {
    fn from(message: Response<IO, B>) -> Self {
        let head = message.message.head.lock().unwrap().clone();
        Self::from_parts(head.into(), message.into_body())
    }
}

/// Skip unknown extension frames and require the next known frame to be HEADERS.
async fn be_headers_frame<R: AsyncRead + Unpin + ?Sized>(rs: &mut R) -> Result<Frame<Headers>> {
    loop {
        let ty = frame::be_frame_type(rs).await?.ok_or_else(|| {
            ErrorCode::H3_FRAME_ERROR.reason("response stream ended before response HEADERS")
        })?;
        if !matches!(ty, FrameType::Headers | FrameType::Unknown(_)) {
            return Err(ErrorCode::H3_FRAME_UNEXPECTED
                .reason("expected response HEADERS before message body"));
        }
        let length = frame::be_frame_length(rs).await?;
        match frame::be_frame_payload(rs, ty, length).await? {
            H3Frame::Headers(frame) => return Ok(frame),
            H3Frame::Unknown { length, .. } => {
                frame::skip_payload(rs, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED
                    .reason("expected response HEADERS before message body"));
            }
        }
    }
}

/// Validate and encode metadata before sending HEADERS. The caller owns FIN and cleanup.
pub(crate) trait WriteResponse {
    async fn write_response_head<B: Clone>(
        &mut self,
        response: &Response<Write, B>,
        qpack: &ArcQpack,
        method: &http::Method,
    ) -> Result<ContentType>
    where
        Body<Write, B>: Into<super::Body<Write>>;

    async fn write_response_bytes_body(&mut self, response: &Response<Write, Bytes>) -> Result<()>;

    async fn write_response_streaming_body(
        &mut self,
        response: &Response<Write, ArcWndBuf>,
        mode: ContentType,
    ) -> Result<()>;
}

impl<B> Response<Write, B> {
    fn encode_head(
        &self,
        stream_id: u64,
        qpack: &ArcQpack,
        method: &http::Method,
    ) -> Result<(Vec<u8>, ContentType)>
    where
        B: Clone,
        Body<Write, B>: Into<super::Body<Write>>,
    {
        let head = self.message.head.lock().unwrap();
        let mode = ContentType::from_response(&head, Some(method))?;
        if let super::Body::Bytes(body) = self.message.body.lock().unwrap().clone().into() {
            body.validate(mode)?;
        }
        let mut fields = Vec::new();
        head.encode(&mut fields)?;
        let headers = Frame::new(Headers {
            field_section: qpack.encode(stream_id, fields)?,
        })?;
        let mut bytes = Vec::new();
        bytes.put_frame(&headers);
        Ok((bytes, mode))
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> WriteResponse for H3WriteStream<W> {
    async fn write_response_head<B: Clone>(
        &mut self,
        response: &Response<Write, B>,
        qpack: &ArcQpack,
        method: &http::Method,
    ) -> Result<ContentType>
    where
        Body<Write, B>: Into<super::Body<Write>>,
    {
        let (bytes, mode) = response.encode_head(self.stream_id(), qpack, method)?;
        self.write_all(&bytes).await?;
        Ok(mode)
    }

    async fn write_response_bytes_body(&mut self, response: &Response<Write, Bytes>) -> Result<()> {
        let body = response.message.body.lock().unwrap().clone();
        body.encode(self).await
    }

    async fn write_response_streaming_body(
        &mut self,
        response: &Response<Write, ArcWndBuf>,
        mode: ContentType,
    ) -> Result<()> {
        let mut body = response.message.body.lock().unwrap().clone();
        body.encode(self, mode).await
    }
}

pub(crate) trait ReadResponse: Sized {
    async fn read_response_head(
        &mut self,
        qpack: &ArcQpack,
        method: Option<&http::Method>,
    ) -> Result<(head::ResponseHead, ContentType)>;

    fn read_response_body(
        self,
        head: head::ResponseHead,
        mode: ContentType,
        qpack: ArcQpack,
    ) -> super::Response<Read>;

    async fn read_response(
        self,
        qpack: ArcQpack,
        method: Option<http::Method>,
    ) -> Result<super::Response<Read>>;
}

impl<R: AsyncRead + StopSending + Unpin + Send + 'static> ReadResponse for H3ReadStream<R> {
    async fn read_response_head(
        &mut self,
        qpack: &ArcQpack,
        method: Option<&http::Method>,
    ) -> Result<(head::ResponseHead, ContentType)> {
        let stream_id = self.stream_id();
        let result = async {
            loop {
                let frame = be_headers_frame(self).await?;
                let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
                let head = head::ResponseHead::decode(fields)?;
                let status = head.response_status()?;
                let mode = ContentType::from_received_response(&head, method)?;
                if status.is_informational() {
                    continue;
                }
                return Ok((head, mode));
            }
        }
        .await;
        if let Err(error) = &result {
            crate::error::receive_error(self, qpack, error);
        }
        result
    }

    fn read_response_body(
        self,
        head: head::ResponseHead,
        mode: ContentType,
        qpack: ArcQpack,
    ) -> super::Response<Read> {
        let body = Body::<Read, ArcWndBuf>::receive(self, mode, qpack);
        super::Response::Streaming(Message::from_parts(head, body).into())
    }

    async fn read_response(
        mut self,
        qpack: ArcQpack,
        method: Option<http::Method>,
    ) -> Result<super::Response<Read>> {
        let (head, mode) = self.read_response_head(&qpack, method.as_ref()).await?;
        Ok(self.read_response_body(head, mode, qpack))
    }
}
