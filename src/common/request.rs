use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{
    Read, Write,
    body::{Body, ContentType},
    head,
    head::RequestHead,
    message::{self, Message},
};
use crate::{
    ArcQpack, ArcWndBuf, Error, ErrorCode, Result,
    protocol::{
        frame::{self, Frame, FrameType, H3Frame, Headers, Write as _},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub struct Request<IO, B> {
    pub(crate) message: Message<RequestHead, Body<IO, B>>,
}

impl<IO, B> From<Message<RequestHead, Body<IO, B>>> for Request<IO, B> {
    fn from(message: Message<RequestHead, Body<IO, B>>) -> Self {
        Self { message }
    }
}

impl<IO, B> message::ReadRequest for Request<IO, B> {
    fn protocol(&self) -> Option<std::sync::Arc<str>> {
        self.message.protocol()
    }

    fn method(&self) -> Method {
        self.message.method()
    }

    fn authority(&self) -> String {
        self.message.authority()
    }

    fn path(&self) -> String {
        self.message.path()
    }

    fn scheme(&self) -> String {
        self.message.scheme()
    }

    fn headers(&self) -> HeaderMap {
        self.message.headers()
    }
}

impl<IO, B: Clone> Request<IO, B> {
    /// Transfer application ownership to a directional body handle.
    pub fn into_body(self) -> Body<IO, B> {
        self.message.into_body()
    }
}

impl<B> message::WriteRequest for Request<Write, B> {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.message.set_method(method);
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.message.set_uri(uri);
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

/// Construct an outgoing message using the standard HTTP builder and body storage.
impl<B> From<http::Request<B>> for Request<Write, B> {
    fn from(message: http::Request<B>) -> Self {
        let (parts, body) = message.into_parts();
        Message::from_parts(parts.into(), Body::new(body)).into()
    }
}

/// Preserve metadata and body direction when returning to the standard HTTP type.
impl<IO, B: Clone> From<Request<IO, B>> for http::Request<Body<IO, B>> {
    fn from(message: Request<IO, B>) -> Self {
        let head = message.message.head.lock().unwrap().clone();
        Self::from_parts(head.into(), message.into_body())
    }
}

/// Skip unknown frames and require request HEADERS, distinguishing clean EOF.
async fn read_headers<R: AsyncRead + Unpin + ?Sized>(rs: &mut R) -> Result<Frame<Headers>> {
    loop {
        let Some(ty) = frame::be_frame_type(rs).await? else {
            return Err(ErrorCode::H3_REQUEST_INCOMPLETE
                .reason("request stream ended before request HEADERS"));
        };
        if !matches!(ty, FrameType::Headers | FrameType::Unknown(_)) {
            return Err(ErrorCode::H3_FRAME_UNEXPECTED
                .reason("expected request HEADERS before message body"));
        }
        let length = frame::be_frame_length(rs).await?;
        match frame::be_frame_payload(rs, ty, length).await? {
            H3Frame::Headers(frame) => return Ok(frame),
            H3Frame::Unknown { length, .. } => {
                frame::skip_payload(rs, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED
                    .reason("expected request HEADERS before message body"));
            }
        }
    }
}

pub(crate) async fn read_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<head::RequestHead> {
    let stream_id = rs.stream_id();
    async {
        let frame = read_headers(rs).await?;
        let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
        let head = head::RequestHead::decode(fields)?;
        ContentType::from_request(&head)?;
        Ok::<_, Error>(head)
    }
    .await
    .inspect_err(|error| crate::error::receive_error(rs, qpack, error))
}

/// Write request HEADERS, body, and FIN; handle failures in the write direction.
pub(crate) trait WriteRequest {
    async fn write_bytes_request(
        self,
        request: Request<Write, Bytes>,
        qpack: ArcQpack,
    ) -> Result<()>
    where
        Self: Sized;

    async fn write_streaming_request(
        self,
        request: Request<Write, ArcWndBuf>,
        qpack: ArcQpack,
    ) -> Result<()>
    where
        Self: Sized;

    async fn write_request_head<B: Clone>(
        &mut self,
        request: &Request<Write, B>,
        qpack: &ArcQpack,
    ) -> Result<ContentType>
    where
        Body<Write, B>: Into<super::Body<Write>>;

    async fn write_request_bytes_body(&mut self, request: &Request<Write, Bytes>) -> Result<()>;

    /// Drain the streaming body and send FIN, handling cancellation and failures.
    async fn write_request_streaming_body(
        &mut self,
        request: &Request<Write, ArcWndBuf>,
        mode: ContentType,
    ) -> Result<()>;
}

impl<B> Request<Write, B> {
    fn encode_head(&self, stream_id: u64, qpack: &ArcQpack) -> Result<(Vec<u8>, ContentType)>
    where
        B: Clone,
        Body<Write, B>: Into<super::Body<Write>>,
    {
        let head = self.message.head.lock().unwrap();
        let mode = ContentType::from_request(&head)?;
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

impl<W: AsyncWrite + CancelStream + Unpin> WriteRequest for H3WriteStream<W> {
    async fn write_bytes_request(
        mut self,
        request: Request<Write, Bytes>,
        qpack: ArcQpack,
    ) -> Result<()>
    where
        Self: Sized,
    {
        async {
            self.write_request_head(&request, &qpack).await?;
            self.write_request_bytes_body(&request).await?;
            self.shutdown().await?;
            Ok::<_, Error>(())
        }
        .await
        .inspect_err(|error| (&self).cancel(error.code.as_u64()))
    }

    async fn write_streaming_request(
        mut self,
        request: Request<Write, ArcWndBuf>,
        qpack: ArcQpack,
    ) -> Result<()>
    where
        Self: Sized,
    {
        let body = request.message.body();
        let sending = async {
            let mode = self.write_request_head(&request, &qpack).await?;
            self.flush().await?;
            Ok(mode)
        };
        let mode = tokio::select! {
            biased;
            error = body.wait_error() => Err(error),
            result = sending => result,
        }
        .inspect_err(|error| {
            (&self).cancel(error.code.as_u64());
            body.on_error(error.clone());
        })?;
        self.write_request_streaming_body(&request, mode).await
    }

    async fn write_request_head<B: Clone>(
        &mut self,
        request: &Request<Write, B>,
        qpack: &ArcQpack,
    ) -> Result<ContentType>
    where
        Body<Write, B>: Into<super::Body<Write>>,
    {
        let (bytes, mode) = request.encode_head(self.stream_id(), qpack)?;
        self.write_all(&bytes).await?;
        Ok(mode)
    }

    async fn write_request_bytes_body(&mut self, request: &Request<Write, Bytes>) -> Result<()> {
        let body = request.message.body.lock().unwrap().clone();
        body.encode(self).await
    }

    async fn write_request_streaming_body(
        &mut self,
        request: &Request<Write, ArcWndBuf>,
        mode: ContentType,
    ) -> Result<()> {
        let producer = request.message.body();
        let sending = async {
            let mut body = request.message.body.lock().unwrap().clone();
            body.encode(self, mode).await?;
            self.shutdown().await?;
            Ok::<_, Error>(())
        };
        tokio::select! {
            biased;
            error = producer.wait_error() => Err(error),
            result = sending => result,
        }
        .inspect_err(|error| {
            (&*self).cancel(error.code.as_u64());
            producer.on_error(error.clone());
        })
    }
}

/// Reading the body transfers the stream to the background receiver.
pub(crate) trait ReadRequest: Sized {
    async fn read_request_head(&mut self, qpack: &ArcQpack) -> Result<head::RequestHead>;

    fn read_request_body(
        self,
        head: head::RequestHead,
        qpack: ArcQpack,
    ) -> Result<super::Request<Read>>;

    async fn read_request(self, qpack: ArcQpack) -> Result<super::Request<Read>>;
}

impl<R: AsyncRead + StopSending + Unpin + Send + 'static> ReadRequest for H3ReadStream<R> {
    async fn read_request_head(&mut self, qpack: &ArcQpack) -> Result<head::RequestHead> {
        read_head(self, qpack).await
    }

    fn read_request_body(
        self,
        head: head::RequestHead,
        qpack: ArcQpack,
    ) -> Result<super::Request<Read>> {
        let mode = ContentType::from_request(&head).inspect_err(|error| {
            crate::error::receive_error(&self, &qpack, error);
        })?;
        let body = Body::<Read, ArcWndBuf>::receive(self, mode, qpack);
        Ok(super::Request::Streaming(
            Message::from_parts(head, body).into(),
        ))
    }

    async fn read_request(mut self, qpack: ArcQpack) -> Result<super::Request<Read>> {
        let head = ReadRequest::read_request_head(&mut self, &qpack).await?;
        ReadRequest::read_request_body(self, head, qpack)
    }
}
