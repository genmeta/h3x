use std::sync::Arc;

use bytes::Bytes;

use crate::{
    ArcWndBuf,
    common::message::{ReadRequest, ReadResponse, WriteRequest, WriteResponse},
};

pub(crate) mod body;
pub(crate) mod head;
pub mod message;
pub(crate) mod request;
pub(crate) mod response;
pub mod wnd_buf;

/// Apply the message receive error boundary in a consistent order.
/// QPACK temporarily carries connection failures to the connection task.
pub(crate) fn receive_error<R: tokio::io::AsyncRead + qrecovery::recv::StopSending + Unpin>(
    stream: &crate::protocol::stream::H3ReadStream<R>,
    qpack: &crate::ArcQpack,
    error: &crate::Error,
) {
    use crate::ErrorCode::*;
    stream.close(error.clone());
    let connection_error = match error.code {
        H3_NO_ERROR
        | H3_REQUEST_REJECTED
        | H3_REQUEST_CANCELLED
        | H3_REQUEST_INCOMPLETE
        | H3_MESSAGE_ERROR
        | H3_CONNECT_ERROR
        | H3_VERSION_FALLBACK => false,
        H3_GENERAL_PROTOCOL_ERROR
        | H3_INTERNAL_ERROR
        | H3_STREAM_CREATION_ERROR
        | H3_CLOSED_CRITICAL_STREAM
        | H3_FRAME_UNEXPECTED
        | H3_FRAME_ERROR
        | H3_EXCESSIVE_LOAD
        | H3_ID_ERROR
        | H3_SETTINGS_ERROR
        | H3_MISSING_SETTINGS
        | QPACK_DECOMPRESSION_FAILED
        | QPACK_ENCODER_STREAM_ERROR
        | QPACK_DECODER_STREAM_ERROR => true,
    };
    if connection_error {
        qpack.on_error(error.clone());
    }
    let _ = qpack.cancel(stream.stream_id());
}

/// Validated, case-sensitive Extended CONNECT protocol token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol(Arc<str>);
impl Protocol {
    pub fn new(name: &str) -> crate::Result<Self> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        {
            return Err(crate::ErrorCode::H3_MESSAGE_ERROR.reason("invalid CONNECT protocol token"));
        }
        Ok(Self(Arc::from(name)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub enum Read {}
pub enum Write {}

/// Body storage and direction are independent: IO is Read or Write.
pub enum Body<IO> {
    Bytes(body::Body<Bytes, IO>),
    Streaming(body::Body<ArcWndBuf, IO>),
}

impl Clone for Body<Write> {
    fn clone(&self) -> Self {
        match self {
            Self::Bytes(body) => Self::Bytes(body.clone()),
            Self::Streaming(body) => Self::Streaming(body.clone()),
        }
    }
}

impl<IO> From<body::Body<Bytes, IO>> for Body<IO> {
    fn from(body: body::Body<Bytes, IO>) -> Self {
        Self::Bytes(body)
    }
}

impl<IO> From<body::Body<ArcWndBuf, IO>> for Body<IO> {
    fn from(body: body::Body<ArcWndBuf, IO>) -> Self {
        Self::Streaming(body)
    }
}

impl tokio::io::AsyncRead for Body<Read> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        output: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Bytes(body) => std::pin::Pin::new(body).poll_read(cx, output),
            Self::Streaming(body) => std::pin::Pin::new(body).poll_read(cx, output),
        }
    }
}

impl Body<Read> {
    pub async fn read(&mut self, bytes: &mut [u8]) -> crate::Result<usize> {
        match self {
            Self::Bytes(body) => body.read(bytes).await,
            Self::Streaming(body) => body.read(bytes).await,
        }
    }

    pub async fn stop(self) {
        if let Self::Streaming(body) = self {
            body.stop().await;
        }
    }

    pub async fn collect(self) -> crate::Result<Bytes> {
        match self {
            Self::Bytes(body) => body.collect().await,
            Self::Streaming(body) => body.collect().await,
        }
    }
}

pub enum Request<IO> {
    Bytes(request::Request<IO, Bytes>),
    Streaming(request::Request<IO, ArcWndBuf>),
}

pub enum Response<IO> {
    Bytes(response::Response<IO, Bytes>),
    Streaming(response::Response<IO, ArcWndBuf>),
}

impl<IO> ReadRequest for Request<IO> {
    fn protocol(&self) -> Option<crate::Protocol> {
        match self {
            Self::Bytes(r) => r.protocol(),
            Self::Streaming(r) => r.protocol(),
        }
    }

    fn method(&self) -> http::Method {
        match self {
            Self::Bytes(request) => request.method(),
            Self::Streaming(request) => request.method(),
        }
    }

    fn authority(&self) -> String {
        match self {
            Self::Bytes(request) => request.authority(),
            Self::Streaming(request) => request.authority(),
        }
    }

    fn path(&self) -> String {
        match self {
            Self::Bytes(request) => request.path(),
            Self::Streaming(request) => request.path(),
        }
    }

    fn scheme(&self) -> String {
        match self {
            Self::Bytes(request) => request.scheme(),
            Self::Streaming(request) => request.scheme(),
        }
    }

    fn headers(&self) -> http::HeaderMap {
        match self {
            Self::Bytes(request) => request.headers(),
            Self::Streaming(request) => request.headers(),
        }
    }
}

impl WriteRequest for Request<Write> {
    fn new(url: &str, method: http::Method) -> crate::Result<Self> {
        Ok(Self::Bytes(request::Request::new(url, method)?))
    }

    fn header(self, key: http::HeaderName, value: http::HeaderValue) -> Self {
        match &self {
            Self::Bytes(request) => {
                request
                    .message
                    .head
                    .lock()
                    .unwrap()
                    .headers
                    .insert(key, value);
            }
            Self::Streaming(request) => {
                request
                    .message
                    .head
                    .lock()
                    .unwrap()
                    .headers
                    .insert(key, value);
            }
        }
        self
    }
}

impl ReadResponse for Response<Read> {
    fn status(&self) -> http::StatusCode {
        match self {
            Self::Bytes(response) => response.status(),
            Self::Streaming(response) => response.status(),
        }
    }

    fn headers(&self) -> http::HeaderMap {
        match self {
            Self::Bytes(response) => response.headers(),
            Self::Streaming(response) => response.headers(),
        }
    }
}

impl WriteResponse for Response<Write> {
    fn set_status(&mut self, status: http::StatusCode) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.set_status(status);
            }
            Self::Streaming(response) => {
                response.set_status(status);
            }
        };
        self
    }

    fn set_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.set_header(name, value);
            }
            Self::Streaming(response) => {
                response.set_header(name, value);
            }
        }
        self
    }

    fn append_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.append_header(name, value);
            }
            Self::Streaming(response) => {
                response.append_header(name, value);
            }
        }
        self
    }
}

impl<IO> From<request::Request<IO, Bytes>> for Request<IO> {
    fn from(request: request::Request<IO, Bytes>) -> Self {
        Self::Bytes(request)
    }
}

impl<IO> From<request::Request<IO, ArcWndBuf>> for Request<IO> {
    fn from(request: request::Request<IO, ArcWndBuf>) -> Self {
        Self::Streaming(request)
    }
}

impl<IO> From<response::Response<IO, Bytes>> for Response<IO> {
    fn from(response: response::Response<IO, Bytes>) -> Self {
        Self::Bytes(response)
    }
}

impl<IO> From<response::Response<IO, ArcWndBuf>> for Response<IO> {
    fn from(response: response::Response<IO, ArcWndBuf>) -> Self {
        Self::Streaming(response)
    }
}

impl<IO> Request<IO> {
    pub fn into_body(self) -> Body<IO> {
        match self {
            Self::Bytes(message) => Body::Bytes(message.into_body()),
            Self::Streaming(message) => Body::Streaming(message.into_body()),
        }
    }
}

impl<IO> Response<IO> {
    pub fn into_body(self) -> Body<IO> {
        match self {
            Self::Bytes(message) => Body::Bytes(message.into_body()),
            Self::Streaming(message) => Body::Streaming(message.into_body()),
        }
    }
}
