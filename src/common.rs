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

pub enum Read {}
pub enum Write {}

/// Body storage and direction are independent: IO is Read or Write.
pub enum Body<IO> {
    Bytes(body::Body<IO, Bytes>),
    Streaming(body::Body<IO, ArcWndBuf>),
}

impl Clone for Body<Write> {
    fn clone(&self) -> Self {
        match self {
            Self::Bytes(body) => Self::Bytes(body.clone()),
            Self::Streaming(body) => Self::Streaming(body.clone()),
        }
    }
}

impl<IO> From<body::Body<IO, Bytes>> for Body<IO> {
    fn from(body: body::Body<IO, Bytes>) -> Self {
        Self::Bytes(body)
    }
}

impl<IO> From<body::Body<IO, ArcWndBuf>> for Body<IO> {
    fn from(body: body::Body<IO, ArcWndBuf>) -> Self {
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
        Ok(tokio::io::AsyncReadExt::read(self, bytes).await?)
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
    fn protocol(&self) -> Option<std::sync::Arc<str>> {
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

impl<IO> ReadResponse for Response<IO> {
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

impl WriteRequest for Request<Write> {
    fn set_method(&mut self, method: http::Method) -> &mut Self {
        match self {
            Self::Bytes(request) => {
                request.set_method(method);
            }
            Self::Streaming(request) => {
                request.set_method(method);
            }
        }
        self
    }

    fn set_uri(&mut self, uri: http::Uri) -> &mut Self {
        match self {
            Self::Bytes(request) => {
                request.set_uri(uri);
            }
            Self::Streaming(request) => {
                request.set_uri(uri);
            }
        }
        self
    }

    fn set_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(request) => {
                request.set_header(name, value);
            }
            Self::Streaming(request) => {
                request.set_header(name, value);
            }
        }
        self
    }

    fn append_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(request) => {
                request.append_header(name, value);
            }
            Self::Streaming(request) => {
                request.append_header(name, value);
            }
        }
        self
    }
}

impl<IO> From<Request<IO>> for http::Request<Body<IO>> {
    fn from(message: Request<IO>) -> Self {
        match message {
            Request::Bytes(message) => http::Request::from(message).map(Body::Bytes),
            Request::Streaming(message) => http::Request::from(message).map(Body::Streaming),
        }
    }
}

impl<IO> From<Response<IO>> for http::Response<Body<IO>> {
    fn from(message: Response<IO>) -> Self {
        match message {
            Response::Bytes(message) => http::Response::from(message).map(Body::Bytes),
            Response::Streaming(message) => http::Response::from(message).map(Body::Streaming),
        }
    }
}

impl qrecovery::recv::StopSending for Body<Read> {
    fn stop(&mut self, error_code: u64) {
        match self {
            Self::Bytes(body) => body.stop(error_code),
            Self::Streaming(body) => body.stop(error_code),
        }
    }
}
