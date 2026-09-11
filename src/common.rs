use bytes::Bytes;

use crate::{
    ArcWndBuf,
    common::message::{ReadRequest, ReadResponse, WriteRequest, WriteResponse},
};

pub mod message;
pub(crate) mod request;
pub(crate) mod response;

pub enum Read {}
pub enum Write {}

pub enum Request<IO> {
    Bytes(request::Request<IO, Bytes>),
    Streaming(request::Request<IO, ArcWndBuf>),
}

pub enum Response<IO> {
    Bytes(response::Response<IO, Bytes>),
    Streaming(response::Response<IO, ArcWndBuf>),
}

impl ReadRequest for Request<Read> {
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
}

impl WriteRequest for Request<Write> {
    fn new(url: &str, method: http::Method) -> crate::Result<Self> {
        Ok(Self::Bytes(request::Request::new(url, method)?))
    }

    fn header(self, key: http::HeaderName, value: http::HeaderValue) -> Self {
        match &self {
            Self::Bytes(request) => {
                request.message.0.lock().unwrap().set_header(key, value);
            }
            Self::Streaming(request) => {
                request.message.0.lock().unwrap().set_header(key, value);
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
