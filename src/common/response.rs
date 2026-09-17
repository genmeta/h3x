use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use super::{
    Write,
    body::Body,
    head::ResponseHead,
    message::{Message, ReadResponse, WriteResponse},
};

pub struct Response<IO, B> {
    pub(crate) message: Message<ResponseHead, Body<IO, B>>,
}

impl<IO, B> From<Message<ResponseHead, Body<IO, B>>> for Response<IO, B> {
    fn from(message: Message<ResponseHead, Body<IO, B>>) -> Self {
        Self { message }
    }
}

impl<IO, B> ReadResponse for Response<IO, B> {
    fn status(&self) -> StatusCode {
        self.message.status()
    }

    fn headers(&self) -> HeaderMap {
        self.message.headers()
    }
}

impl<B> WriteResponse for Response<Write, B> {
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
