use std::marker::PhantomData;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use super::{
    Write,
    message::{self, Message},
};
use crate::ArcWndBuf;

pub struct Response<IO> {
    pub(crate) message: Message,
    _io: PhantomData<IO>,
}

impl<IO> From<Message> for Response<IO> {
    fn from(message: Message) -> Self {
        Self {
            message,
            _io: PhantomData,
        }
    }
}

impl<IO> message::ReadResponse for Response<IO> {
    fn status(&self) -> StatusCode {
        self.message.status()
    }

    fn headers(&self) -> HeaderMap {
        self.message.headers()
    }
}

impl message::WriteResponse for Response<Write> {
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

impl<IO> Response<IO> {
    /// Return the shared streaming body.
    pub fn into_body(self) -> ArcWndBuf {
        self.message.body
    }
}

/// Construct an outgoing message using the standard HTTP builder and body storage.
impl From<http::Response<ArcWndBuf>> for Response<Write> {
    fn from(message: http::Response<ArcWndBuf>) -> Self {
        let (parts, body) = message.into_parts();
        Message::from_parts(parts.into(), body).into()
    }
}

/// Preserve metadata and raw body storage when returning to the standard HTTP type.
impl<IO> From<Response<IO>> for http::Response<ArcWndBuf> {
    fn from(message: Response<IO>) -> Self {
        let Message { head, body } = message.message;
        Self::from_parts(head.into(), body)
    }
}

impl<IO> message::PesudoHeaders for Response<IO> {
    fn pesudo_headers() -> &'static [&'static str] {
        &[":status"]
    }
}

impl From<Response<Write>> for Message {
    fn from(value: Response<Write>) -> Self {
        let Message { head, body } = value.message;
        Self::from_parts(head, body)
    }
}
