use std::marker::PhantomData;

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use super::{
    Write,
    message::{self, Message},
};
use crate::ArcWndBuf;

pub struct Request<IO> {
    pub(crate) message: Message,
    _io: PhantomData<IO>,
}

impl<IO> From<Message> for Request<IO> {
    fn from(message: Message) -> Self {
        Self {
            message,
            _io: PhantomData,
        }
    }
}

impl<IO> message::ReadRequest for Request<IO> {
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

impl<IO> Request<IO> {
    /// Return the shared streaming body.
    pub fn into_body(self) -> ArcWndBuf {
        self.message.body
    }
}

impl message::WriteRequest for Request<Write> {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.message.set_method(method);
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.message.set_uri(uri);
        self
    }

    fn set_protocol(&mut self, protocol: &str) -> &mut Self {
        self.message.set_protocol(protocol);
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
impl From<http::Request<ArcWndBuf>> for Request<Write> {
    fn from(message: http::Request<ArcWndBuf>) -> Self {
        let (parts, body) = message.into_parts();
        Message::from_parts(parts.into(), body).into()
    }
}

/// Preserve metadata and raw body storage when returning to the standard HTTP type.
impl<IO> From<Request<IO>> for http::Request<ArcWndBuf> {
    fn from(message: Request<IO>) -> Self {
        let Message { head, body } = message.message;
        Self::from_parts(head.into(), body)
    }
}

impl<IO> message::PesudoHeaders for Request<IO> {
    fn pesudo_headers() -> &'static [&'static str] {
        &[":method", ":scheme", ":authority", ":path", ":protocol"]
    }
}

impl From<Request<Write>> for Message {
    fn from(value: Request<Write>) -> Self {
        let Message { head, body } = value.message;
        Self::from_parts(head, body)
    }
}
