use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use super::{
    Write,
    body::Body,
    head::RequestHead,
    message::{Message, ReadRequest, WriteRequest},
};

pub struct Request<IO, B> {
    pub(crate) message: Message<RequestHead, Body<IO, B>>,
}

impl<IO, B> From<Message<RequestHead, Body<IO, B>>> for Request<IO, B> {
    fn from(message: Message<RequestHead, Body<IO, B>>) -> Self {
        Self { message }
    }
}

impl<IO, B> ReadRequest for Request<IO, B> {
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

impl<B> WriteRequest for Request<Write, B> {
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
