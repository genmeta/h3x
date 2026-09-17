use std::sync::{Arc, Mutex};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

use super::{
    body::Body,
    head::{RequestHead, ResponseHead},
};

#[derive(Debug)]
/// Metadata and body are shared independently so either can be accessed without
/// taking a lock for the other. Construction does not start network or body work.
pub(crate) struct Message<H, B> {
    pub(crate) head: Arc<Mutex<H>>,
    pub(crate) body: Arc<Mutex<B>>,
}

impl<H, B> Message<H, B> {
    pub(crate) fn from_parts(head: H, body: B) -> Self {
        Self {
            head: Arc::new(Mutex::new(head)),
            body: Arc::new(Mutex::new(body)),
        }
    }
}

/// Request metadata, available for both incoming and outgoing requests.
pub trait ReadRequest: Sized {
    fn protocol(&self) -> Option<std::sync::Arc<str>>;

    fn method(&self) -> Method;

    fn authority(&self) -> String;

    fn path(&self) -> String;

    fn scheme(&self) -> String;

    /// Return an owned snapshot of the ordinary headers, excluding pseudo-headers.
    /// Use [`HeaderMap::get_all`] to read multiple values for a name. Changing the
    /// returned map does not change the request.
    fn headers(&self) -> HeaderMap;
}

/// Outgoing request metadata. Set these before sending the request.
pub trait WriteRequest {
    fn set_method(&mut self, method: Method) -> &mut Self;

    fn set_uri(&mut self, uri: Uri) -> &mut Self;

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;
}

/// Server-side response status and headers. Set these before sending the response.
pub trait WriteResponse {
    fn set_status(&mut self, status: StatusCode) -> &mut Self;

    /// Replace all existing values for this header name.
    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;

    /// Append a value, preserving existing values for this header name.
    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;
}

/// Response metadata, available for both incoming and outgoing responses.
pub trait ReadResponse {
    fn status(&self) -> StatusCode;

    /// Return an owned snapshot of the ordinary headers, excluding pseudo-headers.
    /// Use [`HeaderMap::get_all`] to read multiple values such as `Set-Cookie`.
    /// Changing the returned map does not change the response.
    fn headers(&self) -> HeaderMap;
}

impl ReadRequest for RequestHead {
    fn protocol(&self) -> Option<std::sync::Arc<str>> {
        self.request_protocol().cloned()
    }

    fn method(&self) -> Method {
        self.request_method().clone()
    }

    fn authority(&self) -> String {
        self.request_uri()
            .authority()
            .map_or("", |value| value.as_str())
            .to_owned()
    }

    fn path(&self) -> String {
        self.request_uri()
            .path_and_query()
            .map_or("", |value| value.as_str())
            .to_owned()
    }

    fn scheme(&self) -> String {
        self.request_uri()
            .scheme_str()
            .unwrap_or_default()
            .to_owned()
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl<B> ReadRequest for Message<RequestHead, B> {
    fn protocol(&self) -> Option<std::sync::Arc<str>> {
        ReadRequest::protocol(&*self.head.lock().unwrap())
    }

    fn method(&self) -> Method {
        self.head.lock().unwrap().method()
    }

    fn authority(&self) -> String {
        self.head.lock().unwrap().authority()
    }

    fn path(&self) -> String {
        self.head.lock().unwrap().path()
    }

    fn scheme(&self) -> String {
        self.head.lock().unwrap().scheme()
    }

    fn headers(&self) -> HeaderMap {
        ReadRequest::headers(&*self.head.lock().unwrap())
    }
}

impl WriteResponse for ResponseHead {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.pseudo.status = Some(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.insert(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.append(name, value);
        self
    }
}

impl ReadResponse for ResponseHead {
    fn status(&self) -> StatusCode {
        self.response_status().expect("missing or invalid :status")
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl<B> WriteResponse for Message<ResponseHead, B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.head.lock().unwrap().set_status(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.lock().unwrap().set_header(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.lock().unwrap().append_header(name, value);
        self
    }
}

impl<B> ReadResponse for Message<ResponseHead, B> {
    fn status(&self) -> StatusCode {
        ReadResponse::status(&*self.head.lock().unwrap())
    }

    fn headers(&self) -> HeaderMap {
        ReadResponse::headers(&*self.head.lock().unwrap())
    }
}

impl<H, B: Clone, IO> Message<H, Body<IO, B>> {
    pub(crate) fn into_body(self) -> Body<IO, B> {
        match Arc::try_unwrap(self.body) {
            Ok(body) => body.into_inner().unwrap(),
            Err(body) => Body::new(body.lock().unwrap().storage.clone()),
        }
    }
}

impl<H, IO> Message<H, Body<IO, crate::ArcWndBuf>> {
    pub(crate) fn body_stream(&self) -> crate::ArcWndBuf {
        self.body.lock().unwrap().storage.clone()
    }
}

impl WriteRequest for RequestHead {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.pseudo.method = method;
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.pseudo.uri = uri;
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.insert(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.append(name, value);
        self
    }
}

impl<B> WriteRequest for Message<RequestHead, B> {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.head.lock().unwrap().set_method(method);
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.head.lock().unwrap().set_uri(uri);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.lock().unwrap().set_header(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.lock().unwrap().append_header(name, value);
        self
    }
}
