use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    Read, Write,
    body::Body,
    head::{RequestHead, ResponseHead},
};
use crate::Result;

#[derive(Debug, Default)]
/// Metadata and body are shared independently so either can be accessed without
/// taking a lock for the other. Construction does not start network or body work.
pub(crate) struct Message<H, B> {
    pub(crate) head: Arc<Mutex<H>>,
    pub(crate) body: Arc<Mutex<B>>,
}

impl<H, B> Clone for Message<H, B> {
    fn clone(&self) -> Self {
        Self {
            head: self.head.clone(),
            body: self.body.clone(),
        }
    }
}

impl<H, B> Message<H, B> {
    pub(crate) fn from_parts(head: H, body: B) -> Self {
        Self {
            head: Arc::new(Mutex::new(head)),
            body: Arc::new(Mutex::new(body)),
        }
    }
}

/// Client-side request construction and headers.
pub trait WriteRequest: Sized {
    fn new(url: &str, method: Method) -> Result<Self>;

    fn get(url: &str) -> Result<Self> {
        Self::new(url, Method::GET)
    }

    fn head(url: &str) -> Result<Self> {
        Self::new(url, Method::HEAD)
    }

    fn post(url: &str) -> Result<Self> {
        Self::new(url, Method::POST)
    }

    fn put(url: &str) -> Result<Self> {
        Self::new(url, Method::PUT)
    }

    fn delete(url: &str) -> Result<Self> {
        Self::new(url, Method::DELETE)
    }

    fn connect(url: &str) -> Result<Self> {
        Self::new(url, Method::CONNECT)
    }

    fn options(url: &str) -> Result<Self> {
        Self::new(url, Method::OPTIONS)
    }

    fn trace(url: &str) -> Result<Self> {
        Self::new(url, Method::TRACE)
    }

    fn patch(url: &str) -> Result<Self> {
        Self::new(url, Method::PATCH)
    }

    /// Replace all existing values for this header name.
    fn header(self, key: HeaderName, value: HeaderValue) -> Self;
}

pub trait WriteBody {
    fn set_body(&mut self, body: Bytes) -> &mut Self;
}

#[async_trait]
pub trait WriteStream: Sized {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize>;

    /// Close the producer. Buffered bytes remain readable and the send task
    /// drains them before sending FIN; this does not wait for transport shutdown.
    async fn finish(&mut self) -> Result<()>;

    /// Cancel the body, discard buffered bytes, and wake pending operations.
    async fn reset(self) -> Result<()>;
}

/// Server-side view of request metadata.
pub trait ReadRequest: Sized {
    fn protocol(&self) -> Option<crate::Protocol> {
        None
    }
    fn method(&self) -> Method;

    fn authority(&self) -> String;

    fn path(&self) -> String;

    fn scheme(&self) -> String;

    /// Return an owned snapshot of the ordinary headers, excluding pseudo-headers.
    /// Use [`HeaderMap::get_all`] to read multiple values for a name. Changing the
    /// returned map does not change the request.
    fn headers(&self) -> HeaderMap;
}

/// Server-side response status and headers. Set these before sending the response.
pub trait WriteResponse {
    fn set_status(&mut self, status: StatusCode) -> &mut Self;

    /// Replace all existing values for this header name.
    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;

    /// Append a value, preserving existing values for this header name.
    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;
}

/// Client-side view of the response status and headers.
pub trait ReadResponse {
    fn status(&self) -> StatusCode;

    /// Return an owned snapshot of the ordinary headers, excluding pseudo-headers.
    /// Use [`HeaderMap::get_all`] to read multiple values such as `Set-Cookie`.
    /// Changing the returned map does not change the response.
    fn headers(&self) -> HeaderMap;
}

#[async_trait]
pub trait ReadStream: Sized {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Stop receiving, discard buffered bytes, and wake pending operations.
    async fn stop(self);
}

pub trait ReadBody {
    fn body(&self) -> Bytes;
}

impl<B: Default> WriteRequest for Message<RequestHead, B> {
    fn new(url: &str, method: Method) -> Result<Self> {
        Ok(Self::from_parts(
            RequestHead::new(url, method)?,
            B::default(),
        ))
    }

    fn header(self, key: HeaderName, value: HeaderValue) -> Self {
        self.head.lock().unwrap().headers.insert(key, value);
        self
    }
}

impl ReadRequest for RequestHead {
    fn protocol(&self) -> Option<crate::Protocol> {
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
    fn protocol(&self) -> Option<crate::Protocol> {
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

impl<H> WriteBody for Message<H, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        *self.body.lock().unwrap() = body;
        self
    }
}

impl<H> ReadBody for Message<H, Bytes> {
    fn body(&self) -> Bytes {
        self.body.lock().unwrap().clone()
    }
}

// Standard I/O operates on body bytes; protocol framing lives in common::body.
impl<H: Unpin, B: AsyncRead + Unpin> AsyncRead for Message<H, B> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.body.lock().unwrap()).poll_read(cx, buf)
    }
}

impl<H: Unpin, B: AsyncWrite + Unpin> AsyncWrite for Message<H, B> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.body.lock().unwrap()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.body.lock().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.body.lock().unwrap()).poll_shutdown(cx)
    }
}

impl<H: Clone, B> Message<H, B> {
    pub(crate) fn with_body<T>(&self, body: T) -> Message<H, T> {
        Message {
            head: Arc::new(Mutex::new(self.head.lock().unwrap().clone())),
            body: Arc::new(Mutex::new(body)),
        }
    }
}

impl<H, B: Clone, IO> Message<H, Body<B, IO>> {
    pub(crate) fn body(&self) -> Body<B, IO> {
        Body::new(self.body.lock().unwrap().storage.clone())
    }

    pub(crate) fn into_body(self) -> Body<B, IO> {
        match Arc::try_unwrap(self.body) {
            Ok(body) => body.into_inner().unwrap(),
            Err(body) => Body::new(body.lock().unwrap().storage.clone()),
        }
    }
}

impl<H, IO> Message<H, Body<crate::ArcWndBuf, IO>> {
    pub(crate) fn body_stream(&self) -> crate::ArcWndBuf {
        self.body.lock().unwrap().storage.clone()
    }
}

#[async_trait]
impl<H: Send> ReadStream for Message<H, Body<crate::ArcWndBuf, Read>> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.body().read(buf).await
    }

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut body = self.body();
        let mut count = 0;
        while count < buf.len() {
            let n = body.read(&mut buf[count..]).await?;
            if n == 0 {
                break;
            }
            count += n;
        }
        Ok(count)
    }

    async fn stop(self) {
        self.into_body().stop().await;
    }
}

#[async_trait]
impl<H: Send> WriteStream for Message<H, Body<crate::ArcWndBuf, Write>> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        self.body().write(chunk).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.body().finish().await
    }

    async fn reset(self) -> Result<()> {
        self.into_body().reset().await
    }
}

impl<H, IO> ReadBody for Message<H, Body<Bytes, IO>> {
    fn body(&self) -> Bytes {
        self.body.lock().unwrap().storage.clone()
    }
}

impl<H> WriteBody for Message<H, Body<Bytes, Write>> {
    fn set_body(&mut self, bytes: Bytes) -> &mut Self {
        self.body.lock().unwrap().storage = bytes;
        self
    }
}
