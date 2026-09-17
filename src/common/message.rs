use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{
    Read, Write,
    body::Body,
    headers::{RequestHead, ResponseHead},
};
use crate::Result;

#[derive(Default)]
/// Metadata and body are shared independently so either can be accessed without
/// taking a lock for the other.
pub(crate) struct ArcMessage<H, B> {
    pub(crate) head: Arc<Mutex<H>>,
    pub(crate) body: Arc<Mutex<B>>,
}

impl<H, B> Clone for ArcMessage<H, B> {
    fn clone(&self) -> Self {
        Self {
            head: self.head.clone(),
            body: self.body.clone(),
        }
    }
}

/// Client/server message parts before they are placed in independent shared slots.
/// Construction does not start network or body work.
/// 直接用 ArcMutex 包起来
#[derive(Debug, Default)]
pub(crate) struct Message<H, B> {
    pub(crate) head: H,
    body: B,
}

impl<H, B> Message<H, B> {
    pub(crate) fn from_parts(head: H, body: B) -> Self {
        Self { head, body }
    }

    #[cfg(test)]
    pub fn with_body<T>(self, body: T) -> Message<H, T> {
        Message {
            head: self.head,
            body,
        }
    }
}

#[cfg(test)]
impl<B> Message<RequestHead, B> {
    /// Replace all existing values for this header name.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.headers.insert(name, value);
        self
    }
}

#[cfg(test)]
impl<B> Message<ResponseHead, B> {
    /// Replace all existing values for this header name.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.headers.insert(name, value);
        self
    }

    /// Append a value, preserving existing values for this header name.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.headers.append(name, value);
        self
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

    fn header(mut self, key: HeaderName, value: HeaderValue) -> Self {
        self.head.headers.insert(key, value);
        self
    }
}

impl ReadRequest for RequestHead {
    fn protocol(&self) -> Option<crate::Protocol> {
        self.extensions.get().cloned()
    }
    fn method(&self) -> Method {
        self.method.clone()
    }

    fn authority(&self) -> String {
        self.uri
            .authority()
            .map_or("", |value| value.as_str())
            .to_owned()
    }

    fn path(&self) -> String {
        self.uri
            .path_and_query()
            .map_or("", |value| value.as_str())
            .to_owned()
    }

    fn scheme(&self) -> String {
        self.uri.scheme_str().unwrap_or_default().to_owned()
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl<B> ReadRequest for Message<RequestHead, B> {
    fn protocol(&self) -> Option<crate::Protocol> {
        self.head.protocol()
    }
    fn method(&self) -> Method {
        self.head.method()
    }

    fn authority(&self) -> String {
        self.head.authority()
    }

    fn path(&self) -> String {
        self.head.path()
    }

    fn scheme(&self) -> String {
        self.head.scheme()
    }

    fn headers(&self) -> HeaderMap {
        ReadRequest::headers(&self.head)
    }
}

impl WriteResponse for ResponseHead {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.status = Some(status);
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
        self.status.expect("missing :status")
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl<B> WriteResponse for Message<ResponseHead, B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.head.set_status(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.set_header(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.append_header(name, value);
        self
    }
}

impl<B> ReadResponse for Message<ResponseHead, B> {
    fn status(&self) -> StatusCode {
        ReadResponse::status(&self.head)
    }

    fn headers(&self) -> HeaderMap {
        ReadResponse::headers(&self.head)
    }
}

impl<H> WriteBody for Message<H, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.body = body;
        self
    }
}

impl<H> ReadBody for Message<H, Bytes> {
    fn body(&self) -> Bytes {
        self.body.clone()
    }
}

// Standard I/O operates on body bytes; protocol framing lives in common::body.
impl<H: Unpin, B: AsyncRead + Unpin> AsyncRead for Message<H, B> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().body).poll_read(cx, buf)
    }
}

impl<H: Unpin, B: AsyncWrite + Unpin> AsyncWrite for Message<H, B> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().body).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().body).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().body).poll_shutdown(cx)
    }
}

#[async_trait]
impl<H: Unpin + Send, B: AsyncWrite + Unpin + Send> WriteStream for Message<H, B> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        Ok(AsyncWriteExt::write(self, chunk.as_ref()).await?)
    }

    async fn finish(&mut self) -> Result<()> {
        Ok(AsyncWriteExt::shutdown(self).await?)
    }

    async fn reset(self) -> Result<()> {
        drop(self);
        Ok(())
    }
}

#[async_trait]
impl<H: Unpin + Send, B: AsyncRead + Unpin + Send> ReadStream for Message<H, B> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(AsyncReadExt::read(self, buf).await?)
    }

    /// Read until the buffer is full or EOF; a short buffer leaves data unread.
    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut count = 0;
        while count < buf.len() {
            let read = AsyncReadExt::read(self, &mut buf[count..]).await?;
            if read == 0 {
                break;
            }
            count += read;
        }
        Ok(count)
    }

    async fn stop(self) {
        drop(self);
    }
}

impl<H, B> From<Message<H, B>> for ArcMessage<H, B> {
    fn from(message: Message<H, B>) -> Self {
        Self {
            head: Arc::new(Mutex::new(message.head)),
            body: Arc::new(Mutex::new(message.body)),
        }
    }
}

impl<H: Clone, B> ArcMessage<H, B> {
    pub(crate) fn with_body<T>(&self, body: T) -> ArcMessage<H, T> {
        ArcMessage {
            head: Arc::new(Mutex::new(self.head.lock().unwrap().clone())),
            body: Arc::new(Mutex::new(body)),
        }
    }
}

impl<H, B: Clone, IO> ArcMessage<H, Body<B, IO>> {
    pub(crate) fn body(&self) -> Body<B, IO> {
        Body::new(self.body.lock().unwrap().storage.clone())
    }

    pub(crate) fn into_body(self) -> Body<B, IO> {
        match Arc::try_unwrap(self.body) {
            Ok(body) => body.into_inner().unwrap(),
            Err(body) => Body::new(body.lock().unwrap().storage.clone()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_direction<D>(&self) -> ArcMessage<H, Body<B, D>>
    where
        H: Clone,
    {
        ArcMessage {
            head: Arc::new(Mutex::new(self.head.lock().unwrap().clone())),
            body: Arc::new(Mutex::new(Body::new(
                self.body.lock().unwrap().storage.clone(),
            ))),
        }
    }
}

impl<H, IO> ArcMessage<H, Body<crate::ArcWndBuf, IO>> {
    pub(crate) fn body_stream(&self) -> crate::ArcWndBuf {
        self.body.lock().unwrap().storage.clone()
    }
}

#[async_trait]
impl<H: Send> ReadStream for ArcMessage<H, Body<crate::ArcWndBuf, Read>> {
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
impl<H: Send> WriteStream for ArcMessage<H, Body<crate::ArcWndBuf, Write>> {
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
        self.body.storage.clone()
    }
}

impl<H> WriteBody for Message<H, Body<Bytes, Write>> {
    fn set_body(&mut self, bytes: Bytes) -> &mut Self {
        self.body.storage = bytes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::headers::Write as _;

    impl<H, B> Message<H, B> {
        pub(crate) fn into_body(self) -> B {
            self.body
        }
    }

    #[tokio::test]
    async fn message_metadata_and_body_modes() {
        let mut request = Message::<RequestHead, Bytes>::post("https://example.com/a?q=1").unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.authority(), "example.com");
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.path(), "/a?q=1");
        let name = http::header::CONTENT_TYPE;
        request.set_header(name.clone(), HeaderValue::from_static("text/plain"));
        assert_eq!(request.head.headers[&name], "text/plain");
        request =
            WriteRequest::header(request, name.clone(), HeaderValue::from_static("text/html"));
        assert_eq!(request.head.headers[&name], "text/html");

        let mut response = Message::<ResponseHead, Bytes>::default();
        response
            .set_status(StatusCode::CREATED)
            .set_body(Bytes::from_static(b"hello"));
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(ReadBody::body(&response), Bytes::from_static(b"hello"));
        let mut buf = [0; 3];
        let mut stream = response.with_body(&b"world"[..]);
        assert_eq!(stream.status(), StatusCode::CREATED);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf, b"wor");
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 2);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 0);
        stream.stop().await;
        let mut stream = Message::<ResponseHead, Vec<u8>>::default();
        assert_eq!(WriteStream::write(&mut stream, b"hello").await.unwrap(), 5);
        stream.finish().await.unwrap();
        assert_eq!(stream.into_body(), b"hello");
        Message::<ResponseHead, Vec<u8>>::default()
            .reset()
            .await
            .unwrap();
        assert!(Message::<RequestHead, Bytes>::get("/relative").is_err());
        assert!(Message::<RequestHead, Bytes>::get("https://bad host/").is_err());
        for url in ["example.com:443", "https://example.com:443/"] {
            let connect = Message::<RequestHead, Bytes>::connect(url).unwrap();
            assert_eq!(connect.authority(), "example.com:443");
            assert_eq!(connect.scheme(), "");
            assert_eq!(connect.path(), "");
        }
    }

    #[test]
    fn header_values_survive_body_conversions_and_can_be_replaced() {
        let mut message = Message::<ResponseHead, Bytes>::default();
        message.set_status(StatusCode::OK);
        let name = http::header::SET_COOKIE;
        let mut sensitive = HeaderValue::from_static("b=2");
        sensitive.set_sensitive(true);
        message
            .set_header(name.clone(), HeaderValue::from_static("a=1"))
            .append_header(name.clone(), sensitive.clone());

        let message = message.with_body(Vec::<u8>::new());
        assert_eq!(message.head.headers.get_all(&name).iter().count(), 2);
        let original = ArcMessage::from(message);
        let copied = original.with_body(Bytes::new());
        let mut head = copied.head.lock().unwrap();
        assert_eq!(ReadResponse::status(&*head), StatusCode::OK);
        assert_eq!(
            head.headers.get_all(&name).iter().collect::<Vec<_>>(),
            [&HeaderValue::from_static("a=1"), &sensitive]
        );
        let mut fields = Vec::new();
        fields.put_response(&head).unwrap();
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[1].name, "set-cookie");
        assert_eq!(fields[2].name, "set-cookie");
        assert!(!fields[1].never_index);
        assert!(fields[2].never_index);

        head.set_header(name.clone(), HeaderValue::from_static("c=3"));
        assert_eq!(head.headers.get_all(&name).iter().count(), 1);
        assert_eq!(head.headers[&name], "c=3");
        assert_eq!(
            original
                .head
                .lock()
                .unwrap()
                .headers
                .get_all(&name)
                .iter()
                .count(),
            2
        );
    }
}
