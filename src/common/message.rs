use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Read, Write, body::Body};
use crate::{Error, Result, protocol::qpack::Field};

#[derive(Default)]
pub(crate) struct ArcMessage<B>(pub(crate) Arc<Mutex<Message<B>>>);

impl<B> Clone for ArcMessage<B> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// Shared client/server message. Application messages contain a directional Body.
/// Construction does not start network or body work.
#[derive(Debug, Default)]
pub(crate) struct Message<B> {
    headers: HeaderMap,
    pseudo_headers: HashMap<&'static str, HeaderValue>,
    body: B,
}

impl<B> Message<B> {
    pub(crate) fn new_with_body(url: &str, method: Method, body: B) -> Result<Self> {
        let uri: Uri = url.parse().map_err(|_| Error::H3_MESSAGE_ERROR)?;
        // CONNECT also accepts an authority-form target such as example.com:443.
        let authority_form = method == Method::CONNECT
            && uri.scheme().is_none()
            && uri.authority().is_some()
            && uri.path_and_query().is_none();
        if !authority_form && (uri.scheme().is_none() || uri.authority().is_none()) {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mut message = Self {
            headers: HeaderMap::new(),
            pseudo_headers: HashMap::new(),
            body,
        };
        message.set_pseudo_header(":method", HeaderValue::from_str(method.as_str()).unwrap());
        message.set_pseudo_header(
            ":authority",
            HeaderValue::from_str(uri.authority().unwrap().as_str()).unwrap(),
        );
        if method != Method::CONNECT {
            message.set_pseudo_header(
                ":scheme",
                HeaderValue::from_str(uri.scheme_str().unwrap()).unwrap(),
            );
            message.set_pseudo_header(
                ":path",
                HeaderValue::from_str(uri.path_and_query().map_or("/", |value| value.as_str()))
                    .unwrap(),
            );
        }
        Ok(message)
    }

    pub(crate) fn fields(&self) -> Vec<Field> {
        self.pseudo_headers
            .iter()
            .map(|(name, value)| (*name, value))
            .chain(
                self.headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value)),
            )
            .map(|(name, value)| Field {
                name: Bytes::copy_from_slice(name.as_bytes()),
                value: Bytes::copy_from_slice(value.as_bytes()),
                never_index: value.is_sensitive(),
            })
            .collect()
    }

    pub fn with_body<T>(self, body: T) -> Message<T> {
        Message {
            headers: self.headers,
            pseudo_headers: self.pseudo_headers,
            body,
        }
    }

    /// Replace all existing values for this header name.
    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.insert(name, value);
        self
    }

    /// Append a value, preserving existing values for this header name.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.append(name, value);
        self
    }

    pub(crate) fn set_pseudo_header(&mut self, name: &'static str, value: HeaderValue) {
        debug_assert!(name.starts_with(':'));
        self.pseudo_headers.insert(name, value);
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

impl<B: Default> WriteRequest for Message<B> {
    fn new(url: &str, method: Method) -> Result<Self> {
        Self::new_with_body(url, method, B::default())
    }

    fn header(mut self, key: HeaderName, value: HeaderValue) -> Self {
        Message::set_header(&mut self, key, value);
        self
    }
}

impl<B> ReadRequest for Message<B> {
    fn method(&self) -> Method {
        Method::from_bytes(
            self.pseudo_headers
                .get(":method")
                .expect("missing :method")
                .as_bytes(),
        )
        .expect("invalid :method")
    }

    fn authority(&self) -> String {
        self.pseudo_headers
            .get(":authority")
            .map_or("", |value| value.to_str().expect("invalid :authority"))
            .to_owned()
    }

    fn path(&self) -> String {
        self.pseudo_headers
            .get(":path")
            .map_or("", |value| value.to_str().expect("invalid :path"))
            .to_owned()
    }

    fn scheme(&self) -> String {
        self.pseudo_headers
            .get(":scheme")
            .map_or("", |value| value.to_str().expect("invalid :scheme"))
            .to_owned()
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl<B> WriteResponse for Message<B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.set_pseudo_header(":status", HeaderValue::from_str(status.as_str()).unwrap());
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        Message::set_header(self, name, value)
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        Message::append_header(self, name, value)
    }
}

impl<B> ReadResponse for Message<B> {
    fn status(&self) -> StatusCode {
        StatusCode::from_bytes(
            self.pseudo_headers
                .get(":status")
                .expect("missing :status")
                .as_bytes(),
        )
        .expect("invalid :status")
    }

    fn headers(&self) -> HeaderMap {
        self.headers.clone()
    }
}

impl WriteBody for Message<Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.body = body;
        self
    }
}

impl ReadBody for Message<Bytes> {
    fn body(&self) -> Bytes {
        self.body.clone()
    }
}

// Standard I/O operates on body bytes; protocol framing lives in common::body.
impl<B: AsyncRead + Unpin> AsyncRead for Message<B> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().body).poll_read(cx, buf)
    }
}

impl<B: AsyncWrite + Unpin> AsyncWrite for Message<B> {
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
impl<B: AsyncWrite + Unpin + Send> WriteStream for Message<B> {
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
impl<B: AsyncRead + Unpin + Send> ReadStream for Message<B> {
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

impl<B> From<Message<B>> for ArcMessage<B> {
    fn from(message: Message<B>) -> Self {
        Self(Arc::new(Mutex::new(message)))
    }
}

impl<B> ArcMessage<B> {
    pub(crate) fn with_body<T>(&self, body: T) -> ArcMessage<T> {
        let message = self.0.lock().unwrap();
        ArcMessage::from(Message {
            headers: message.headers.clone(),
            pseudo_headers: message.pseudo_headers.clone(),
            body,
        })
    }
}

impl<B: Clone, IO> ArcMessage<Body<B, IO>> {
    pub(crate) fn body_handle(&self) -> Body<B, IO> {
        Body::from_storage(self.0.lock().unwrap().body.storage.clone())
    }

    pub(crate) fn into_body(self) -> Body<B, IO> {
        match Arc::try_unwrap(self.0) {
            Ok(message) => message.into_inner().unwrap().body,
            Err(message) => Body::from_storage(message.lock().unwrap().body.storage.clone()),
        }
    }

    #[cfg(test)]
    pub(crate) fn test_direction<D>(&self) -> ArcMessage<Body<B, D>> {
        let message = self.0.lock().unwrap();
        ArcMessage::from(Message {
            headers: message.headers.clone(),
            pseudo_headers: message.pseudo_headers.clone(),
            body: Body::from_storage(message.body.storage.clone()),
        })
    }
}

#[async_trait]
impl ReadStream for ArcMessage<Body<crate::ArcWndBuf, Read>> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.body_handle().read(buf).await
    }

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut body = self.body_handle();
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
impl WriteStream for ArcMessage<Body<crate::ArcWndBuf, Write>> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        self.body_handle().write(chunk).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.body_handle().finish().await
    }

    async fn reset(self) -> Result<()> {
        self.into_body().reset().await
    }
}

impl<IO> Message<Body<crate::ArcWndBuf, IO>> {
    pub(crate) fn body_stream(&self) -> crate::ArcWndBuf {
        self.body.storage.clone()
    }
}

impl<IO> ReadBody for Message<Body<Bytes, IO>> {
    fn body(&self) -> Bytes {
        self.body.storage.clone()
    }
}

impl WriteBody for Message<Body<Bytes, Write>> {
    fn set_body(&mut self, bytes: Bytes) -> &mut Self {
        self.body.storage = bytes;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl<B> Message<B> {
        pub(crate) fn header(&self, name: &HeaderName) -> Option<HeaderValue> {
            self.headers.get(name.as_str()).cloned()
        }

        pub(crate) fn into_body(self) -> B {
            self.body
        }
    }

    #[tokio::test]
    async fn message_metadata_and_body_modes() {
        let mut message = Message::<Bytes>::post("https://example.com/a?q=1").unwrap();
        assert_eq!(message.pseudo_headers[":method"], "POST");
        assert_eq!(message.method(), Method::POST);
        assert_eq!(message.authority(), "example.com");
        assert_eq!(message.scheme(), "https");
        assert_eq!(message.path(), "/a?q=1");
        let name = http::header::CONTENT_TYPE;
        message.set_header(name.clone(), HeaderValue::from_static("text/plain"));
        assert_eq!(Message::header(&message, &name).unwrap(), "text/plain");
        message =
            WriteRequest::header(message, name.clone(), HeaderValue::from_static("text/html"));
        assert_eq!(Message::header(&message, &name).unwrap(), "text/html");
        message
            .set_status(StatusCode::CREATED)
            .set_body(Bytes::from_static(b"hello"));
        assert_eq!(message.pseudo_headers[":status"], "201");
        assert_eq!(ReadBody::body(&message), Bytes::from_static(b"hello"));
        assert_eq!(ReadBody::body(&message), Bytes::from_static(b"hello"));
        let mut buf = [0; 3];
        let mut stream = message.with_body(&b"world"[..]);
        assert_eq!(stream.status(), StatusCode::CREATED);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf, b"wor");
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 2);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 0);
        stream.stop().await;
        let mut stream = Message::<Vec<u8>>::default();
        assert_eq!(WriteStream::write(&mut stream, b"hello").await.unwrap(), 5);
        stream.finish().await.unwrap();
        assert_eq!(stream.into_body(), b"hello");
        Message::<Vec<u8>>::default().reset().await.unwrap();
        assert!(Message::<Bytes>::get("/relative").is_err());
        assert!(Message::<Bytes>::get("https://bad host/").is_err());
        for url in ["example.com:443", "https://example.com:443/"] {
            let connect = Message::<Bytes>::connect(url).unwrap();
            assert_eq!(connect.authority(), "example.com:443");
            assert!(!connect.pseudo_headers.contains_key(":scheme"));
            assert!(!connect.pseudo_headers.contains_key(":path"));
        }
    }

    #[test]
    fn header_values_survive_body_conversions_and_can_be_replaced() {
        let mut message = Message::<Bytes>::default();
        message.set_status(StatusCode::OK);
        let name = http::header::SET_COOKIE;
        let mut sensitive = HeaderValue::from_static("b=2");
        sensitive.set_sensitive(true);
        message
            .set_header(name.clone(), HeaderValue::from_static("a=1"))
            .append_header(name.clone(), sensitive.clone());

        let message = message.with_body(Vec::<u8>::new());
        assert_eq!(message.headers.get_all(&name).iter().count(), 2);
        let original = ArcMessage::from(message);
        let copied = original.with_body(Bytes::new());
        let mut message = copied.0.lock().unwrap();
        assert_eq!(message.status(), StatusCode::OK);
        assert_eq!(
            message.headers.get_all(&name).iter().collect::<Vec<_>>(),
            [&HeaderValue::from_static("a=1"), &sensitive]
        );
        let fields = message.fields();
        assert_eq!(fields[0].name, ":status");
        assert_eq!(fields[1].name, "set-cookie");
        assert_eq!(fields[2].name, "set-cookie");
        assert!(!fields[1].never_index);
        assert!(fields[2].never_index);

        message.set_header(name.clone(), HeaderValue::from_static("c=3"));
        assert_eq!(message.headers.get_all(&name).iter().count(), 1);
        assert_eq!(message.headers[&name], "c=3");
        assert_eq!(
            original
                .0
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
