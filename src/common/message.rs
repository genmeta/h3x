use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, Uri};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

#[derive(Default, Clone)]
pub(crate) struct ArcMessage<B>(pub(crate) Arc<Mutex<Message<B>>>);
/// Shared client/server message. `B` is buffered bytes or a body stream.
/// Construction does not start network or body work.
#[derive(Debug, Default)]
pub(crate) struct Message<B> {
    headers: HashMap<String, HeaderValue>,
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
            headers: HashMap::new(),
            body,
        };
        message.headers.insert(
            ":method".into(),
            HeaderValue::from_str(method.as_str()).unwrap(),
        );
        message.headers.insert(
            ":authority".into(),
            HeaderValue::from_str(uri.authority().unwrap().as_str()).unwrap(),
        );
        if method != Method::CONNECT {
            message.headers.insert(
                ":scheme".into(),
                HeaderValue::from_str(uri.scheme_str().unwrap()).unwrap(),
            );
            message.headers.insert(
                ":path".into(),
                HeaderValue::from_str(uri.path_and_query().map_or("/", |value| value.as_str()))
                    .unwrap(),
            );
        }
        Ok(message)
    }

    pub(crate) fn headers(&self) -> impl Iterator<Item = (&str, &HeaderValue)> {
        self.headers
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    pub fn with_body<T>(self, body: T) -> Message<T> {
        Message {
            headers: self.headers,
            body,
        }
    }

    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.headers.insert(name.as_str().to_owned(), value);
        self
    }

    pub(crate) fn set_pseudo_header(&mut self, name: &'static str, value: HeaderValue) {
        debug_assert!(name.starts_with(':'));
        self.headers.insert(name.into(), value);
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

    fn header(self, key: HeaderName, value: HeaderValue) -> Self;
}

pub trait WriteBody {
    fn set_body(&mut self, body: Bytes) -> &mut Self;
}

#[async_trait]
pub trait WriteStream: Sized {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize>;

    async fn finish(&mut self) -> Result<()>;

    /// Release the body; transport cancellation requires a body that cancels on drop.
    async fn reset(self) -> Result<()>;
}

/// Server-side view of request metadata.
pub trait ReadRequest: Sized {
    fn method(&self) -> Method;

    fn authority(&self) -> String;

    fn path(&self) -> String;

    fn scheme(&self) -> String;
}

/// Server-side response status.
pub trait WriteResponse {
    fn set_status(&mut self, status: StatusCode) -> &mut Self;
}

/// Client-side view of the response status.
pub trait ReadResponse {
    fn status(&self) -> StatusCode;
}

#[async_trait]
pub trait ReadStream: Sized {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Release the body; transport cancellation requires a body that cancels on drop.
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
            self.headers
                .get(":method")
                .expect("missing :method")
                .as_bytes(),
        )
        .expect("invalid :method")
    }
    fn authority(&self) -> String {
        self.headers
            .get(":authority")
            .map_or("", |value| value.to_str().expect("invalid :authority"))
            .to_owned()
    }
    fn path(&self) -> String {
        self.headers
            .get(":path")
            .map_or("", |value| value.to_str().expect("invalid :path"))
            .to_owned()
    }
    fn scheme(&self) -> String {
        self.headers
            .get(":scheme")
            .map_or("", |value| value.to_str().expect("invalid :scheme"))
            .to_owned()
    }
}

impl<B> WriteResponse for Message<B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.headers.insert(
            ":status".into(),
            HeaderValue::from_str(status.as_str()).unwrap(),
        );
        self
    }
}

impl<B> ReadResponse for Message<B> {
    fn status(&self) -> StatusCode {
        StatusCode::from_bytes(
            self.headers
                .get(":status")
                .expect("missing :status")
                .as_bytes(),
        )
        .expect("invalid :status")
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

#[async_trait]
impl<B: AsyncWrite + Unpin + Send> WriteStream for Message<B> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        Ok(self.body.write(chunk.as_ref()).await?)
    }

    async fn finish(&mut self) -> Result<()> {
        Ok(self.body.shutdown().await?)
    }

    // Releasing the body delegates cancellation to its Drop implementation.
    async fn reset(self) -> Result<()> {
        drop(self);
        Ok(())
    }
}

#[async_trait]
impl<B: AsyncRead + Unpin + Send> ReadStream for Message<B> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.body.read(buf).await?)
    }

    /// Read until the buffer is full or EOF; a short buffer leaves data unread.
    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut count = 0;
        while count < buf.len() {
            let read = self.body.read(&mut buf[count..]).await?;
            if read == 0 {
                break;
            }
            count += read;
        }
        Ok(count)
    }

    // Releasing the body delegates cancellation to its Drop implementation.
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
        ArcMessage::from(Message {
            headers: self.0.lock().unwrap().headers.clone(),
            body,
        })
    }
}

impl ArcMessage<crate::ArcWndBuf> {
    fn stream(&self) -> Message<crate::ArcWndBuf> {
        Message {
            headers: HashMap::new(),
            body: self.0.lock().unwrap().body.clone(),
        }
    }
}

#[async_trait]
impl ReadStream for ArcMessage<crate::ArcWndBuf> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream().read(buf).await
    }

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream().read_all(buf).await
    }

    async fn stop(self) {
        self.0
            .lock()
            .unwrap()
            .body
            .set_error(Error::H3_REQUEST_CANCELLED);
    }
}

#[async_trait]
impl WriteStream for ArcMessage<crate::ArcWndBuf> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        self.stream().write(chunk).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.stream().finish().await
    }

    async fn reset(self) -> Result<()> {
        self.0
            .lock()
            .unwrap()
            .body
            .set_error(Error::H3_REQUEST_CANCELLED);
        Ok(())
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
        assert_eq!(message.headers[":method"], "POST");
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
        assert_eq!(message.headers[":status"], "201");
        assert_eq!(ReadBody::body(&message), Bytes::from_static(b"hello"));
        assert_eq!(ReadBody::body(&message), Bytes::from_static(b"hello"));
        let mut buf = [0; 3];
        let mut stream = Message {
            headers: message.headers,
            body: &b"world"[..],
        };
        assert_eq!(stream.status(), StatusCode::CREATED);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf, b"wor");
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 2);
        assert_eq!(stream.read_all(&mut buf).await.unwrap(), 0);
        stream.stop().await;
        let mut stream = Message::<Vec<u8>>::default();
        assert_eq!(stream.write(b"hello").await.unwrap(), 5);
        stream.finish().await.unwrap();
        assert_eq!(stream.into_body(), b"hello");
        Message::<Vec<u8>>::default().reset().await.unwrap();
        assert!(Message::<Bytes>::get("/relative").is_err());
        assert!(Message::<Bytes>::get("https://bad host/").is_err());
        for url in ["example.com:443", "https://example.com:443/"] {
            let connect = Message::<Bytes>::connect(url).unwrap();
            assert_eq!(connect.authority(), "example.com:443");
            assert!(!connect.headers.contains_key(":scheme"));
            assert!(!connect.headers.contains_key(":path"));
        }
    }
}
