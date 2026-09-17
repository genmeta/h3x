use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};

use super::{
    Read, Write,
    body::Body,
    head::RequestHead,
    message::{Message, ReadBody, ReadRequest, ReadStream, WriteBody, WriteRequest, WriteStream},
};
use crate::{ArcWndBuf, ErrorCode, Result};

impl RequestHead {
    pub(crate) fn new(url: &str, method: Method) -> Result<Self> {
        if url.contains('#') {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("URI fragments are forbidden"));
        }
        let mut uri: Uri = url.parse().map_err(|error| {
            ErrorCode::H3_MESSAGE_ERROR.reason(format!("invalid request URI: {error}"))
        })?;
        let websocket_scheme = if method == Method::CONNECT {
            match uri.scheme_str() {
                Some(scheme) if scheme.eq_ignore_ascii_case("ws") => Some(http::uri::Scheme::HTTP),
                Some(scheme) if scheme.eq_ignore_ascii_case("wss") => {
                    Some(http::uri::Scheme::HTTPS)
                }
                _ => None,
            }
        } else {
            None
        };
        let websocket = websocket_scheme.is_some();
        if let Some(scheme) = websocket_scheme {
            let mut parts = uri.into_parts();
            parts.scheme = Some(scheme);
            uri = Uri::from_parts(parts).map_err(|error| {
                ErrorCode::H3_MESSAGE_ERROR.reason(format!("invalid request URI: {error}"))
            })?;
        }
        // CONNECT also accepts an authority-form target such as example.com:443.
        let authority_form = method == Method::CONNECT
            && uri.scheme().is_none()
            && uri.authority().is_some()
            && uri.path_and_query().is_none();
        if !authority_form && (uri.scheme().is_none() || uri.authority().is_none()) {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("request URI requires scheme and authority")
            );
        }
        if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("userinfo is forbidden"));
        }
        let mut headers = HeaderMap::new();
        let protocol = if websocket {
            headers.insert("sec-websocket-version", HeaderValue::from_static("13"));
            Some(crate::Protocol::new("websocket")?)
        } else {
            None
        };
        let uri = if method == Method::CONNECT && !websocket {
            Uri::builder()
                .authority(uri.authority().unwrap().clone())
                .build()
                .map_err(|error| {
                    ErrorCode::H3_MESSAGE_ERROR
                        .reason(format!("invalid CONNECT authority: {error}"))
                })?
        } else {
            uri
        };
        Ok(Self::from_request_parts(method, uri, headers, protocol))
    }
}

const DEFAULT_STREAM_CAPACITY: usize = 16 * 1024;

pub struct Request<IO, B = Bytes> {
    pub(crate) message: Message<RequestHead, Body<B, IO>>,
}

/// Cloning shares metadata and body storage.
impl<B> Clone for Request<Write, B> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
        }
    }
}

impl<IO, B> From<Message<RequestHead, Body<B, IO>>> for Request<IO, B> {
    fn from(message: Message<RequestHead, Body<B, IO>>) -> Self {
        Self { message }
    }
}

impl ReadBody for Request<Read, Bytes> {
    fn body(&self) -> Bytes {
        self.message.body.lock().unwrap().storage.clone()
    }
}

impl WriteBody for Request<Write, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.message.body.lock().unwrap().storage = body;
        self
    }
}

impl Request<Write, ArcWndBuf> {
    /// Construct a streaming CONNECT request without opening a connection.
    /// `ws://` and `wss://` select WebSocket; authority-form targets use plain CONNECT.
    /// Retain `body()` and wait for successful response headers before writing.
    pub fn connect(url: &str) -> Result<Self> {
        Self::streaming(url, Method::CONNECT)
    }

    fn streaming(url: &str, method: Method) -> Result<Self> {
        let message = Message::from_parts(
            RequestHead::new(url, method)?,
            Body::<ArcWndBuf, Write>::with_capacity(DEFAULT_STREAM_CAPACITY),
        );
        Ok(message.into())
    }

    /// Body writes may precede sending; a full buffer waits for the send task to drain it.
    pub fn streaming_post(url: &str) -> Result<Self> {
        Self::streaming(url, Method::POST)
    }

    pub fn streaming_put(url: &str) -> Result<Self> {
        Self::streaming(url, Method::PUT)
    }

    pub fn streaming_patch(url: &str) -> Result<Self> {
        Self::streaming(url, Method::PATCH)
    }
}

impl<B> Request<Write, B> {
    /// Replace all existing values for this header name.
    pub fn header(self, key: HeaderName, value: HeaderValue) -> Self {
        self.message.head.lock().unwrap().headers.insert(key, value);
        self
    }
}

#[async_trait]
impl ReadStream for Request<Read, ArcWndBuf> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.message.read(buf).await
    }

    async fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.message.read_all(buf).await
    }

    async fn stop(self) {
        self.message.stop().await;
    }
}

#[async_trait]
impl WriteStream for Request<Write, ArcWndBuf> {
    async fn write<T: AsRef<[u8]> + Send>(&mut self, chunk: T) -> Result<usize> {
        self.message.write(chunk).await
    }

    async fn finish(&mut self) -> Result<()> {
        self.message.finish().await
    }

    async fn reset(self) -> Result<()> {
        self.message.reset().await
    }
}

impl<IO, B> ReadRequest for Request<IO, B> {
    fn protocol(&self) -> Option<crate::Protocol> {
        self.message
            .head
            .lock()
            .unwrap()
            .request_protocol()
            .cloned()
    }
    fn method(&self) -> Method {
        self.message.head.lock().unwrap().method()
    }

    fn authority(&self) -> String {
        self.message.head.lock().unwrap().authority()
    }

    fn path(&self) -> String {
        self.message.head.lock().unwrap().path()
    }

    fn scheme(&self) -> String {
        self.message.head.lock().unwrap().scheme()
    }

    fn headers(&self) -> HeaderMap {
        ReadRequest::headers(&*self.message.head.lock().unwrap())
    }
}

impl<B: Default> WriteRequest for Request<Write, B> {
    fn new(url: &str, method: Method) -> Result<Self> {
        Ok(Message::<RequestHead, Body<B, Write>>::new(url, method)?.into())
    }

    fn header(self, key: HeaderName, value: HeaderValue) -> Self {
        Request::header(self, key, value)
    }
}

impl<IO, B: Clone> Request<IO, B> {
    /// Transfer application ownership to a directional body handle.
    pub fn into_body(self) -> super::body::Body<B, IO> {
        self.message.into_body()
    }
}

impl<B: Clone> Request<Write, B> {
    /// Retain a body producer independently of the message being sent.
    pub fn body(&self) -> super::body::Body<B, Write> {
        self.message.body()
    }
}

impl Request<Write, Bytes> {
    /// Attach an application body, retaining this message's headers.
    pub fn with_body<C>(self, body: super::body::Body<C, Write>) -> Request<Write, C> {
        self.message.with_body(body).into()
    }
}
