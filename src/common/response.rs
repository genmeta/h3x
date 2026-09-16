use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use super::{
    Read, Write,
    body::Body,
    headers::ResponseHead,
    message::{
        ArcMessage, ReadBody, ReadResponse, ReadStream, WriteBody, WriteResponse, WriteStream,
    },
};
use crate::{ArcWndBuf, Result};

pub struct Response<IO, B = Bytes> {
    pub(crate) message: ArcMessage<ResponseHead, Body<B, IO>>,
}

impl<B: Default> Default for Response<Write, B> {
    fn default() -> Self {
        Self {
            message: ArcMessage::default(),
        }
    }
}

/// Cloning shares metadata and body storage.
impl Clone for Response<Write, ArcWndBuf> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
        }
    }
}

impl<IO, B> From<ArcMessage<ResponseHead, Body<B, IO>>> for Response<IO, B> {
    fn from(message: ArcMessage<ResponseHead, Body<B, IO>>) -> Self {
        Self { message }
    }
}

impl ReadBody for Response<Read, Bytes> {
    fn body(&self) -> Bytes {
        self.message.body.lock().unwrap().storage.clone()
    }
}

impl WriteBody for Response<Write, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.message.body.lock().unwrap().storage = body;
        self
    }
}

impl Response<Write, Bytes> {
    pub fn streaming(self, capacity: usize) -> Response<Write, ArcWndBuf> {
        self.message
            .with_body(Body::<ArcWndBuf, Write>::with_capacity(capacity))
            .into()
    }
}

#[async_trait]
impl ReadStream for Response<Read, ArcWndBuf> {
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
impl WriteStream for Response<Write, ArcWndBuf> {
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

impl<B> ReadResponse for Response<Read, B> {
    fn status(&self) -> StatusCode {
        ReadResponse::status(&*self.message.head.lock().unwrap())
    }

    fn headers(&self) -> HeaderMap {
        ReadResponse::headers(&*self.message.head.lock().unwrap())
    }
}

impl<B> WriteResponse for Response<Write, B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.message.head.lock().unwrap().set_status(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.message.head.lock().unwrap().set_header(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.message.head.lock().unwrap().append_header(name, value);
        self
    }
}

impl<IO, B: Clone> Response<IO, B> {
    /// Transfer application ownership to a directional body handle.
    pub fn into_body(self) -> super::body::Body<B, IO> {
        self.message.into_body()
    }
}

impl<B: Clone> Response<Write, B> {
    /// Retain a body producer independently of the message being sent.
    pub fn body(&self) -> super::body::Body<B, Write> {
        self.message.body()
    }
}

impl Response<Write, Bytes> {
    /// Attach an application body, retaining this message's headers.
    pub fn with_body<C>(self, body: super::body::Body<C, Write>) -> Response<Write, C> {
        self.message.with_body(body).into()
    }
}
