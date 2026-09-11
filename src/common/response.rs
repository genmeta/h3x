use std::marker::PhantomData;

use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;

use super::{
    Read, Write,
    message::{
        ArcMessage, ReadBody, ReadResponse, ReadStream, WriteBody, WriteResponse, WriteStream,
    },
};
use crate::{ArcWndBuf, Result};

pub struct Response<IO, B = Bytes> {
    pub(crate) message: ArcMessage<B>,
    _io: PhantomData<IO>,
}

impl<B: Default> Default for Response<Write, B> {
    fn default() -> Self {
        Self {
            message: ArcMessage::default(),
            _io: PhantomData,
        }
    }
}

/// Cloning shares the message and body stream.
impl Clone for Response<Write, ArcWndBuf> {
    fn clone(&self) -> Self {
        self.message.clone().into()
    }
}

impl<IO, B> From<ArcMessage<B>> for Response<IO, B> {
    fn from(message: ArcMessage<B>) -> Self {
        Self {
            message,
            _io: PhantomData,
        }
    }
}

impl ReadBody for Response<Read, Bytes> {
    fn body(&self) -> Bytes {
        ReadBody::body(&*self.message.0.lock().unwrap())
    }
}

impl WriteBody for Response<Write, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.message.0.lock().unwrap().set_body(body);
        self
    }
}

impl Response<Write, Bytes> {
    pub fn streaming(self, capacity: usize) -> Response<Write, ArcWndBuf> {
        self.message.with_body(ArcWndBuf::new(capacity)).into()
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
        self.message.0.lock().unwrap().status()
    }
}

impl<B> WriteResponse for Response<Write, B> {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.message.0.lock().unwrap().set_status(status);
        self
    }
}
