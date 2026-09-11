use std::marker::PhantomData;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method};

use super::{
    Read, Write,
    message::{
        ArcMessage, Message, ReadBody, ReadRequest, ReadStream, WriteBody, WriteRequest,
        WriteStream,
    },
};
use crate::{ArcWndBuf, Result};

const DEFAULT_STREAM_CAPACITY: usize = 16 * 1024;

pub struct Request<IO, B = Bytes> {
    pub(crate) message: ArcMessage<B>,
    _io: PhantomData<IO>,
}

/// Cloning shares the message and body stream.
impl Clone for Request<Write, ArcWndBuf> {
    fn clone(&self) -> Self {
        self.message.clone().into()
    }
}

impl<IO, B> From<ArcMessage<B>> for Request<IO, B> {
    fn from(message: ArcMessage<B>) -> Self {
        Self {
            message,
            _io: PhantomData,
        }
    }
}

impl ReadBody for Request<Read, Bytes> {
    fn body(&self) -> Bytes {
        ReadBody::body(&*self.message.0.lock().unwrap())
    }
}

impl WriteBody for Request<Write, Bytes> {
    fn set_body(&mut self, body: Bytes) -> &mut Self {
        self.message.0.lock().unwrap().set_body(body);
        self
    }
}

impl Request<Write, Bytes> {
    pub fn body(mut self, body: Bytes) -> Self {
        self.set_body(body);
        self
    }
}

impl Request<Write, ArcWndBuf> {
    pub fn streaming_post(url: &str) -> Result<Self> {
        Ok(ArcMessage::from(Message::new_with_body(
            url,
            Method::POST,
            ArcWndBuf::new(DEFAULT_STREAM_CAPACITY),
        )?)
        .into())
    }

    pub fn streaming_put(url: &str) -> Result<Self> {
        Ok(ArcMessage::from(Message::new_with_body(
            url,
            Method::PUT,
            ArcWndBuf::new(DEFAULT_STREAM_CAPACITY),
        )?)
        .into())
    }

    pub fn streaming_patch(url: &str) -> Result<Self> {
        Ok(ArcMessage::from(Message::new_with_body(
            url,
            Method::PATCH,
            ArcWndBuf::new(DEFAULT_STREAM_CAPACITY),
        )?)
        .into())
    }

    pub fn streaming_connect(url: &str) -> Result<Self> {
        Ok(ArcMessage::from(Message::new_with_body(
            url,
            Method::CONNECT,
            ArcWndBuf::new(DEFAULT_STREAM_CAPACITY),
        )?)
        .into())
    }
}

impl<B> Request<Write, B> {
    pub fn header(self, key: HeaderName, value: HeaderValue) -> Self {
        self.message.0.lock().unwrap().set_header(key, value);
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

impl<B> ReadRequest for Request<Read, B> {
    fn method(&self) -> Method {
        self.message.0.lock().unwrap().method()
    }
    fn authority(&self) -> String {
        self.message.0.lock().unwrap().authority()
    }
    fn path(&self) -> String {
        self.message.0.lock().unwrap().path()
    }
    fn scheme(&self) -> String {
        self.message.0.lock().unwrap().scheme()
    }
}

impl<B: Default> WriteRequest for Request<Write, B> {
    fn new(url: &str, method: Method) -> Result<Self> {
        Ok(ArcMessage::from(Message::<B>::new(url, method)?).into())
    }

    fn header(self, key: HeaderName, value: HeaderValue) -> Self {
        Request::header(self, key, value)
    }
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};

    use super::*;
    use crate::{
        Error,
        common::{
            message::{ReadResponse, WriteResponse},
            response::Response,
        },
    };

    #[test]
    fn streaming_constructors() {
        use crate::client::Request;

        for (constructor, method) in [
            (
                Request::streaming_post as fn(&str) -> Result<Request<ArcWndBuf>>,
                Method::POST,
            ),
            (Request::streaming_put, Method::PUT),
            (Request::streaming_patch, Method::PATCH),
            (Request::streaming_connect, Method::CONNECT),
        ] {
            let request = constructor("https://example.com/upload?q=1").unwrap();
            let message = request.message.0.lock().unwrap();
            assert_eq!(message.method(), method);
            assert_eq!(message.authority(), "example.com");
            assert_eq!(
                message.path(),
                if method == Method::CONNECT {
                    ""
                } else {
                    "/upload?q=1"
                }
            );
            assert!(constructor("/relative").is_err());
            assert_eq!(
                constructor("example.com:443").is_ok(),
                method == Method::CONNECT
            );
        }
    }

    #[tokio::test]
    async fn shared_metadata_bodies_and_streams() {
        let mut writer = Request::<Write>::post("https://example.com/a?q=1")
            .unwrap()
            .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))
            .body(Bytes::from_static(b"hello"));
        let reader = Request::<Read>::from(writer.message.clone());
        assert_eq!(reader.method(), Method::POST);
        assert_eq!(reader.authority(), "example.com");
        assert_eq!(reader.path(), "/a?q=1");
        assert_eq!(reader.scheme(), "https");
        assert_eq!(reader.body(), Bytes::from_static(b"hello"));
        writer.set_body(Bytes::from_static(b"updated"));
        assert_eq!(reader.body(), Bytes::from_static(b"updated"));
        assert!(Request::<Write>::get("/relative").is_err());

        let message = ArcMessage::from(Message::<Bytes>::default());
        let mut response = Response::<Write>::from(message.clone());
        response
            .set_status(StatusCode::CREATED)
            .set_body(Bytes::from_static(b"ok"));
        let response = Response::<Read>::from(message);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.body(), Bytes::from_static(b"ok"));

        let request = crate::client::Request::streaming_post("https://example.com/")
            .unwrap()
            .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let mut writer = request.clone();
        assert!(std::sync::Arc::ptr_eq(
            &request.message.0,
            &writer.message.0
        ));
        let mut reader = Request::<Read, _>::from(request.message);
        assert_eq!(reader.method(), Method::POST);
        assert_eq!(reader.authority(), "example.com");
        assert_eq!(
            reader
                .message
                .0
                .lock()
                .unwrap()
                .header(&header::CONTENT_TYPE)
                .unwrap(),
            "text/plain"
        );
        let sentences = [
            "This is the first sentence. ",
            "Here is the second sentence. ",
            "This is the last sentence.",
        ];
        let payload = sentences.concat().into_bytes();
        let mut buf = vec![0; payload.len()];
        let ((), count) = tokio::join!(
            async {
                for sentence in sentences {
                    assert_eq!(writer.write(sentence).await.unwrap(), sentence.len());
                }
                writer.finish().await.unwrap();
            },
            reader.read_all(&mut buf)
        );
        assert_eq!(count.unwrap(), payload.len());
        assert_eq!(buf, payload);
        assert_eq!(reader.read(&mut buf).await.unwrap(), 0);
        writer.reset().await.unwrap();
        assert_eq!(
            reader.read(&mut buf).await.unwrap_err(),
            Error::H3_REQUEST_CANCELLED
        );

        let message = ArcMessage::from(Message::<Bytes>::default().with_body(ArcWndBuf::new(1)));
        let mut writer = Response::<Write, _>::from(message.clone());
        let reader = Response::<Read, _>::from(message);
        reader.stop().await;
        assert_eq!(
            writer.write(b"x").await.unwrap_err(),
            Error::H3_REQUEST_CANCELLED
        );
    }
}
