use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};

use super::{
    Read, Write,
    body::Body,
    headers::RequestHead,
    message::{
        ArcMessage, Message, ReadBody, ReadRequest, ReadStream, WriteBody, WriteRequest,
        WriteStream,
    },
};
use crate::{ArcWndBuf, Result};

const DEFAULT_STREAM_CAPACITY: usize = 16 * 1024;

pub struct Request<IO, B = Bytes> {
    pub(crate) message: ArcMessage<RequestHead, Body<B, IO>>,
}

/// Cloning shares metadata and body storage.
impl<B> Clone for Request<Write, B> {
    fn clone(&self) -> Self {
        Self {
            message: self.message.clone(),
        }
    }
}

impl<IO, B> From<ArcMessage<RequestHead, Body<B, IO>>> for Request<IO, B> {
    fn from(message: ArcMessage<RequestHead, Body<B, IO>>) -> Self {
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

impl Request<Write, Bytes> {
    pub fn body(mut self, body: Bytes) -> Self {
        self.set_body(body);
        self
    }
}

impl Request<Write, ArcWndBuf> {
    fn streaming(url: &str, method: Method) -> Result<Self> {
        let message = Message::new_request_with_body(
            url,
            method,
            Body::<ArcWndBuf, Write>::new(DEFAULT_STREAM_CAPACITY),
        )?;
        Ok(ArcMessage::from(message).into())
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

    pub fn streaming_connect(url: &str) -> Result<Self> {
        Self::streaming(url, Method::CONNECT)
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
        Ok(ArcMessage::from(Message::<RequestHead, Body<B, Write>>::new(url, method)?).into())
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
    pub fn body_handle(&self) -> super::body::Body<B, Write> {
        self.message.body_handle()
    }
}

impl Request<Write, Bytes> {
    /// Attach an application body, retaining this message's headers.
    pub fn with_body<C>(self, body: super::body::Body<C, Write>) -> Request<Write, C> {
        self.message.with_body(body).into()
    }
}

#[cfg(test)]
mod tests {
    use http::{StatusCode, header};

    use super::*;
    use crate::{
        ErrorCode,
        common::{
            message::{ReadResponse, WriteResponse},
            response::Response,
        },
    };

    #[test]
    fn sharing_a_body_does_not_share_or_overwrite_headers() {
        fn check<B: Clone>(body: Body<B, Write>) {
            let first = crate::client::Request::post("https://example.com/first")
                .unwrap()
                .header(header::CONTENT_TYPE, "text/plain".parse().unwrap())
                .with_body(body.clone());
            let second = crate::client::Request::put("https://example.com/second")
                .unwrap()
                .header(header::CONTENT_TYPE, "application/json".parse().unwrap())
                .with_body(body);
            assert_eq!(first.method(), Method::POST);
            assert_eq!(first.path(), "/first");
            assert_eq!(first.headers()[header::CONTENT_TYPE], "text/plain");
            assert_eq!(second.method(), Method::PUT);
            assert_eq!(second.path(), "/second");
            assert_eq!(second.headers()[header::CONTENT_TYPE], "application/json");
        }
        check(Body::<Bytes, Write>::new(Bytes::from_static(b"data")));
        check(Body::<ArcWndBuf, Write>::new(1));
    }

    #[tokio::test]
    async fn extracted_body_releases_headers() {
        use std::sync::Arc;
        for retain_clone in [false, true] {
            let request = crate::client::Request::streaming_post("https://example.com/").unwrap();
            let message = Arc::downgrade(&request.message.head);
            let retained = retain_clone.then(|| request.clone());
            let mut body = request.into_body();
            assert_eq!(message.upgrade().is_some(), retain_clone);
            drop(retained);
            assert!(
                message.upgrade().is_none(),
                "body must not retain message headers"
            );
            body.write_all(b"x").await.unwrap();
            body.finish().await.unwrap();
        }
    }

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
            let head = request.message.head.lock().unwrap();
            assert_eq!(head.method(), method);
            assert_eq!(head.authority(), "example.com");
            assert_eq!(
                head.path(),
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
    async fn streaming_body_backpressure_and_errors_before_sending() {
        use std::{
            future::Future,
            task::{Context, Waker},
            time::Duration,
        };

        use crate::protocol::stream::{H3ReadStream, H3WriteStream};

        tokio::time::timeout(Duration::from_secs(5), async {
            for error in [ErrorCode::H3_REQUEST_CANCELLED, ErrorCode::H3_MESSAGE_ERROR] {
                let mut request = Request::streaming_post("https://example.com/upload").unwrap();
                if error == ErrorCode::H3_MESSAGE_ERROR {
                    request =
                        request.header(header::CONTENT_LENGTH, HeaderValue::from_static("invalid"));
                }
                assert_eq!(
                    request
                        .write(vec![b'x'; DEFAULT_STREAM_CAPACITY])
                        .await
                        .unwrap(),
                    DEFAULT_STREAM_CAPACITY
                );
                let mut writer = request.clone();
                let mut waiting = Box::pin(writer.write(b"y"));
                assert!(
                    waiting
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                if error == ErrorCode::H3_REQUEST_CANCELLED {
                    request.reset().await.unwrap();
                } else {
                    let result = crate::client::write_streaming_request(
                        request,
                        H3WriteStream::new(0, tokio::io::sink()),
                        H3ReadStream::new(0, tokio::io::empty()),
                        crate::test_support::connection(),
                    );
                    assert!(matches!(result, Err(actual) if actual == error));
                }
                assert_eq!(waiting.await, Err(error));
                assert_eq!(writer.finish().await, Err(error));
            }
        })
        .await
        .expect("body writes must use buffer capacity and errors before sending");
    }

    #[tokio::test]
    async fn shared_metadata_bodies_and_streams() {
        let mut writer = Request::<Write>::post("https://example.com/a?q=1")
            .unwrap()
            .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))
            .body(Bytes::from_static(b"hello"));
        let reader = Request::<Read>::from(writer.message.test_direction());
        assert_eq!(reader.method(), Method::POST);
        assert_eq!(reader.authority(), "example.com");
        assert_eq!(reader.path(), "/a?q=1");
        assert_eq!(reader.scheme(), "https");
        assert_eq!(reader.body(), Bytes::from_static(b"hello"));
        writer.set_body(Bytes::from_static(b"updated"));
        assert_eq!(reader.body(), Bytes::from_static(b"hello"));
        assert_eq!(
            writer.message.body.lock().unwrap().storage,
            Bytes::from_static(b"updated")
        );
        assert!(Request::<Write>::get("/relative").is_err());

        let message = ArcMessage::from(Message::<
            crate::common::headers::ResponseHead,
            Body<Bytes, Write>,
        >::default());
        let mut response = Response::<Write>::from(message.clone());
        response
            .set_status(StatusCode::CREATED)
            .set_body(Bytes::from_static(b"ok"));
        let response = Response::<Read>::from(message.test_direction());
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.body(), Bytes::from_static(b"ok"));

        let request = crate::client::Request::streaming_post("https://example.com/")
            .unwrap()
            .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let mut writer = request.clone();
        assert!(std::sync::Arc::ptr_eq(
            &request.message.head,
            &writer.message.head
        ));
        assert!(std::sync::Arc::ptr_eq(
            &request.message.body,
            &writer.message.body
        ));
        let mut reader = Request::<Read, _>::from(request.message.test_direction());
        assert_eq!(reader.method(), Method::POST);
        assert_eq!(reader.authority(), "example.com");
        assert_eq!(
            reader
                .message
                .head
                .lock()
                .unwrap()
                .headers
                .get(&header::CONTENT_TYPE)
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
            ErrorCode::H3_REQUEST_CANCELLED
        );

        let message = ArcMessage::from(
            Message::<crate::common::headers::ResponseHead, Bytes>::default()
                .with_body(crate::Body::from_storage(ArcWndBuf::new(1))),
        );
        let mut writer = Response::<Write, _>::from(message.clone());
        let reader = Response::<Read, _>::from(message.test_direction());
        reader.stop().await;
        assert_eq!(
            writer.write(b"x").await.unwrap_err(),
            ErrorCode::H3_REQUEST_CANCELLED
        );
    }
}
