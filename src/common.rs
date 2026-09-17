use std::sync::Arc;

use bytes::Bytes;

use crate::{
    ArcWndBuf,
    common::message::{ReadRequest, ReadResponse, WriteRequest, WriteResponse},
};

pub(crate) mod body;
pub(crate) mod headers;
pub mod message;
pub(crate) mod request;
pub(crate) mod response;
pub mod wnd_buf;

/// Validated, case-sensitive Extended CONNECT protocol token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Protocol(Arc<str>);
impl Protocol {
    pub fn new(name: &str) -> crate::Result<Self> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
        {
            return Err(crate::ErrorCode::H3_MESSAGE_ERROR.reason("invalid CONNECT protocol token"));
        }
        Ok(Self(Arc::from(name)))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub enum Read {}
pub enum Write {}

/// Body storage and direction are independent: IO is Read or Write.
pub enum Body<IO> {
    Bytes(body::Body<Bytes, IO>),
    Streaming(body::Body<ArcWndBuf, IO>),
}

impl Clone for Body<Write> {
    fn clone(&self) -> Self {
        match self {
            Self::Bytes(body) => Self::Bytes(body.clone()),
            Self::Streaming(body) => Self::Streaming(body.clone()),
        }
    }
}

impl<IO> From<body::Body<Bytes, IO>> for Body<IO> {
    fn from(body: body::Body<Bytes, IO>) -> Self {
        Self::Bytes(body)
    }
}

impl<IO> From<body::Body<ArcWndBuf, IO>> for Body<IO> {
    fn from(body: body::Body<ArcWndBuf, IO>) -> Self {
        Self::Streaming(body)
    }
}

impl Body<Read> {
    pub async fn read(&mut self, bytes: &mut [u8]) -> crate::Result<usize> {
        match self {
            Self::Bytes(body) => body.read(bytes).await,
            Self::Streaming(body) => body.read(bytes).await,
        }
    }

    pub async fn stop(self) {
        if let Self::Streaming(body) = self {
            body.stop().await;
        }
    }

    pub async fn collect(self) -> crate::Result<Bytes> {
        match self {
            Self::Bytes(body) => body.collect().await,
            Self::Streaming(body) => body.collect().await,
        }
    }
}

pub enum Request<IO> {
    Bytes(request::Request<IO, Bytes>),
    Streaming(request::Request<IO, ArcWndBuf>),
}

pub enum Response<IO> {
    Bytes(response::Response<IO, Bytes>),
    Streaming(response::Response<IO, ArcWndBuf>),
}

impl<IO> ReadRequest for Request<IO> {
    fn protocol(&self) -> Option<crate::Protocol> {
        match self {
            Self::Bytes(r) => r.protocol(),
            Self::Streaming(r) => r.protocol(),
        }
    }

    fn method(&self) -> http::Method {
        match self {
            Self::Bytes(request) => request.method(),
            Self::Streaming(request) => request.method(),
        }
    }

    fn authority(&self) -> String {
        match self {
            Self::Bytes(request) => request.authority(),
            Self::Streaming(request) => request.authority(),
        }
    }

    fn path(&self) -> String {
        match self {
            Self::Bytes(request) => request.path(),
            Self::Streaming(request) => request.path(),
        }
    }

    fn scheme(&self) -> String {
        match self {
            Self::Bytes(request) => request.scheme(),
            Self::Streaming(request) => request.scheme(),
        }
    }

    fn headers(&self) -> http::HeaderMap {
        match self {
            Self::Bytes(request) => request.headers(),
            Self::Streaming(request) => request.headers(),
        }
    }
}

impl WriteRequest for Request<Write> {
    fn new(url: &str, method: http::Method) -> crate::Result<Self> {
        Ok(Self::Bytes(request::Request::new(url, method)?))
    }

    fn header(self, key: http::HeaderName, value: http::HeaderValue) -> Self {
        match &self {
            Self::Bytes(request) => {
                request
                    .message
                    .head
                    .lock()
                    .unwrap()
                    .headers
                    .insert(key, value);
            }
            Self::Streaming(request) => {
                request
                    .message
                    .head
                    .lock()
                    .unwrap()
                    .headers
                    .insert(key, value);
            }
        }
        self
    }
}

impl ReadResponse for Response<Read> {
    fn status(&self) -> http::StatusCode {
        match self {
            Self::Bytes(response) => response.status(),
            Self::Streaming(response) => response.status(),
        }
    }

    fn headers(&self) -> http::HeaderMap {
        match self {
            Self::Bytes(response) => response.headers(),
            Self::Streaming(response) => response.headers(),
        }
    }
}

impl WriteResponse for Response<Write> {
    fn set_status(&mut self, status: http::StatusCode) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.set_status(status);
            }
            Self::Streaming(response) => {
                response.set_status(status);
            }
        };
        self
    }

    fn set_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.set_header(name, value);
            }
            Self::Streaming(response) => {
                response.set_header(name, value);
            }
        }
        self
    }

    fn append_header(&mut self, name: http::HeaderName, value: http::HeaderValue) -> &mut Self {
        match self {
            Self::Bytes(response) => {
                response.append_header(name, value);
            }
            Self::Streaming(response) => {
                response.append_header(name, value);
            }
        }
        self
    }
}

impl<IO> From<request::Request<IO, Bytes>> for Request<IO> {
    fn from(request: request::Request<IO, Bytes>) -> Self {
        Self::Bytes(request)
    }
}

impl<IO> From<request::Request<IO, ArcWndBuf>> for Request<IO> {
    fn from(request: request::Request<IO, ArcWndBuf>) -> Self {
        Self::Streaming(request)
    }
}

impl<IO> From<response::Response<IO, Bytes>> for Response<IO> {
    fn from(response: response::Response<IO, Bytes>) -> Self {
        Self::Bytes(response)
    }
}

impl<IO> From<response::Response<IO, ArcWndBuf>> for Response<IO> {
    fn from(response: response::Response<IO, ArcWndBuf>) -> Self {
        Self::Streaming(response)
    }
}

impl<IO> Request<IO> {
    pub fn into_body(self) -> Body<IO> {
        match self {
            Self::Bytes(message) => Body::Bytes(message.into_body()),
            Self::Streaming(message) => Body::Streaming(message.into_body()),
        }
    }
}

impl<IO> Response<IO> {
    pub fn into_body(self) -> Body<IO> {
        match self {
            Self::Bytes(message) => Body::Bytes(message.into_body()),
            Self::Streaming(message) => Body::Streaming(message.into_body()),
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, Method, StatusCode, header};

    use super::*;

    #[test]
    fn request_constructors_and_enum_metadata() {
        for (constructor, method) in [
            (
                Request::<Write>::get as fn(&str) -> crate::Result<Request<Write>>,
                Method::GET,
            ),
            (Request::head, Method::HEAD),
            (Request::post, Method::POST),
            (Request::put, Method::PUT),
            (Request::delete, Method::DELETE),
            (Request::connect, Method::CONNECT),
            (Request::options, Method::OPTIONS),
            (Request::trace, Method::TRACE),
            (Request::patch, Method::PATCH),
        ] {
            let request = constructor("https://example.com:443/a?q=1")
                .unwrap()
                .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            let Request::Bytes(request) = request else {
                panic!("expected buffered request")
            };
            let incoming: Request<Read> =
                request::Request::from(request.message.test_direction()).into();
            let streaming: Request<Write> = request::Request::from(
                request
                    .message
                    .with_body(body::Body::<ArcWndBuf, Write>::with_capacity(1)),
            )
            .into();
            let Request::Streaming(streaming) =
                streaming.header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
            else {
                panic!("expected streaming request")
            };
            assert_eq!(
                streaming
                    .message
                    .head
                    .lock()
                    .unwrap()
                    .headers
                    .get(&header::CONTENT_TYPE)
                    .unwrap(),
                "text/html"
            );
            for incoming in [
                incoming,
                request::Request::from(streaming.message.test_direction()).into(),
            ] {
                assert_eq!(incoming.method(), method);
                assert_eq!(incoming.authority(), "example.com:443");
                assert_eq!(
                    incoming.path(),
                    if method == Method::CONNECT {
                        ""
                    } else {
                        "/a?q=1"
                    }
                );
                assert_eq!(
                    incoming.scheme(),
                    if method == Method::CONNECT {
                        ""
                    } else {
                        "https"
                    }
                );
            }
            assert!(constructor("/relative").is_err());
        }
        let request = WriteRequest::header(
            request::Request::<Write>::get("https://example.com").unwrap(),
            header::ACCEPT,
            HeaderValue::from_static("text/plain"),
        );
        assert_eq!(
            request.message.head.lock().unwrap().headers[header::ACCEPT],
            "text/plain"
        );
    }

    #[test]
    fn response_enum_metadata_updates_both_body_modes() {
        for mut response in [
            Response::<Write>::from(response::Response::<Write, Bytes>::default()),
            response::Response::default().streaming(1).into(),
        ] {
            response
                .set_status(StatusCode::ACCEPTED)
                .append_header(header::SET_COOKIE, HeaderValue::from_static("old=1"))
                .append_header(header::SET_COOKIE, HeaderValue::from_static("old=2"))
                .set_header(header::SET_COOKIE, HeaderValue::from_static("a=1"))
                .append_header(header::SET_COOKIE, HeaderValue::from_static("b=2"));
            let incoming: Response<Read> = match response {
                Response::Bytes(response) => {
                    response::Response::from(response.message.test_direction()).into()
                }
                Response::Streaming(response) => {
                    response::Response::from(response.message.test_direction()).into()
                }
            };
            assert_eq!(incoming.status(), StatusCode::ACCEPTED);
            assert_eq!(
                incoming
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .collect::<Vec<_>>(),
                [
                    &HeaderValue::from_static("a=1"),
                    &HeaderValue::from_static("b=2")
                ]
            );
        }
    }
}
