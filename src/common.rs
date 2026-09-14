use bytes::Bytes;

use crate::{
    ArcWndBuf,
    common::message::{ReadRequest, ReadResponse, WriteRequest, WriteResponse},
};

pub mod message;
pub(crate) mod request;
pub(crate) mod response;

pub enum Read {}
pub enum Write {}

pub enum Request<IO> {
    Bytes(request::Request<IO, Bytes>),
    Streaming(request::Request<IO, ArcWndBuf>),
}

pub enum Response<IO> {
    Bytes(response::Response<IO, Bytes>),
    Streaming(response::Response<IO, ArcWndBuf>),
}

impl<IO> ReadRequest for Request<IO> {
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
}

impl WriteRequest for Request<Write> {
    fn new(url: &str, method: http::Method) -> crate::Result<Self> {
        Ok(Self::Bytes(request::Request::new(url, method)?))
    }

    fn header(self, key: http::HeaderName, value: http::HeaderValue) -> Self {
        match &self {
            Self::Bytes(request) => {
                request.message.0.lock().unwrap().set_header(key, value);
            }
            Self::Streaming(request) => {
                request.message.0.lock().unwrap().set_header(key, value);
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
            let incoming: Request<Read> = request::Request::from(request.message.clone()).into();
            let streaming: Request<Write> =
                request::Request::from(request.message.with_body(ArcWndBuf::new(1))).into();
            let Request::Streaming(streaming) =
                streaming.header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
            else {
                panic!("expected streaming request")
            };
            assert_eq!(
                streaming
                    .message
                    .0
                    .lock()
                    .unwrap()
                    .header(&header::CONTENT_TYPE)
                    .unwrap(),
                "text/html"
            );
            for incoming in [incoming, request::Request::from(streaming.message).into()] {
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
            message::Message::header(&request.message.0.lock().unwrap(), &header::ACCEPT).unwrap(),
            "text/plain"
        );
    }

    #[test]
    fn response_enum_status_updates_both_body_modes() {
        for mut response in [
            Response::<Write>::from(response::Response::<Write, Bytes>::default()),
            response::Response::default().streaming(1).into(),
        ] {
            response.set_status(StatusCode::ACCEPTED);
            let incoming: Response<Read> = match response {
                Response::Bytes(response) => response::Response::from(response.message).into(),
                Response::Streaming(response) => response::Response::from(response.message).into(),
            };
            assert_eq!(incoming.status(), StatusCode::ACCEPTED);
        }
    }
}
