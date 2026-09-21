use std::{
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Read, Write};
use crate::{ArcQpack, ArcWndBuf, ErrorCode, Result, qpack::Field};

/// An HTTP response and its shared streaming body.
#[derive(Debug)]
pub struct Response<IO> {
    pub(crate) head: http::response::Parts,
    pub(crate) body: ArcWndBuf,
    _io: PhantomData<IO>,
}

impl<IO> Response<IO> {
    pub(crate) fn from_parts(head: http::response::Parts, body: ArcWndBuf) -> Self {
        Self {
            head,
            body,
            _io: PhantomData,
        }
    }

    pub fn status(&self) -> StatusCode {
        self.head.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.head.headers
    }

    pub(crate) fn pseudo_headers(&self) -> [(&'static [u8], Option<&str>); 1] {
        [(b":status", Some(self.head.status.as_str()))]
    }

    pub fn body(&self) -> &ArcWndBuf {
        &self.body
    }

    pub fn into_body(self) -> ArcWndBuf {
        self.body
    }
}

impl Response<Write> {
    pub fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.head.status = status;
        self
    }

    pub fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.headers.insert(name, value);
        self
    }

    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.head.headers.append(name, value);
        self
    }
}

impl Response<Read> {
    pub(crate) fn from_fields(fields: Vec<Field>, body: ArcWndBuf) -> Result<Self> {
        let mut status = None;

        let mut response = http::Response::new(());

        for field in fields {
            if field.name.iter().any(u8::is_ascii_uppercase) {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("uppercase field name"));
            }
            if !response.headers().is_empty() && field.name.starts_with(b":") {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("pseudo-header after regular header field")
                );
            }
            match field.name.as_ref() {
                b":status" => {
                    let value = StatusCode::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::H3_MESSAGE_ERROR.reason("invalid :status"))?;
                    if status.replace(value).is_some() {
                        return Err(ErrorCode::H3_MESSAGE_ERROR.reason("duplicate :status"));
                    }
                }
                name if name.starts_with(b":") => {
                    return Err(
                        ErrorCode::H3_MESSAGE_ERROR.reason("undefined response pseudo-header")
                    );
                }
                name => {
                    let name = HeaderName::from_bytes(name)
                        .map_err(|_| ErrorCode::H3_MESSAGE_ERROR.reason("invalid header name"))?;
                    let mut value = HeaderValue::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::H3_MESSAGE_ERROR.reason("invalid header value"))?;
                    value.set_sensitive(field.never_index);
                    response.headers_mut().append(name, value);
                }
            }
        }

        *response.status_mut() = status
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("missing or invalid :status"))?;
        *response.version_mut() = http::Version::HTTP_3;
        Ok(Self::from_parts(response.into_parts().0, body))
    }
}

impl From<http::Response<ArcWndBuf>> for Response<Write> {
    fn from(response: http::Response<ArcWndBuf>) -> Self {
        let (mut head, body) = response.into_parts();
        head.version = http::Version::HTTP_3;
        Self {
            head,
            body,
            _io: PhantomData,
        }
    }
}

impl<IO> From<Response<IO>> for http::Response<ArcWndBuf> {
    fn from(response: Response<IO>) -> Self {
        Self::from_parts(response.head, response.body)
    }
}

impl AsyncRead for Response<Read> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_read(cx, buf)
    }
}

impl AsyncWrite for Response<Write> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.body).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_shutdown(cx)
    }
}

/// Read a final HTTP/3 response from a request stream.
pub trait ReadResponse: Sized + Send {
    fn read_response(
        self,
        request_method: Method,
        qpack: ArcQpack,
    ) -> impl Future<Output = Result<Response<Read>>> + Send;
}

/// Write an HTTP/3 response to a request stream.
pub trait WriteResponse: Sized + Send {
    fn write_response(
        self,
        response: Response<Write>,
        request_method: Method,
        qpack: ArcQpack,
    ) -> impl Future<Output = Result<()>> + Send;
}
