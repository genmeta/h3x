use std::{
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Read, Write, trailers::Trailers};
use crate::{ArcQpack, ArcWndBuf, ErrorCode, Result, qpack::Field};

/// An HTTP response and its shared streaming body.
#[derive(Debug)]
pub struct Response<IO> {
    pub(crate) head: http::response::Parts,
    pub(crate) body: ArcWndBuf,
    pub(crate) trailers: Trailers,
    _io: PhantomData<IO>,
}

impl<IO> Response<IO> {
    /// Build a response from its metadata and shared streaming body.
    pub fn from_parts(mut head: http::response::Parts, body: ArcWndBuf) -> Self {
        let trailers = head.extensions.remove::<Trailers>().unwrap_or_default();
        Self {
            head,
            body,
            trailers,
            _io: PhantomData,
        }
    }

    /// Split this response into its metadata and shared streaming body.
    pub fn into_parts(self) -> (http::response::Parts, ArcWndBuf) {
        let mut head = self.head;
        head.extensions.insert(self.trailers);
        (head, self.body)
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

    /// Return a snapshot of the trailer fields.
    ///
    /// Incoming trailers are complete after the body reaches EOF.
    pub fn trailers(&self) -> HeaderMap {
        self.trailers.headers()
    }
}

impl Clone for Response<Write> {
    fn clone(&self) -> Self {
        Self {
            head: self.head.clone(),
            body: self.body.clone(),
            trailers: self.trailers.clone(),
            _io: PhantomData,
        }
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

    /// Set an outgoing trailer field.
    ///
    /// All trailers must be set before the body is shut down.
    pub fn set_trailer(&self, name: HeaderName, value: HeaderValue) -> &Self {
        self.trailers.set(name, value);
        self
    }

    /// Append an outgoing trailer field without replacing existing values.
    ///
    /// All trailers must be appended before the body is shut down.
    pub fn append_trailer(&self, name: HeaderName, value: HeaderValue) -> &Self {
        self.trailers.append(name, value);
        self
    }
}

impl Response<Read> {
    pub(crate) fn from_fields(fields: Vec<Field>, body: ArcWndBuf) -> Result<Self> {
        let mut status = None;

        let mut response = http::Response::new(());

        for field in fields {
            if field.name.iter().any(u8::is_ascii_uppercase) {
                return Err(ErrorCode::MessageError.stream("uppercase field name"));
            }
            if !response.headers().is_empty() && field.name.starts_with(b":") {
                return Err(
                    ErrorCode::MessageError.stream("pseudo-header after regular header field")
                );
            }
            match field.name.as_ref() {
                b":status" => {
                    let value = StatusCode::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::MessageError.stream("invalid :status"))?;
                    if status.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.stream("duplicate :status"));
                    }
                }
                name if name.starts_with(b":") => {
                    return Err(ErrorCode::MessageError.stream("undefined response pseudo-header"));
                }
                name => {
                    let name = HeaderName::from_bytes(name)
                        .map_err(|_| ErrorCode::MessageError.stream("invalid header name"))?;
                    let mut value = HeaderValue::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::MessageError.stream("invalid header value"))?;
                    value.set_sensitive(field.never_index);
                    response.headers_mut().append(name, value);
                }
            }
        }

        *response.status_mut() =
            status.ok_or_else(|| ErrorCode::MessageError.stream("missing or invalid :status"))?;
        *response.version_mut() = http::Version::HTTP_3;
        Ok(Self::from_parts(response.into_parts().0, body))
    }
}

impl From<http::Response<ArcWndBuf>> for Response<Write> {
    fn from(response: http::Response<ArcWndBuf>) -> Self {
        let (mut head, body) = response.into_parts();
        head.version = http::Version::HTTP_3;
        let trailers = head.extensions.remove::<Trailers>().unwrap_or_default();
        Self {
            head,
            body,
            trailers,
            _io: PhantomData,
        }
    }
}

impl<IO> From<Response<IO>> for http::Response<ArcWndBuf> {
    fn from(response: Response<IO>) -> Self {
        let (head, body) = response.into_parts();
        Self::from_parts(head, body)
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

impl StopSending for Response<Read> {
    fn stop(&mut self, error_code: u64) {
        self.body.stop(error_code);
    }
}

impl CancelStream for Response<Write> {
    fn cancel(&mut self, error_code: u64) {
        self.body.cancel(error_code);
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
