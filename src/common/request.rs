use std::{
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Read, Write, trailers::Trailers};
use crate::{ArcQpack, ArcWndBuf, ErrorCode, Result, qpack::Field};

/// An HTTP request and its shared streaming body.
#[derive(Debug)]
pub struct Request<IO> {
    pub(crate) head: http::request::Parts,
    pub(crate) body: ArcWndBuf,
    pub(crate) trailers: Trailers,
    _io: PhantomData<IO>,
}

impl<IO> Request<IO> {
    /// Build a request from its metadata and shared streaming body.
    pub fn from_parts(mut head: http::request::Parts, body: ArcWndBuf) -> Self {
        let trailers = head.extensions.remove::<Trailers>().unwrap_or_default();
        Self {
            head,
            body,
            trailers,
            _io: PhantomData,
        }
    }

    /// Split this request into its metadata and shared streaming body.
    pub fn into_parts(self) -> (http::request::Parts, ArcWndBuf) {
        let mut head = self.head;
        head.extensions.insert(self.trailers);
        (head, self.body)
    }

    pub fn method(&self) -> &Method {
        &self.head.method
    }

    pub fn uri(&self) -> &Uri {
        &self.head.uri
    }

    pub fn protocol(&self) -> Option<&str> {
        self.head.extensions.get::<Arc<str>>().map(AsRef::as_ref)
    }

    pub fn authority(&self) -> &str {
        self.head.uri.authority().map_or("", |value| value.as_str())
    }

    pub fn path(&self) -> &str {
        self.head
            .uri
            .path_and_query()
            .map_or("", |value| value.as_str())
    }

    pub fn scheme(&self) -> &str {
        self.head.uri.scheme_str().unwrap_or("")
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.head.headers
    }

    pub(crate) fn pseudo_headers(&self) -> [(&'static [u8], Option<&str>); 5] {
        [
            (b":method", Some(self.head.method.as_str())),
            (b":scheme", self.head.uri.scheme_str()),
            (
                b":authority",
                self.head.uri.authority().map(http::uri::Authority::as_str),
            ),
            (
                b":path",
                self.head
                    .uri
                    .path_and_query()
                    .map(http::uri::PathAndQuery::as_str),
            ),
            (b":protocol", self.protocol()),
        ]
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

impl Clone for Request<Write> {
    fn clone(&self) -> Self {
        Self {
            head: self.head.clone(),
            body: self.body.clone(),
            trailers: self.trailers.clone(),
            _io: PhantomData,
        }
    }
}

impl Request<Write> {
    fn normalize_websocket_scheme(&mut self) {
        if self.head.method != Method::CONNECT || self.protocol() != Some("websocket") {
            return;
        }
        let Some(scheme) = self.head.uri.scheme_str() else {
            return;
        };
        let scheme = match scheme {
            "ws" => "http",
            "wss" => "https",
            _ => return,
        };
        let mut uri = Uri::builder().scheme(scheme);
        if let Some(authority) = self.head.uri.authority() {
            uri = uri.authority(authority.clone());
        }
        if let Some(path) = self.head.uri.path_and_query() {
            uri = uri.path_and_query(path.clone());
        }
        self.head.uri = uri.build().expect("existing URI components remain valid");
    }

    pub fn set_method(&mut self, method: Method) -> &mut Self {
        self.head.method = method;
        self.normalize_websocket_scheme();
        self
    }

    pub fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.head.uri = uri;
        self.normalize_websocket_scheme();
        self
    }

    pub fn set_protocol(&mut self, protocol: &str) -> &mut Self {
        self.head.extensions.insert(Arc::<str>::from(protocol));
        self.normalize_websocket_scheme();
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

impl Request<Read> {
    pub(crate) fn from_fields(fields: Vec<Field>, body: ArcWndBuf) -> Result<Self> {
        let mut method = None;
        let mut scheme = None;
        let mut authority = None;
        let mut path = None;
        let mut protocol = None;
        let mut request = http::Request::new(());

        for field in fields {
            if !request.headers().is_empty() && field.name.starts_with(b":") {
                return Err(
                    ErrorCode::MessageError.reason("pseudo-header after regular header field")
                );
            }
            match field.name.as_ref() {
                b":method" => {
                    let value = Method::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid :method"))?;
                    if method.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.reason("duplicate :method"));
                    }
                }
                b":scheme" => {
                    let value = std::str::from_utf8(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid :scheme"))?
                        .to_owned();
                    if scheme.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.reason("duplicate :scheme"));
                    }
                }
                b":authority" => {
                    let value = std::str::from_utf8(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid :authority"))?
                        .to_owned();
                    if authority.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.reason("duplicate :authority"));
                    }
                }
                b":path" => {
                    let value = std::str::from_utf8(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid :path"))?
                        .to_owned();
                    if path.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.reason("duplicate :path"));
                    }
                }
                b":protocol" => {
                    let value = std::str::from_utf8(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid :protocol"))?
                        .to_owned();
                    if protocol.replace(value).is_some() {
                        return Err(ErrorCode::MessageError.reason("duplicate :protocol"));
                    }
                }
                name if name.starts_with(b":") => {
                    return Err(ErrorCode::MessageError.reason("undefined request pseudo-header"));
                }
                name => {
                    let name = HeaderName::from_lowercase(name)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid header name"))?;
                    let mut value = HeaderValue::from_bytes(&field.value)
                        .map_err(|_| ErrorCode::MessageError.reason("invalid header value"))?;
                    value.set_sensitive(field.never_index);
                    request.headers_mut().append(name, value);
                }
            }
        }

        let method =
            method.ok_or_else(|| ErrorCode::MessageError.reason("missing or invalid :method"))?;

        let mut uri = Uri::builder();
        if let Some(scheme) = &scheme {
            uri = uri.scheme(scheme.as_str());
        }
        if let Some(authority) = &authority {
            uri = uri.authority(authority.as_str());
        }
        if let Some(path) = &path {
            uri = uri.path_and_query(path.as_str());
        }
        *request.method_mut() = method;
        *request.uri_mut() = uri
            .build()
            .map_err(|_| ErrorCode::MessageError.reason("invalid request URI"))?;
        *request.version_mut() = http::Version::HTTP_3;
        if let Some(protocol) = protocol {
            request.extensions_mut().insert(Arc::<str>::from(protocol));
        }
        Ok(Self::from_parts(request.into_parts().0, body))
    }
}

impl From<http::Request<ArcWndBuf>> for Request<Write> {
    fn from(request: http::Request<ArcWndBuf>) -> Self {
        let (mut head, body) = request.into_parts();
        head.version = http::Version::HTTP_3;
        let trailers = head.extensions.remove::<Trailers>().unwrap_or_default();
        let mut request = Self {
            head,
            body,
            trailers,
            _io: PhantomData,
        };
        request.normalize_websocket_scheme();
        request
    }
}

impl<IO> From<Request<IO>> for http::Request<ArcWndBuf> {
    fn from(request: Request<IO>) -> Self {
        let (head, body) = request.into_parts();
        Self::from_parts(head, body)
    }
}

impl AsyncRead for Request<Read> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.body).poll_read(cx, buf)
    }
}

impl AsyncWrite for Request<Write> {
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

impl StopSending for Request<Read> {
    fn stop(&mut self, error_code: u64) {
        self.body.stop(error_code);
    }
}

impl CancelStream for Request<Write> {
    fn cancel(&mut self, error_code: u64) {
        self.body.cancel(error_code);
    }
}

/// Read an HTTP/3 request from a request stream.
pub trait ReadRequest: Sized + Send {
    fn read_request(self, qpack: ArcQpack) -> impl Future<Output = Result<Request<Read>>> + Send;
}

/// Write an HTTP/3 request to a request stream.
pub trait WriteRequest: Sized + Send {
    fn write_request(
        self,
        request: Request<Write>,
        qpack: ArcQpack,
    ) -> impl Future<Output = Result<()>> + Send;
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn fields(values: &[(&'static str, &'static str)]) -> Vec<Field> {
        values
            .iter()
            .map(|(name, value)| Field {
                name: Bytes::from_static(name.as_bytes()),
                value: Bytes::from_static(value.as_bytes()),
                never_index: false,
            })
            .collect()
    }

    fn parse(values: &[(&'static str, &'static str)]) -> Result<Request<Read>> {
        Request::from_fields(fields(values), ArcWndBuf::new(1))
    }

    #[test]
    fn rejects_malformed_request_pseudo_headers() {
        for values in [
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/"),
                (":status", "200"),
            ][..],
            &[
                (":method", "GET"),
                (":method", "POST"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/"),
            ],
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                ("x-tag", "a"),
                (":path", "/"),
            ],
            &[
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "example.com"),
                (":path", "/"),
                ("X-Tag", "a"),
            ],
        ] {
            assert!(matches!(
                parse(values),
                Err(error) if error.code == ErrorCode::MessageError
            ));
        }
    }

    #[test]
    fn accepts_flexible_connect_pseudo_headers() {
        let connect = parse(&[(":method", "CONNECT")]).unwrap();
        assert_eq!(connect.authority(), "");

        let connect = parse(&[(":method", "CONNECT"), (":authority", "example.com:443")]).unwrap();
        assert_eq!(connect.authority(), "example.com:443");
        assert_eq!(connect.scheme(), "");
        assert_eq!(connect.path(), "");

        let extended = parse(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/chat"),
            (":protocol", "websocket"),
        ])
        .unwrap();
        assert_eq!(extended.protocol(), Some("websocket"));

        parse(&[
            (":method", "CONNECT"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
        ])
        .unwrap();
        parse(&[
            (":method", "CONNECT"),
            (":authority", "example.com"),
            (":protocol", "websocket"),
        ])
        .unwrap();
    }
}
