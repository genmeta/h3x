use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

use crate::{
    ArcQpack, ArcWndBuf, ErrorCode, Result,
    frame::{self, Frame},
    qpack::Field,
};

pub trait PesudoHeaders {
    fn pesudo_headers() -> &'static [&'static str];
}

/// Message metadata with pseudo-headers kept separate from ordinary HTTP fields.
#[derive(Clone, Default, Debug)]
pub struct Headers {
    pub header: HeaderMap,
    pub pseduo_head: HashMap<String, String>,
}

impl Headers {
    pub(crate) async fn decode_headers(
        stream_id: u64,
        frame: Frame<frame::Headers>,
        qpack: &ArcQpack,
    ) -> Result<Self> {
        let mut headers = Self::default();
        for field in qpack.decode(stream_id, frame.payload.field_section).await? {
            if field.name.starts_with(b":") {
                let name = String::from_utf8(field.name.to_vec()).map_err(field_error)?;
                let value = String::from_utf8(field.value.to_vec()).map_err(field_error)?;
                headers.pseduo_head.insert(name, value);
            } else {
                let name = HeaderName::from_bytes(&field.name).map_err(field_error)?;
                let mut value = HeaderValue::from_bytes(&field.value).map_err(field_error)?;
                value.set_sensitive(field.never_index);
                headers.header.append(name, value);
            }
        }
        Ok(headers)
    }

    pub(crate) fn encode_headers(
        &self,
        stream_id: u64,
        qpack: &ArcQpack,
    ) -> Result<Frame<frame::Headers>> {
        let mut fields = Vec::with_capacity(self.pseduo_head.len() + self.header.len());
        let mut pseudo: Vec<_> = self.pseduo_head.iter().collect();
        pseudo.sort_unstable_by_key(|(name, _)| *name);
        fields.extend(pseudo.into_iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: false,
        }));
        fields.extend(self.header.iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: value.is_sensitive(),
        }));
        Frame::new(frame::Headers {
            field_section: qpack.encode(stream_id, fields)?,
        })
    }

    pub(crate) fn response_status(&self) -> Result<StatusCode> {
        let status = self
            .pseduo_head
            .get(":status")
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("missing :status"))?;
        StatusCode::from_bytes(status.as_bytes()).map_err(field_error)
    }

    fn normalize_websocket_scheme(&mut self) {
        if self.pseduo_head.get(":method").map(String::as_str) != Some("CONNECT")
            || self.pseduo_head.get(":protocol").map(String::as_str) != Some("websocket")
        {
            return;
        }
        match self.pseduo_head.get(":scheme").map(String::as_str) {
            Some("ws") => {
                self.pseduo_head.insert(":scheme".into(), "http".into());
            }
            Some("wss") => {
                self.pseduo_head.insert(":scheme".into(), "https".into());
            }
            _ => {}
        }
    }

    fn replace_uri(&mut self, uri: Uri) {
        for name in [":scheme", ":authority", ":path"] {
            self.pseduo_head.remove(name);
        }
        if let Some(scheme) = uri.scheme_str() {
            self.pseduo_head.insert(":scheme".into(), scheme.into());
        }
        if let Some(authority) = uri.authority() {
            self.pseduo_head
                .insert(":authority".into(), authority.as_str().into());
        }
        if let Some(path) = uri.path_and_query() {
            self.pseduo_head
                .insert(":path".into(), path.as_str().into());
        }
        self.normalize_websocket_scheme();
    }
}

fn field_error(error: impl std::fmt::Display) -> crate::Error {
    ErrorCode::H3_MESSAGE_ERROR.reason(format!("cannot parse HTTP field: {error}"))
}

impl From<http::request::Parts> for Headers {
    fn from(parts: http::request::Parts) -> Self {
        let mut headers = Self {
            header: parts.headers,
            pseduo_head: HashMap::new(),
        };
        headers.set_method(parts.method);
        if let Some(protocol) = parts.extensions.get::<Arc<str>>() {
            headers.set_protocol(protocol);
        }
        headers.replace_uri(parts.uri);
        headers
    }
}

impl From<Headers> for http::request::Parts {
    fn from(headers: Headers) -> Self {
        let mut request = http::Request::new(());
        *request.method_mut() = headers.method();
        *request.version_mut() = http::Version::HTTP_3;
        if let Some(protocol) = headers.protocol() {
            request.extensions_mut().insert(protocol);
        }
        let mut uri = Uri::builder();
        if let Some(scheme) = headers.pseduo_head.get(":scheme") {
            uri = uri.scheme(scheme.as_str());
        }
        if let Some(authority) = headers.pseduo_head.get(":authority") {
            uri = uri.authority(authority.as_str());
        }
        if let Some(path) = headers.pseduo_head.get(":path") {
            uri = uri.path_and_query(path.as_str());
        }
        *request.uri_mut() = uri.build().expect("pseudo-headers must form an HTTP URI");
        *request.headers_mut() = headers.header;
        request.into_parts().0
    }
}

impl From<http::response::Parts> for Headers {
    fn from(parts: http::response::Parts) -> Self {
        Self {
            header: parts.headers,
            pseduo_head: HashMap::from([(":status".into(), parts.status.as_str().into())]),
        }
    }
}

impl From<Headers> for http::response::Parts {
    fn from(headers: Headers) -> Self {
        let mut response = http::Response::new(());
        *response.status_mut() = headers.status();
        *response.version_mut() = http::Version::HTTP_3;
        *response.headers_mut() = headers.header;
        response.into_parts().0
    }
}

#[derive(Debug)]
/// Message metadata and body storage. Construction does not start network or body work.
pub struct Message {
    pub(crate) head: Headers,
    pub body: ArcWndBuf,
}

impl Message {
    pub fn from_parts(head: Headers, body: ArcWndBuf) -> Self {
        Self { head, body }
    }
}

/// Request metadata, available for both incoming and outgoing requests.
pub trait ReadRequest: Sized {
    fn protocol(&self) -> Option<Arc<str>>;

    fn method(&self) -> Method;

    fn authority(&self) -> String;

    fn path(&self) -> String;

    fn scheme(&self) -> String;

    /// Return an owned snapshot of the ordinary headers, excluding pseudo-headers.
    fn headers(&self) -> HeaderMap;
}

/// Outgoing request metadata. Set these before sending the request.
pub trait WriteRequest {
    fn set_method(&mut self, method: Method) -> &mut Self;

    fn set_uri(&mut self, uri: Uri) -> &mut Self;

    fn set_protocol(&mut self, protocol: &str) -> &mut Self;

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;
}

/// Server-side response status and headers. Set these before sending the response.
pub trait WriteResponse {
    fn set_status(&mut self, status: StatusCode) -> &mut Self;

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self;
}

/// Response metadata, available for both incoming and outgoing responses.
pub trait ReadResponse {
    fn status(&self) -> StatusCode;

    fn headers(&self) -> HeaderMap;
}

impl ReadRequest for Headers {
    fn protocol(&self) -> Option<Arc<str>> {
        self.pseduo_head
            .get(":protocol")
            .map(|protocol| Arc::from(protocol.as_str()))
    }

    fn method(&self) -> Method {
        self.pseduo_head
            .get(":method")
            .and_then(|method| Method::from_bytes(method.as_bytes()).ok())
            .expect("missing or invalid :method")
    }

    fn authority(&self) -> String {
        self.pseduo_head
            .get(":authority")
            .cloned()
            .unwrap_or_default()
    }

    fn path(&self) -> String {
        self.pseduo_head.get(":path").cloned().unwrap_or_default()
    }

    fn scheme(&self) -> String {
        self.pseduo_head.get(":scheme").cloned().unwrap_or_default()
    }

    fn headers(&self) -> HeaderMap {
        self.header.clone()
    }
}

impl WriteRequest for Headers {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.pseduo_head
            .insert(":method".into(), method.as_str().into());
        self.normalize_websocket_scheme();
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.replace_uri(uri);
        self
    }

    fn set_protocol(&mut self, protocol: &str) -> &mut Self {
        self.pseduo_head.insert(":protocol".into(), protocol.into());
        self.normalize_websocket_scheme();
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.header.insert(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.header.append(name, value);
        self
    }
}

impl WriteResponse for Headers {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.pseduo_head
            .insert(":status".into(), status.as_str().into());
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.header.insert(name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        self.header.append(name, value);
        self
    }
}

impl ReadResponse for Headers {
    fn status(&self) -> StatusCode {
        self.pseduo_head
            .get(":status")
            .and_then(|status| StatusCode::from_bytes(status.as_bytes()).ok())
            .expect("missing or invalid :status")
    }

    fn headers(&self) -> HeaderMap {
        self.header.clone()
    }
}

impl ReadRequest for Message {
    fn protocol(&self) -> Option<Arc<str>> {
        self.head.protocol()
    }

    fn method(&self) -> Method {
        self.head.method()
    }

    fn authority(&self) -> String {
        self.head.authority()
    }

    fn path(&self) -> String {
        self.head.path()
    }

    fn scheme(&self) -> String {
        self.head.scheme()
    }

    fn headers(&self) -> HeaderMap {
        ReadRequest::headers(&self.head)
    }
}

impl WriteRequest for Message {
    fn set_method(&mut self, method: Method) -> &mut Self {
        self.head.set_method(method);
        self
    }

    fn set_uri(&mut self, uri: Uri) -> &mut Self {
        self.head.set_uri(uri);
        self
    }

    fn set_protocol(&mut self, protocol: &str) -> &mut Self {
        self.head.set_protocol(protocol);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        WriteRequest::set_header(&mut self.head, name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        WriteRequest::append_header(&mut self.head, name, value);
        self
    }
}

impl WriteResponse for Message {
    fn set_status(&mut self, status: StatusCode) -> &mut Self {
        self.head.set_status(status);
        self
    }

    fn set_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        WriteResponse::set_header(&mut self.head, name, value);
        self
    }

    fn append_header(&mut self, name: HeaderName, value: HeaderValue) -> &mut Self {
        WriteResponse::append_header(&mut self.head, name, value);
        self
    }
}

impl ReadResponse for Message {
    fn status(&self) -> StatusCode {
        self.head.status()
    }

    fn headers(&self) -> HeaderMap {
        ReadResponse::headers(&self.head)
    }
}

impl Message {
    pub fn into_body(self) -> ArcWndBuf {
        self.body
    }
}

/// Read final HTTP/3 headers and return a shared streaming body.
/// Subsequent body and framing errors are reported through the body reader.
#[allow(async_fn_in_trait)]
pub trait ReadMeesage<P>: Sized {
    async fn read_message(self, qpack: ArcQpack) -> Result<P>;
}

/// Write HEADERS, DATA and FIN. Poll concurrently with a streaming body producer.
/// For responses, supply the original request method.
#[allow(async_fn_in_trait)]
pub trait WriteMessage<P>: Sized {
    async fn write_message(self, message: P, qpack: ArcQpack) -> Result<()>;
}
