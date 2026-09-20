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

#[cfg(test)]
mod tests {
    use http::header::{ACCEPT, CONTENT_TYPE};

    use super::*;
    use crate::{
        common::{Read, Write, request::Request, response::Response},
        connection::Settings,
    };

    fn body() -> ArcWndBuf {
        ArcWndBuf::new(32)
    }

    #[test]
    fn request_headers_and_http_parts_round_trip() {
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri("wss://example.com:443/chat?q=1")
            .header(CONTENT_TYPE, "text/plain")
            .body(body())
            .unwrap();
        request
            .extensions_mut()
            .insert::<Arc<str>>(Arc::from("websocket"));

        let mut request = Request::<Write>::from(request);
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.authority(), "example.com:443");
        assert_eq!(request.path(), "/chat?q=1");
        assert_eq!(request.scheme(), "wss");
        assert_eq!(request.protocol().as_deref(), Some("websocket"));
        assert_eq!(request.headers()[CONTENT_TYPE], "text/plain");

        request
            .set_method(Method::CONNECT)
            .set_protocol("websocket")
            .set_header(ACCEPT, HeaderValue::from_static("text/html"))
            .append_header(ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(request.scheme(), "https");
        request.set_uri("ws://other.example/socket".parse().unwrap());
        assert_eq!(request.scheme(), "http");
        assert_eq!(request.authority(), "other.example");

        let standard: http::Request<ArcWndBuf> = request.into();
        assert_eq!(standard.version(), http::Version::HTTP_3);
        assert_eq!(standard.method(), Method::CONNECT);
        assert_eq!(standard.uri(), "http://other.example/socket");
        assert_eq!(
            standard.extensions().get::<Arc<str>>().unwrap().as_ref(),
            "websocket"
        );
        assert_eq!(standard.headers().get_all(ACCEPT).iter().count(), 2);

        let wrapper =
            Request::<Read>::from(Message::from_parts(standard.into_parts().0.into(), body()));
        let _: ArcWndBuf = wrapper.into_body();
    }

    #[test]
    fn response_headers_and_http_parts_round_trip() {
        let standard = http::Response::builder()
            .status(StatusCode::CREATED)
            .header(CONTENT_TYPE, "application/json")
            .body(body())
            .unwrap();
        let mut response = Response::<Write>::from(standard);
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            ReadResponse::headers(&response)[CONTENT_TYPE],
            "application/json"
        );
        response
            .set_status(StatusCode::ACCEPTED)
            .set_header(ACCEPT, HeaderValue::from_static("text/plain"))
            .append_header(ACCEPT, HeaderValue::from_static("text/html"));

        let standard: http::Response<ArcWndBuf> = response.into();
        assert_eq!(standard.status(), StatusCode::ACCEPTED);
        assert_eq!(standard.version(), http::Version::HTTP_3);
        assert_eq!(standard.headers().get_all(ACCEPT).iter().count(), 2);
        let wrapper =
            Response::<Read>::from(Message::from_parts(standard.into_parts().0.into(), body()));
        let _: ArcWndBuf = wrapper.into_body();
    }

    #[test]
    fn direct_message_traits_delegate_to_headers() {
        let mut message = Message::from_parts(Headers::default(), body());
        message
            .set_method(Method::PATCH)
            .set_uri("https://example.test/a".parse().unwrap())
            .set_protocol("custom");
        WriteRequest::set_header(&mut message, CONTENT_TYPE, HeaderValue::from_static("a/b"));
        WriteRequest::append_header(&mut message, CONTENT_TYPE, HeaderValue::from_static("c/d"));
        assert_eq!(message.method(), Method::PATCH);
        assert_eq!(message.authority(), "example.test");
        assert_eq!(message.path(), "/a");
        assert_eq!(message.scheme(), "https");
        assert_eq!(message.protocol().as_deref(), Some("custom"));
        assert_eq!(
            ReadRequest::headers(&message)
                .get_all(CONTENT_TYPE)
                .iter()
                .count(),
            2
        );

        message.set_status(StatusCode::NO_CONTENT);
        WriteResponse::set_header(&mut message, ACCEPT, HeaderValue::from_static("one"));
        WriteResponse::append_header(&mut message, ACCEPT, HeaderValue::from_static("two"));
        assert_eq!(message.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            ReadResponse::headers(&message)
                .get_all(ACCEPT)
                .iter()
                .count(),
            2
        );
        let _: ArcWndBuf = message.into_body();
    }

    #[tokio::test]
    async fn header_qpack_codec_preserves_pseudo_regular_and_sensitive_fields() {
        let qpack = ArcQpack::new(&Settings::default()).unwrap();
        let mut headers = Headers::default();
        headers.set_method(Method::GET);
        headers.set_uri("https://example.test/path".parse().unwrap());
        let mut sensitive = HeaderValue::from_static("secret");
        sensitive.set_sensitive(true);
        WriteRequest::set_header(&mut headers, http::header::AUTHORIZATION, sensitive);
        WriteRequest::append_header(&mut headers, ACCEPT, HeaderValue::from_static("text/plain"));

        let frame = headers.encode_headers(4, &qpack).unwrap();
        let decoded = Headers::decode_headers(4, frame, &qpack).await.unwrap();
        assert_eq!(decoded.method(), Method::GET);
        assert_eq!(decoded.authority(), "example.test");
        assert_eq!(decoded.path(), "/path");
        assert!(decoded.header[http::header::AUTHORIZATION].is_sensitive());
        assert_eq!(decoded.header[ACCEPT], "text/plain");
    }

    #[tokio::test]
    async fn malformed_decoded_fields_and_response_status_are_message_errors() {
        let qpack = ArcQpack::new(&Settings::default()).unwrap();
        for fields in [
            vec![Field {
                name: Bytes::from_static(b":bad"),
                value: Bytes::from_static(&[0xff]),
                never_index: false,
            }],
            vec![Field {
                name: Bytes::from_static(b"bad header"),
                value: Bytes::from_static(b"value"),
                never_index: false,
            }],
            vec![Field {
                name: Bytes::from_static(b"x-test"),
                value: Bytes::from_static(b"\n"),
                never_index: false,
            }],
        ] {
            let field_section = qpack.encode(8, fields).unwrap();
            let error = Headers::decode_headers(
                8,
                Frame::new(frame::Headers { field_section }).unwrap(),
                &qpack,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
        }

        let mut headers = Headers::default();
        assert_eq!(
            headers.response_status().unwrap_err().code,
            ErrorCode::H3_MESSAGE_ERROR
        );
        headers
            .pseduo_head
            .insert(":status".into(), "invalid".into());
        assert_eq!(
            headers.response_status().unwrap_err().code,
            ErrorCode::H3_MESSAGE_ERROR
        );
        headers.pseduo_head.insert(":status".into(), "204".into());
        assert_eq!(headers.response_status().unwrap(), StatusCode::NO_CONTENT);
    }

    #[test]
    fn pseudo_header_lists_are_role_specific() {
        assert_eq!(
            Request::<Read>::pesudo_headers(),
            &[":method", ":scheme", ":authority", ":path", ":protocol"]
        );
        assert_eq!(Response::<Read>::pesudo_headers(), &[":status"]);
    }
}
