use std::str::from_utf8;

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TE, TRANSFER_ENCODING, UPGRADE},
    uri::Authority,
};

use crate::{Error, ErrorCode, Result, protocol::qpack::Field};

/// Validated request metadata. HTTP/3 pseudo-headers are represented by their
/// typed HTTP equivalents; `headers` contains ordinary fields only.
#[derive(Clone, Debug)]
pub(crate) struct RequestHead {
    pub(crate) extensions: http::Extensions,
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) headers: HeaderMap,
}

/// Response metadata. `status` is unset only while an outgoing response is
/// being built; decoded responses always contain `:status`. `headers` contains
/// ordinary fields only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResponseHead {
    pub(crate) status: Option<StatusCode>,
    pub(crate) headers: HeaderMap,
}

impl ResponseHead {
    pub(crate) fn status(&self) -> Result<StatusCode> {
        self.status
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.with_reason("response is missing :status"))
    }
}

fn message_error<T: std::error::Error + Send + Sync + 'static>(error: T) -> Error {
    ErrorCode::H3_MESSAGE_ERROR.with_reason(format!("invalid HTTP field: {error}"))
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("multiple Content-Length fields are not allowed"));
    }
    let value = value.to_str().map_err(message_error)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("Content-Length must contain only decimal digits"));
    }
    value.parse::<u64>().map(Some).map_err(message_error)
}

/// Parse and validate an HTTP/3 request field section.
pub(crate) fn be_request(fields: Vec<Field>) -> Result<RequestHead> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.iter().any(|field| {
        !matches!(
            field.name.as_ref(),
            b":method" | b":scheme" | b":authority" | b":path" | b":protocol"
        )
    }) {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("request contains an unsupported pseudo-header"));
    }

    let method =
        Method::from_bytes(required_pseudo(&pseudo, b":method")?).map_err(message_error)?;
    let scheme = pseudo_value(&pseudo, b":scheme");
    let authority = pseudo_value(&pseudo, b":authority");
    let path = pseudo_value(&pseudo, b":path");
    let mut extensions = http::Extensions::new();
    let protocol = pseudo_value(&pseudo, b":protocol");
    if let Some(protocol) = protocol {
        if method != Method::CONNECT || authority.is_none() {
            return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("invalid Extended CONNECT"));
        }
        extensions.insert(crate::ext::Protocol::new(
            from_utf8(protocol).map_err(message_error)?,
        )?);
    }
    let semantic_method = if protocol.is_some() {
        &Method::GET
    } else {
        &method
    };
    let authority = validate_request_pseudo(semantic_method, scheme, authority, path, &headers)?;
    if authority.as_str().contains('@') {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("userinfo is forbidden"));
    }
    let uri = build_request_uri(semantic_method, scheme, authority, path)?;

    Ok(RequestHead {
        uri,
        extensions,
        method,
        headers,
    })
}

/// Parse and validate an HTTP/3 response field section.
pub(crate) fn be_response(fields: Vec<Field>) -> Result<ResponseHead> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.len() != 1 {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("response must contain exactly one :status pseudo-header"));
    }
    let status =
        StatusCode::from_bytes(required_pseudo(&pseudo, b":status")?).map_err(message_error)?;
    Ok(ResponseHead {
        status: Some(status),
        headers,
    })
}

/// Parse and validate an HTTP/3 trailer field section.
pub(crate) fn be_trailers(fields: Vec<Field>) -> Result<HeaderMap> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if !pseudo.is_empty() {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.with_reason("trailers must not contain pseudo-headers")
        );
    }
    Ok(headers)
}

/// Write typed HTTP metadata as QPACK input fields.
pub(crate) trait Write {
    /// Write one complete request field section into an empty field vector.
    fn put_request(&mut self, head: &RequestHead) -> Result<()>;

    /// Write one complete response field section into an empty field vector.
    fn put_response(&mut self, head: &ResponseHead) -> Result<()>;
}

impl Write for Vec<Field> {
    fn put_request(&mut self, head: &RequestHead) -> Result<()> {
        require_empty(self)?;
        validate_regular_headers(&head.headers)?;
        let RequestPseudo {
            scheme,
            authority,
            path,
        } = request_pseudo(head)?;

        self.reserve(4 + head.headers.len());
        self.push(pseudo_field(b":method", head.method.as_str().as_bytes()));
        if let Some(scheme) = scheme {
            self.push(pseudo_field(b":scheme", scheme));
        }
        self.push(pseudo_field(b":authority", authority));
        if let Some(path) = path {
            self.push(pseudo_field(b":path", path));
        }
        if let Some(protocol) = head.extensions.get::<crate::ext::Protocol>() {
            self.push(pseudo_field(b":protocol", protocol.as_str().as_bytes()));
        }
        put_regular_headers(self, &head.headers);
        Ok(())
    }

    fn put_response(&mut self, head: &ResponseHead) -> Result<()> {
        require_empty(self)?;
        validate_regular_headers(&head.headers)?;
        self.reserve(1 + head.headers.len());
        self.push(pseudo_field(b":status", head.status()?.as_str().as_bytes()));
        put_regular_headers(self, &head.headers);
        Ok(())
    }
}

fn require_empty(fields: &[Field]) -> Result<()> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("field section output must be empty before encoding"))
    }
}

struct ParsedFields {
    pseudo: Vec<Field>,
    headers: HeaderMap,
}

fn parse_fields(fields: Vec<Field>) -> Result<ParsedFields> {
    let mut pseudo = Vec::new();
    let mut headers = HeaderMap::new();
    let mut regular_seen = false;

    for field in fields {
        if field.name.starts_with(b":") {
            if regular_seen {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .with_reason("pseudo-header appears after a regular header"));
            }
            if pseudo
                .iter()
                .any(|existing: &Field| existing.name == field.name)
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("duplicate pseudo-header"));
            }
            pseudo.push(field);
            continue;
        }

        regular_seen = true;
        let name = HeaderName::from_lowercase(&field.name).map_err(message_error)?;
        let mut value = HeaderValue::from_bytes(&field.value).map_err(message_error)?;
        value.set_sensitive(field.never_index);
        validate_regular_field(&name, &value)?;
        headers.append(name, value);
    }

    if headers.get_all(COOKIE).iter().nth(1).is_some() {
        let never_index = headers
            .get_all(COOKIE)
            .iter()
            .any(HeaderValue::is_sensitive);
        let cookies = headers
            .get_all(COOKIE)
            .iter()
            .map(HeaderValue::as_bytes)
            .collect::<Vec<_>>()
            .join(b"; ".as_slice());
        let mut value = HeaderValue::from_bytes(&cookies).map_err(message_error)?;
        value.set_sensitive(never_index);
        headers.insert(COOKIE, value);
    }
    Ok(ParsedFields { pseudo, headers })
}

fn validate_regular_field(name: &HeaderName, value: &HeaderValue) -> Result<()> {
    if matches!(name, &CONNECTION | &TRANSFER_ENCODING | &UPGRADE)
        || matches!(name.as_str(), "proxy-connection" | "keep-alive")
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("connection-specific header is forbidden in HTTP/3"));
    }
    if name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("TE must have the value trailers"));
    }
    Ok(())
}

fn validate_regular_headers(headers: &HeaderMap) -> Result<()> {
    for (name, value) in headers {
        validate_regular_field(name, value)?;
    }
    Ok(())
}

struct RequestPseudo<'a> {
    scheme: Option<&'a [u8]>,
    authority: &'a [u8],
    path: Option<&'a [u8]>,
}

fn request_pseudo(head: &RequestHead) -> Result<RequestPseudo<'_>> {
    let scheme = head.uri.scheme_str().map(str::as_bytes);
    let authority = head.uri.authority().ok_or_else(|| {
        ErrorCode::H3_MESSAGE_ERROR.with_reason("request URI is missing authority")
    })?;
    let authority = authority.as_str().as_bytes();
    let path = head
        .uri
        .path_and_query()
        .map(|value| value.as_str().as_bytes());

    let protocol = head.extensions.get::<crate::ext::Protocol>();
    if protocol.is_some() && head.method != Method::CONNECT {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason(":protocol requires CONNECT"));
    }
    if authority.contains(&b'@') {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("userinfo is forbidden"));
    }
    if head.method == Method::CONNECT && protocol.is_none() {
        if scheme.is_some() || path.is_some() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("CONNECT must not include :scheme or :path"));
        }
        if head.uri.authority().unwrap().port().is_none() {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.with_reason("CONNECT authority is missing a port")
            );
        }
        return Ok(RequestPseudo {
            scheme: None,
            authority,
            path: None,
        });
    }

    let scheme = scheme
        .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.with_reason("request URI is missing scheme"))?;
    let path =
        path.ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.with_reason("request URI is missing path"))?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.with_reason("request path must be * or start with /")
        );
    }
    if head
        .headers
        .get(HOST)
        .is_some_and(|host| host.as_bytes() != authority)
    {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.with_reason("Host does not match request authority")
        );
    }
    Ok(RequestPseudo {
        scheme: Some(scheme),
        authority,
        path: Some(path),
    })
}

fn pseudo_field(name: &'static [u8], value: &[u8]) -> Field {
    Field {
        name: Bytes::from_static(name),
        value: Bytes::copy_from_slice(value),
        never_index: false,
    }
}

fn put_regular_headers(fields: &mut Vec<Field>, headers: &HeaderMap) {
    fields.extend(headers.iter().map(|(name, value)| Field {
        name: Bytes::copy_from_slice(name.as_str().as_bytes()),
        value: Bytes::copy_from_slice(value.as_bytes()),
        never_index: value.is_sensitive(),
    }));
}

fn validate_request_pseudo(
    method: &Method,
    scheme: Option<&[u8]>,
    authority: Option<&[u8]>,
    path: Option<&[u8]>,
    headers: &HeaderMap,
) -> Result<Authority> {
    if method == Method::CONNECT {
        if scheme.is_some() || path.is_some() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("CONNECT must not include :scheme or :path"));
        }
        let authority = required_utf8(authority, ":authority")?;
        let authority: Authority = authority.parse().map_err(message_error)?;
        if authority.port().is_none() {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.with_reason("CONNECT authority is missing a port")
            );
        }
        return Ok(authority);
    }

    required_utf8(scheme, ":scheme")?;
    let path = required_bytes(path, ":path")?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.with_reason("request path must be * or start with /")
        );
    }
    let host = headers.get(HOST).map(HeaderValue::as_bytes);
    if let (Some(authority), Some(host)) = (authority, host)
        && authority != host
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("Host does not match :authority"));
    }
    required_utf8(authority.or(host), ":authority")?
        .parse()
        .map_err(message_error)
}

fn build_request_uri(
    method: &Method,
    scheme: Option<&[u8]>,
    authority: Authority,
    path: Option<&[u8]>,
) -> Result<Uri> {
    let builder = Uri::builder().authority(authority);
    if method == Method::CONNECT {
        return builder.build().map_err(message_error);
    }

    builder
        .scheme(required_utf8(scheme, ":scheme")?)
        .path_and_query(required_utf8(path, ":path")?)
        .build()
        .map_err(message_error)
}

fn required_pseudo<'a>(pseudo: &'a [Field], name: &[u8]) -> Result<&'a [u8]> {
    pseudo_value(pseudo, name).ok_or_else(|| {
        ErrorCode::H3_MESSAGE_ERROR.with_reason(format!(
            "missing pseudo-header {}",
            String::from_utf8_lossy(name)
        ))
    })
}

fn pseudo_value<'a>(pseudo: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    pseudo
        .iter()
        .find(|field| field.name.as_ref() == name)
        .map(|field| field.value.as_ref())
}

fn required_bytes<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a [u8]> {
    value.ok_or_else(|| {
        ErrorCode::H3_MESSAGE_ERROR.with_reason(format!("missing pseudo-header {name}"))
    })
}

fn required_utf8<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a str> {
    from_utf8(required_bytes(value, name)?).map_err(message_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &'static [u8], value: &'static [u8]) -> Field {
        Field {
            never_index: false,
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        }
    }

    fn request_fields(
        scheme: &'static [u8],
        authority: Option<&'static [u8]>,
        host: Option<&'static [u8]>,
    ) -> Vec<Field> {
        let mut fields = vec![
            field(b":method", b"GET"),
            field(b":scheme", scheme),
            field(b":path", b"/"),
        ];
        if let Some(authority) = authority {
            fields.push(field(b":authority", authority));
        }
        if let Some(host) = host {
            fields.push(field(b"host", host));
        }
        fields
    }

    #[test]
    fn typed_heads_round_trip_through_fields() {
        let request = be_request(vec![
            field(b":method", b"POST"),
            field(b":scheme", b"https"),
            field(b":authority", b"example.com"),
            field(b":path", b"/upload?q=1"),
            field(b"content-type", b"application/octet-stream"),
        ])
        .unwrap();
        let mut request_fields = Vec::new();
        request_fields.put_request(&request).unwrap();
        assert_eq!(
            request_fields
                .iter()
                .map(|field| field.name.as_ref())
                .collect::<Vec<_>>(),
            [
                b":method".as_slice(),
                b":scheme",
                b":authority",
                b":path",
                b"content-type",
            ]
        );
        let decoded = be_request(request_fields).unwrap();
        assert_eq!(decoded.method, request.method);
        assert_eq!(decoded.uri, request.uri);
        assert_eq!(decoded.headers, request.headers);

        let mut sensitive = HeaderValue::from_static("session=secret");
        sensitive.set_sensitive(true);
        let mut response = ResponseHead {
            status: Some(StatusCode::CREATED),
            headers: HeaderMap::new(),
        };
        response.headers.append("set-cookie", sensitive);
        let mut response_fields = Vec::new();
        response_fields.put_response(&response).unwrap();
        assert_eq!(response_fields[0].name, ":status");
        assert!(response_fields[1].never_index);
        assert_eq!(be_response(response_fields).unwrap(), response);
    }

    #[test]
    fn put_rejects_invalid_typed_heads_without_partial_output() {
        let mut request = RequestHead {
            extensions: http::Extensions::new(),
            method: Method::GET,
            uri: "/relative".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        let mut fields = Vec::new();
        assert!(matches!(
            fields.put_request(&request),
            Err(h3x::Error {
                code: ErrorCode::H3_MESSAGE_ERROR,
                ..
            })
        ));
        assert!(fields.is_empty());

        request.uri = "https://example.com/".parse().unwrap();
        request
            .headers
            .insert(CONNECTION, HeaderValue::from_static("close"));
        assert!(matches!(
            fields.put_request(&request),
            Err(h3x::Error {
                code: ErrorCode::H3_MESSAGE_ERROR,
                ..
            })
        ));
        assert!(fields.is_empty());

        let response = ResponseHead::default();
        assert!(matches!(
            fields.put_response(&response),
            Err(h3x::Error {
                code: ErrorCode::H3_MESSAGE_ERROR,
                ..
            })
        ));
        assert!(fields.is_empty());

        fields.push(field(b"x-existing", b"value"));
        let response = ResponseHead {
            status: Some(StatusCode::OK),
            headers: HeaderMap::new(),
        };
        assert!(matches!(
            fields.put_response(&response),
            Err(h3x::Error {
                code: ErrorCode::H3_MESSAGE_ERROR,
                ..
            })
        ));
        assert_eq!(fields.len(), 1);
    }

    #[test]
    fn builds_request_uri_from_authority_or_host() {
        for scheme in [b"http".as_slice(), b"https"] {
            for value in [
                b"example.com".as_slice(),
                b"example.com:8443",
                b"[2001:db8::1]:8443",
            ] {
                for (authority, host) in [
                    (Some(value), None),
                    (None, Some(value)),
                    (Some(value), Some(value)),
                ] {
                    let request = be_request(request_fields(scheme, authority, host))
                        .unwrap_or_else(|error| {
                            panic!("scheme={scheme:?}, authority={authority:?}, host={host:?}: {error:?}")
                        });
                    assert_eq!(
                        request.uri.to_string(),
                        format!(
                            "{}://{}/",
                            from_utf8(scheme).unwrap(),
                            from_utf8(value).unwrap()
                        )
                    );
                    assert_eq!(request.method, Method::GET);
                    assert_eq!(request.headers.get(HOST).map(HeaderValue::as_bytes), host);
                }
            }
        }
    }

    #[test]
    fn rejects_missing_empty_or_conflicting_request_authority() {
        let empty = b"".as_slice();
        let valid = b"example.com".as_slice();
        for scheme in [b"http".as_slice(), b"https"] {
            for (authority, host) in [
                (None, None),
                (Some(empty), None),
                (None, Some(empty)),
                (Some(empty), Some(empty)),
                (Some(empty), Some(valid)),
                (Some(valid), Some(empty)),
                (Some(valid), Some(b"other.example.com".as_slice())),
                (Some(valid), Some(b"example.com:443".as_slice())),
            ] {
                assert!(
                    matches!(
                        be_request(request_fields(scheme, authority, host)),
                        Err(h3x::Error {
                            code: ErrorCode::H3_MESSAGE_ERROR,
                            ..
                        })
                    ),
                    "scheme={scheme:?}, authority={authority:?}, host={host:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_request_authority_or_host() {
        for value in [
            b"bad host".as_slice(),
            b"example.com/path",
            b"example.com?query",
            b"example.com#fragment",
            b"[::1",
            b"\xff",
        ] {
            for (authority, host) in [
                (Some(value), None),
                (None, Some(value)),
                (Some(value), Some(value)),
            ] {
                assert!(
                    matches!(
                        be_request(request_fields(b"https", authority, host)),
                        Err(h3x::Error {
                            code: ErrorCode::H3_MESSAGE_ERROR,
                            ..
                        })
                    ),
                    "authority={authority:?}, host={host:?}"
                );
            }
        }
    }

    #[test]
    fn connect_requires_authority_with_port_without_host_fallback() {
        let request = be_request(vec![
            field(b":method", b"CONNECT"),
            field(b":authority", b"example.com:443"),
        ])
        .unwrap();
        assert_eq!(request.uri, "example.com:443");
        assert_eq!(request.uri.scheme(), None);
        assert_eq!(request.uri.path_and_query(), None);

        for fields in [
            vec![
                field(b":method", b"CONNECT"),
                field(b"host", b"example.com:443"),
            ],
            vec![
                field(b":method", b"CONNECT"),
                field(b":authority", b"example.com"),
            ],
        ] {
            assert!(matches!(
                be_request(fields),
                Err(h3x::Error {
                    code: ErrorCode::H3_MESSAGE_ERROR,
                    ..
                })
            ));
        }
    }

    #[test]
    fn validates_request_response_and_content_length() {
        let request = vec![
            Field {
                never_index: false,
                name: Bytes::from_static(b":method"),
                value: Bytes::from_static(b"GET"),
            },
            Field {
                never_index: false,
                name: Bytes::from_static(b":scheme"),
                value: Bytes::from_static(b"https"),
            },
            Field {
                never_index: false,
                name: Bytes::from_static(b":authority"),
                value: Bytes::from_static(b"example.com"),
            },
            Field {
                never_index: false,
                name: Bytes::from_static(b":path"),
                value: Bytes::from_static(b"/"),
            },
        ];
        assert_eq!(be_request(request).unwrap().uri, "https://example.com/");
        let response = be_response(vec![Field {
            never_index: false,
            name: Bytes::from_static(b":status"),
            value: Bytes::from_static(b"200"),
        }])
        .unwrap();
        assert_eq!(response.status().unwrap(), StatusCode::OK);

        let mut headers = HeaderMap::new();
        assert_eq!(content_length(&headers).unwrap(), None);
        headers.append(CONTENT_LENGTH, "5".parse().unwrap());
        assert_eq!(content_length(&headers).unwrap(), Some(5));
        headers.append(CONTENT_LENGTH, "5".parse().unwrap());
        assert!(matches!(
            content_length(&headers),
            Err(h3x::Error {
                code: ErrorCode::H3_MESSAGE_ERROR,
                ..
            })
        ));

        for value in ["5, 5", "5, 6", "", "+5", "-5", "5x", "18446744073709551616"] {
            headers.insert(CONTENT_LENGTH, value.parse().unwrap());
            assert!(
                matches!(
                    content_length(&headers),
                    Err(h3x::Error {
                        code: ErrorCode::H3_MESSAGE_ERROR,
                        ..
                    })
                ),
                "{value:?}"
            );
        }
    }
}

#[cfg(test)]
mod connect_tests {
    use super::*;
    use crate::{ReadRequest, client};

    #[test]
    fn websocket_urls_and_protocol_fields_round_trip() {
        for (url, scheme, authority, path) in [
            ("ws://example.com", "http", "example.com", "/"),
            (
                "WS://localhost:8765/Api?Token=AbC",
                "http",
                "localhost:8765",
                "/Api?Token=AbC",
            ),
            (
                "WsS://example.com:443/Api?Token=AbC",
                "https",
                "example.com:443",
                "/Api?Token=AbC",
            ),
            (
                "wss://example.com/chat?q=%2F",
                "https",
                "example.com",
                "/chat?q=%2F",
            ),
            ("ws://[::1]:8080/%2f?a=b", "http", "[::1]:8080", "/%2f?a=b"),
        ] {
            let request = client::Request::connect(url).unwrap();
            assert_eq!(request.scheme(), scheme);
            assert_eq!(request.authority(), authority);
            assert_eq!(request.path(), path);
            assert_eq!(request.protocol().unwrap().as_str(), "websocket");
            assert_eq!(request.headers()["sec-websocket-version"], "13");
            assert!(!request.headers().contains_key("sec-websocket-key"));
            let head = request.message.head.lock().unwrap();
            let mut fields = Vec::new();
            fields.put_request(&head).unwrap();
            let decoded = be_request(fields.clone()).unwrap();
            assert_eq!(decoded.uri, head.uri);
            assert_eq!(decoded.protocol(), head.protocol());
            fields[0].value = Bytes::from_static(b"GET");
            assert!(be_request(fields).is_err());
        }
        for url in [
            "ws://user@example.com/",
            "ws://example.com/#frag",
            "wss:///",
            "ws://[::1",
        ] {
            assert!(client::Request::connect(url).is_err(), "{url}");
        }
        let request = client::Request::connect("[::1]:443").unwrap();
        assert!(request.protocol().is_none());
        assert_eq!(request.path(), "");
        for protocol in ["", "web socket", "websocket\r\n", "web/socket", "中文"] {
            assert!(crate::ext::Protocol::new(protocol).is_err());
        }
    }

    #[test]
    fn extended_connect_requires_every_pseudo_header() {
        let request = client::Request::connect("ws://example.com/").unwrap();
        let mut fields = Vec::new();
        fields
            .put_request(&request.message.head.lock().unwrap())
            .unwrap();
        for name in [b":scheme".as_slice(), b":authority", b":path"] {
            let mut missing = fields.clone();
            missing.retain(|f| f.name.as_ref() != name);
            assert!(be_request(missing).is_err());
        }
        let mut duplicate = fields.clone();
        duplicate.insert(
            0,
            fields
                .iter()
                .find(|f| f.name == ":protocol")
                .unwrap()
                .clone(),
        );
        assert!(be_request(duplicate).is_err());
        let mut head = request.message.head.lock().unwrap().clone();
        head.method = Method::GET;
        assert!(Vec::new().put_request(&head).is_err());
    }
}
