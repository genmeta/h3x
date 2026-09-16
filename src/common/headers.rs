use std::str::from_utf8;

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TE, TRANSFER_ENCODING, UPGRADE},
    uri::Authority,
};

use crate::{ErrorCode, Result, protocol::qpack::Field};

/// Validated request metadata. HTTP/3 pseudo-headers are represented by their
/// typed HTTP equivalents; `headers` contains ordinary fields only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestHead {
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
        self.status.ok_or(ErrorCode::H3_MESSAGE_ERROR)
    }
}

fn message_error<T>(_: T) -> ErrorCode {
    ErrorCode::H3_MESSAGE_ERROR
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    let value = value.to_str().map_err(message_error)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    value.parse::<u64>().map(Some).map_err(message_error)
}

/// Parse and validate an HTTP/3 request field section.
pub(crate) fn be_request(fields: Vec<Field>) -> Result<RequestHead> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.iter().any(|field| {
        !matches!(
            field.name.as_ref(),
            b":method" | b":scheme" | b":authority" | b":path"
        )
    }) {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }

    let method =
        Method::from_bytes(required_pseudo(&pseudo, b":method")?).map_err(message_error)?;
    let scheme = pseudo_value(&pseudo, b":scheme");
    let authority = pseudo_value(&pseudo, b":authority");
    let path = pseudo_value(&pseudo, b":path");
    let authority = validate_request_pseudo(&method, scheme, authority, path, &headers)?;

    Ok(RequestHead {
        uri: build_request_uri(&method, scheme, authority, path)?,
        method,
        headers,
    })
}

/// Parse and validate an HTTP/3 response field section.
pub(crate) fn be_response(fields: Vec<Field>) -> Result<ResponseHead> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.len() != 1 {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
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
        return Err(ErrorCode::H3_MESSAGE_ERROR);
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
        Err(ErrorCode::H3_MESSAGE_ERROR)
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
                return Err(ErrorCode::H3_MESSAGE_ERROR);
            }
            if pseudo
                .iter()
                .any(|existing: &Field| existing.name == field.name)
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR);
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
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    if name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
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
    let authority = head.uri.authority().ok_or(ErrorCode::H3_MESSAGE_ERROR)?;
    let authority = authority.as_str().as_bytes();
    let path = head
        .uri
        .path_and_query()
        .map(|value| value.as_str().as_bytes());

    if head.method == Method::CONNECT {
        if scheme.is_some() || path.is_some() {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        if head.uri.authority().unwrap().port().is_none() {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        return Ok(RequestPseudo {
            scheme: None,
            authority,
            path: None,
        });
    }

    let scheme = scheme.ok_or(ErrorCode::H3_MESSAGE_ERROR)?;
    let path = path.ok_or(ErrorCode::H3_MESSAGE_ERROR)?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    if head
        .headers
        .get(HOST)
        .is_some_and(|host| host.as_bytes() != authority)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
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
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        let authority = required_utf8(authority, ":authority")?;
        let authority: Authority = authority.parse().map_err(message_error)?;
        if authority.port().is_none() {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        return Ok(authority);
    }

    required_utf8(scheme, ":scheme")?;
    let path = required_bytes(path, ":path")?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    let host = headers.get(HOST).map(HeaderValue::as_bytes);
    if let (Some(authority), Some(host)) = (authority, host)
        && authority != host
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
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
    pseudo_value(pseudo, name).ok_or(ErrorCode::H3_MESSAGE_ERROR)
}

fn pseudo_value<'a>(pseudo: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    pseudo
        .iter()
        .find(|field| field.name.as_ref() == name)
        .map(|field| field.value.as_ref())
}

fn required_bytes<'a>(value: Option<&'a [u8]>, _: &str) -> Result<&'a [u8]> {
    value.ok_or(ErrorCode::H3_MESSAGE_ERROR)
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
        assert_eq!(be_request(request_fields).unwrap(), request);

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
            method: Method::GET,
            uri: "/relative".parse().unwrap(),
            headers: HeaderMap::new(),
        };
        let mut fields = Vec::new();
        assert!(matches!(
            fields.put_request(&request),
            Err(ErrorCode::H3_MESSAGE_ERROR)
        ));
        assert!(fields.is_empty());

        request.uri = "https://example.com/".parse().unwrap();
        request
            .headers
            .insert(CONNECTION, HeaderValue::from_static("close"));
        assert!(matches!(
            fields.put_request(&request),
            Err(ErrorCode::H3_MESSAGE_ERROR)
        ));
        assert!(fields.is_empty());

        let response = ResponseHead::default();
        assert!(matches!(
            fields.put_response(&response),
            Err(ErrorCode::H3_MESSAGE_ERROR)
        ));
        assert!(fields.is_empty());

        fields.push(field(b"x-existing", b"value"));
        let response = ResponseHead {
            status: Some(StatusCode::OK),
            headers: HeaderMap::new(),
        };
        assert!(matches!(
            fields.put_response(&response),
            Err(ErrorCode::H3_MESSAGE_ERROR)
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
                        Err(ErrorCode::H3_MESSAGE_ERROR)
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
                        Err(ErrorCode::H3_MESSAGE_ERROR)
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
            assert!(matches!(be_request(fields), Err(ErrorCode::H3_MESSAGE_ERROR)));
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
            Err(ErrorCode::H3_MESSAGE_ERROR)
        ));

        for value in ["5, 5", "5, 6", "", "+5", "-5", "5x", "18446744073709551616"] {
            headers.insert(CONTENT_LENGTH, value.parse().unwrap());
            assert!(
                matches!(content_length(&headers), Err(ErrorCode::H3_MESSAGE_ERROR)),
                "{value:?}"
            );
        }
    }
}
