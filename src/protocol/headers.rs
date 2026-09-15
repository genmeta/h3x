use std::str::from_utf8;

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, Version,
    header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TE, TRANSFER_ENCODING, UPGRADE},
    request::Parts as RequestParts,
    response::Parts as ResponseParts,
    uri::Authority,
};

use super::qpack::Field;
use crate::{Error, Result};

fn message_error<T>(_: T) -> Error {
    Error::H3_MESSAGE_ERROR
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let value = value.to_str().map_err(message_error)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    value.parse::<u64>().map(Some).map_err(message_error)
}

pub(crate) fn request_parts(fields: Vec<Field>) -> Result<RequestParts> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.iter().any(|field| {
        !matches!(
            field.name.as_ref(),
            b":method" | b":scheme" | b":authority" | b":path"
        )
    }) {
        return Err(Error::H3_MESSAGE_ERROR);
    }

    let method =
        Method::from_bytes(required_pseudo(&pseudo, b":method")?).map_err(message_error)?;
    let scheme = pseudo_value(&pseudo, b":scheme");
    let authority = pseudo_value(&pseudo, b":authority");
    let path = pseudo_value(&pseudo, b":path");
    let authority = validate_request_pseudo(&method, scheme, authority, path, &headers)?;

    let mut request = Request::builder()
        .method(method.clone())
        .uri(build_request_uri(&method, scheme, authority, path)?)
        .version(Version::HTTP_3)
        .body(())
        .map_err(message_error)?;
    *request.headers_mut() = headers;
    Ok(request.into_parts().0)
}

pub(crate) fn response_parts(fields: Vec<Field>) -> Result<ResponseParts> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.len() != 1 {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let status =
        StatusCode::from_bytes(required_pseudo(&pseudo, b":status")?).map_err(message_error)?;
    let mut response = Response::builder()
        .status(status)
        .version(Version::HTTP_3)
        .body(())
        .map_err(message_error)?;
    *response.headers_mut() = headers;
    Ok(response.into_parts().0)
}

pub(crate) fn trailer_fields(fields: Vec<Field>) -> Result<HeaderMap> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if !pseudo.is_empty() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    Ok(headers)
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
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if pseudo
                .iter()
                .any(|existing: &Field| existing.name == field.name)
            {
                return Err(Error::H3_MESSAGE_ERROR);
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
        return Err(Error::H3_MESSAGE_ERROR);
    }
    if name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    Ok(())
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
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let authority = required_utf8(authority, ":authority")?;
        let authority: Authority = authority.parse().map_err(message_error)?;
        if authority.port().is_none() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        return Ok(authority);
    }

    required_utf8(scheme, ":scheme")?;
    let path = required_bytes(path, ":path")?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let host = headers.get(HOST).map(HeaderValue::as_bytes);
    if let (Some(authority), Some(host)) = (authority, host)
        && authority != host
    {
        return Err(Error::H3_MESSAGE_ERROR);
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
    pseudo_value(pseudo, name).ok_or(Error::H3_MESSAGE_ERROR)
}

fn pseudo_value<'a>(pseudo: &'a [Field], name: &[u8]) -> Option<&'a [u8]> {
    pseudo
        .iter()
        .find(|field| field.name.as_ref() == name)
        .map(|field| field.value.as_ref())
}

fn required_bytes<'a>(value: Option<&'a [u8]>, _: &str) -> Result<&'a [u8]> {
    value.ok_or(Error::H3_MESSAGE_ERROR)
}

fn required_utf8<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a str> {
    from_utf8(required_bytes(value, name)?).map_err(message_error)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

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
                    let request = request_parts(request_fields(scheme, authority, host))
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
                    assert_eq!(request.version, Version::HTTP_3);
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
                        request_parts(request_fields(scheme, authority, host)),
                        Err(Error::H3_MESSAGE_ERROR)
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
                        request_parts(request_fields(b"https", authority, host)),
                        Err(Error::H3_MESSAGE_ERROR)
                    ),
                    "authority={authority:?}, host={host:?}"
                );
            }
        }
    }

    #[test]
    fn connect_requires_authority_with_port_without_host_fallback() {
        let request = request_parts(vec![
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
                request_parts(fields),
                Err(Error::H3_MESSAGE_ERROR)
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
        assert_eq!(request_parts(request).unwrap().uri, "https://example.com/");
        let response = response_parts(vec![Field {
            never_index: false,
            name: Bytes::from_static(b":status"),
            value: Bytes::from_static(b"200"),
        }])
        .unwrap();
        assert_eq!(response.status, StatusCode::OK);

        let mut headers = HeaderMap::new();
        assert_eq!(content_length(&headers).unwrap(), None);
        headers.append(CONTENT_LENGTH, "5".parse().unwrap());
        assert_eq!(content_length(&headers).unwrap(), Some(5));
        headers.append(CONTENT_LENGTH, "5".parse().unwrap());
        assert!(matches!(
            content_length(&headers),
            Err(Error::H3_MESSAGE_ERROR)
        ));

        for value in ["5, 5", "5, 6", "", "+5", "-5", "5x", "18446744073709551616"] {
            headers.insert(CONTENT_LENGTH, value.parse().unwrap());
            assert!(
                matches!(content_length(&headers), Err(Error::H3_MESSAGE_ERROR)),
                "{value:?}"
            );
        }
    }
}
