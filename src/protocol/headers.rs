use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{CONNECTION, HOST, TE, TRANSFER_ENCODING, UPGRADE},
};

use super::qpack::Field;
use crate::{Code, Error};

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>, Error> {
    let mut parsed = None;
    for value in headers.get_all(http::header::CONTENT_LENGTH) {
        let value = value
            .to_str()
            .map_err(message_source("invalid Content-Length"))?;
        for item in value.split(',') {
            let item = item.trim_matches([' ', '\t']);
            if item.is_empty() || !item.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(message_error("Content-Length must contain decimal digits"));
            }
            let value = item
                .parse::<u64>()
                .map_err(message_source("Content-Length overflow"))?;
            if parsed.is_some_and(|previous| previous != value) {
                return Err(message_error("conflicting Content-Length values"));
            }
            parsed = Some(value);
        }
    }
    Ok(parsed)
}

pub(crate) fn request_fields(parts: http::request::Parts) -> Result<Vec<Field>, Error> {
    let http::request::Parts {
        method,
        uri,
        headers,
        #[cfg(feature = "webtransport")]
        extensions,
        #[cfg(not(feature = "webtransport"))]
            extensions: _,
        version: _,
        ..
    } = parts;
    #[cfg(feature = "webtransport")]
    let protocol = extensions
        .get::<crate::webtransport::ProtocolMarker>()
        .map(|_| crate::webtransport::PROTOCOL.as_bytes());
    #[cfg(not(feature = "webtransport"))]
    let protocol = None;
    let mut fields = request_pseudo_fields(&method, &uri, &headers, protocol)?;
    fields.extend(regular_fields(headers)?);
    Ok(fields)
}

pub(super) fn request_parts(fields: Vec<Field>) -> Result<http::request::Parts, Error> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;

    let method = required_pseudo(&pseudo, b":method")?;
    let method = Method::from_bytes(method).map_err(message_source("invalid :method"))?;
    let scheme = pseudo_value(&pseudo, b":scheme")?;
    let authority = pseudo_value(&pseudo, b":authority")?;
    let path = pseudo_value(&pseudo, b":path")?;
    let protocol = pseudo_value(&pseudo, b":protocol")?;
    validate_request_pseudo(&method, scheme, authority, path, protocol, &headers)?;

    let uri = build_request_uri(&method, scheme, authority, path)?;
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .version(Version::HTTP_3)
        .body(())
        .map_err(message_source("invalid HTTP/3 request"))?;
    *request.headers_mut() = headers;
    if let Some(protocol) = protocol {
        #[cfg(feature = "webtransport")]
        {
            if protocol != crate::webtransport::PROTOCOL.as_bytes() {
                return Err(message_error("unsupported extended CONNECT protocol"));
            }
            request
                .extensions_mut()
                .insert(crate::webtransport::ProtocolMarker);
        }
        #[cfg(not(feature = "webtransport"))]
        {
            let _ = protocol;
            return Err(message_error("extended CONNECT is not enabled"));
        }
    }
    Ok(request.into_parts().0)
}

pub(super) fn response_fields(parts: http::response::Parts) -> Result<Vec<Field>, Error> {
    let http::response::Parts {
        status,
        headers,
        extensions: _,
        version: _,
        ..
    } = parts;
    let mut fields = vec![Field {
        name: Bytes::from_static(b":status"),
        value: Bytes::copy_from_slice(status.as_str().as_bytes()),
    }];
    fields.extend(regular_fields(headers)?);
    Ok(fields)
}

pub(super) fn response_parts(fields: Vec<Field>) -> Result<http::response::Parts, Error> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if pseudo.len() != 1 {
        return Err(message_error("response must contain exactly one :status"));
    }
    let status = required_pseudo(&pseudo, b":status")?;
    let status = StatusCode::from_bytes(status).map_err(message_source("invalid :status"))?;

    let mut response = http::Response::builder()
        .status(status)
        .version(Version::HTTP_3)
        .body(())
        .map_err(message_source("invalid HTTP/3 response"))?;
    *response.headers_mut() = headers;
    Ok(response.into_parts().0)
}

pub(super) fn trailer_fields(fields: Vec<Field>) -> Result<HeaderMap, Error> {
    let ParsedFields { pseudo, headers } = parse_fields(fields)?;
    if !pseudo.is_empty() {
        return Err(message_error(
            "trailers cannot contain pseudo-header fields",
        ));
    }
    Ok(headers)
}

struct ParsedFields {
    pseudo: Vec<Field>,
    headers: HeaderMap,
}

fn parse_fields(fields: Vec<Field>) -> Result<ParsedFields, Error> {
    let mut pseudo = Vec::new();
    let mut headers = HeaderMap::new();
    let mut regular_seen = false;

    for field in fields {
        if field.name.starts_with(b":") {
            if regular_seen {
                return Err(message_error(
                    "pseudo-header field appears after a regular field",
                ));
            }
            if pseudo
                .iter()
                .any(|existing: &Field| existing.name == field.name)
            {
                return Err(message_error(format!(
                    "duplicate pseudo-header {}",
                    String::from_utf8_lossy(&field.name)
                )));
            }
            pseudo.push(field);
            continue;
        }

        regular_seen = true;
        let name = HeaderName::from_bytes(&field.name)
            .map_err(message_source("invalid HTTP field name"))?;
        let value = HeaderValue::from_bytes(&field.value)
            .map_err(message_source("invalid HTTP field value"))?;
        validate_regular_field(&name, &value)?;
        headers.append(name, value);
    }
    Ok(ParsedFields { pseudo, headers })
}

fn request_pseudo_fields(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    protocol: Option<&[u8]>,
) -> Result<Vec<Field>, Error> {
    #[cfg(feature = "webtransport")]
    if protocol == Some(crate::webtransport::PROTOCOL.as_bytes())
        && !uri
            .scheme()
            .is_some_and(|scheme| scheme.as_str().eq_ignore_ascii_case("https"))
    {
        return Err(message_error("WebTransport requires the https scheme"));
    }

    let mut fields = vec![Field {
        name: Bytes::from_static(b":method"),
        value: Bytes::copy_from_slice(method.as_str().as_bytes()),
    }];

    if method == Method::CONNECT && protocol.is_none() {
        if uri.scheme().is_some() || uri.path_and_query().is_some() {
            return Err(message_error(
                "CONNECT request target must use authority-form",
            ));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| message_error("CONNECT request is missing :authority"))?;
        if authority.port().is_none() {
            return Err(message_error("CONNECT :authority must contain a port"));
        }
        fields.push(Field {
            name: Bytes::from_static(b":authority"),
            value: Bytes::copy_from_slice(authority.as_str().as_bytes()),
        });
        return Ok(fields);
    }

    let scheme = uri
        .scheme()
        .ok_or_else(|| message_error("request URI is missing :scheme"))?;
    let authority = match uri.authority() {
        Some(authority) => authority.as_str().as_bytes(),
        None => headers
            .get(HOST)
            .ok_or_else(|| message_error("request URI and Host are missing :authority"))?
            .as_bytes(),
    };
    if authority.is_empty() {
        return Err(message_error("request :authority is empty"));
    }
    if let Some(host) = headers.get(HOST)
        && host.as_bytes() != authority
    {
        return Err(message_error("request :authority and Host disagree"));
    }
    let path = match uri.path_and_query().map(|value| value.as_str()) {
        Some(path) if !path.is_empty() && !path.starts_with('?') => path,
        Some(path) if path.starts_with('?') => {
            return Err(message_error(format!(
                "request path {path:?} is not path-absolute"
            )));
        }
        _ if method == Method::OPTIONS => "*",
        _ => "/",
    };

    fields.extend([
        Field {
            name: Bytes::from_static(b":scheme"),
            value: Bytes::copy_from_slice(scheme.as_str().as_bytes()),
        },
        Field {
            name: Bytes::from_static(b":authority"),
            value: Bytes::copy_from_slice(authority),
        },
        Field {
            name: Bytes::from_static(b":path"),
            value: Bytes::copy_from_slice(path.as_bytes()),
        },
    ]);
    if let Some(protocol) = protocol {
        if method != Method::CONNECT {
            return Err(message_error(":protocol requires CONNECT"));
        }
        fields.push(Field {
            name: Bytes::from_static(b":protocol"),
            value: Bytes::copy_from_slice(protocol),
        });
    }
    Ok(fields)
}

pub(super) fn regular_fields(headers: HeaderMap) -> Result<Vec<Field>, Error> {
    let mut fields = Vec::with_capacity(headers.len());
    let mut last_name: Option<HeaderName> = None;
    for (name, value) in headers {
        let name = match name {
            Some(name) => {
                last_name = Some(name.clone());
                name
            }
            None => last_name
                .clone()
                .expect("HeaderMap yields an initial name before repeated values"),
        };
        validate_regular_field(&name, &value)?;
        fields.push(Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
        });
    }
    Ok(fields)
}

fn validate_regular_field(name: &HeaderName, value: &HeaderValue) -> Result<(), Error> {
    if matches!(name, &CONNECTION | &TRANSFER_ENCODING | &UPGRADE)
        || name.as_str() == "proxy-connection"
        || name.as_str() == "keep-alive"
    {
        return Err(message_error(format!(
            "connection-specific field {name} is forbidden in HTTP/3"
        )));
    }
    if name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
        return Err(message_error("TE is only permitted with value trailers"));
    }
    Ok(())
}

fn validate_request_pseudo(
    method: &Method,
    scheme: Option<&[u8]>,
    authority: Option<&[u8]>,
    path: Option<&[u8]>,
    protocol: Option<&[u8]>,
    headers: &HeaderMap,
) -> Result<(), Error> {
    if method == Method::CONNECT && protocol.is_none() {
        if scheme.is_some() || path.is_some() {
            return Err(message_error(
                "CONNECT without :protocol cannot contain :scheme or :path",
            ));
        }
        let authority = authority.ok_or_else(|| message_error("CONNECT is missing :authority"))?;
        let authority = std::str::from_utf8(authority)
            .map_err(message_source("CONNECT :authority is not ASCII"))?;
        let authority: http::uri::Authority = authority
            .parse()
            .map_err(message_source("CONNECT :authority is invalid"))?;
        if authority.port().is_none() {
            return Err(message_error("CONNECT :authority must contain a port"));
        }
        return Ok(());
    }

    if method != Method::CONNECT && protocol.is_some() {
        return Err(message_error(":protocol requires CONNECT"));
    }
    #[cfg(feature = "webtransport")]
    if protocol == Some(crate::webtransport::PROTOCOL.as_bytes())
        && !scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"https"))
    {
        return Err(message_error("WebTransport requires the https scheme"));
    }
    scheme.ok_or_else(|| message_error("request is missing :scheme"))?;
    let path = path.ok_or_else(|| message_error("request is missing :path"))?;
    if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
        return Err(message_error("request :path is not path-absolute"));
    }
    // Match outbound URI validation for every scheme, including an explicitly empty Host.
    let wire_authority = authority.filter(|value| !value.is_empty());
    let host = headers.get(HOST);
    if wire_authority.is_none() && host.is_none_or(HeaderValue::is_empty) {
        return Err(message_error("HTTP request is missing authority and Host"));
    }
    if let (Some(authority), Some(host)) = (wire_authority, host)
        && authority != host.as_bytes()
    {
        return Err(message_error("request :authority and Host disagree"));
    }
    Ok(())
}

fn build_request_uri(
    method: &Method,
    scheme: Option<&[u8]>,
    authority: Option<&[u8]>,
    path: Option<&[u8]>,
) -> Result<Uri, Error> {
    if method == Method::CONNECT && scheme.is_none() && path.is_none() {
        let authority = required_bytes(authority, "CONNECT :authority")?;
        return Uri::try_from(authority).map_err(message_source("invalid CONNECT URI"));
    }

    let scheme = required_utf8(scheme, ":scheme")?;
    let path = required_utf8(path, ":path")?;
    let mut builder = Uri::builder().scheme(scheme).path_and_query(path);
    if let Some(authority) = authority {
        builder = builder.authority(required_utf8(Some(authority), ":authority")?);
    }
    builder
        .build()
        .map_err(message_source("invalid request URI"))
}

fn required_pseudo<'a>(pseudo: &'a [Field], name: &[u8]) -> Result<&'a [u8], Error> {
    pseudo_value(pseudo, name)?.ok_or_else(|| {
        message_error(format!(
            "missing {} pseudo-header",
            String::from_utf8_lossy(name)
        ))
    })
}

fn pseudo_value<'a>(pseudo: &'a [Field], name: &[u8]) -> Result<Option<&'a [u8]>, Error> {
    for field in pseudo {
        match field.name.as_ref() {
            b":method" | b":scheme" | b":authority" | b":path" | b":protocol" | b":status" => {}
            _ => {
                return Err(message_error(format!(
                    "unknown pseudo-header {}",
                    String::from_utf8_lossy(&field.name)
                )));
            }
        }
        if field.name.as_ref() == name {
            return Ok(Some(&field.value));
        }
    }
    Ok(None)
}

fn required_bytes<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a [u8], Error> {
    value.ok_or_else(|| message_error(format!("missing {name}")))
}

fn required_utf8<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a str, Error> {
    std::str::from_utf8(required_bytes(value, name)?)
        .map_err(message_source(format!("{name} is not UTF-8")))
}

pub(super) fn message_error(message: impl Into<std::borrow::Cow<'static, str>>) -> Error {
    Error::stream(Some(Code::H3_MESSAGE_ERROR), message)
}

fn message_source<E>(message: impl Into<std::borrow::Cow<'static, str>>) -> impl FnOnce(E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    let message = message.into();
    move |source| Error::stream_with_source(Some(Code::H3_MESSAGE_ERROR), message, source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_validation_retains_authority_and_host_rules_for_custom_schemes() {
        let fields = || {
            vec![
                Field {
                    name: Bytes::from_static(b":method"),
                    value: Bytes::from_static(b"GET"),
                },
                Field {
                    name: Bytes::from_static(b":scheme"),
                    value: Bytes::from_static(b"custom"),
                },
                Field {
                    name: Bytes::from_static(b":path"),
                    value: Bytes::from_static(b"/"),
                },
            ]
        };
        assert!(request_parts(fields()).is_err());
        let mut valid = fields();
        valid.push(Field {
            name: Bytes::from_static(b":authority"),
            value: Bytes::from_static(b"peer.test"),
        });
        assert_eq!(
            request_parts(valid.clone()).unwrap().uri,
            "custom://peer.test/"
        );
        valid.push(Field {
            name: Bytes::from_static(b"host"),
            value: Bytes::from_static(b"other.test"),
        });
        assert!(request_parts(valid.clone()).is_err());
        valid.last_mut().unwrap().value = Bytes::new();
        assert!(request_parts(valid).is_err());
    }
}
