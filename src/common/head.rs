use std::str::from_utf8;

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri,
    header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, TE, TRANSFER_ENCODING, UPGRADE},
    uri::Authority,
};

use crate::{Error, ErrorCode, Result, protocol::qpack::Field};

#[derive(Clone, Debug, Default)]
pub(crate) struct Head<P> {
    pub(crate) pseudo: P,
    pub(crate) headers: HeaderMap,
}

/// HTTP/3 metadata. Pseudo-headers and ordinary headers are kept separate so
/// the same representation can be used for requests and responses.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    pub(crate) extensions: http::Extensions,
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) version: http::Version,
}

#[derive(Clone, Debug)]
pub(crate) struct Response {
    pub(crate) extensions: http::Extensions,
    pub(crate) status: Option<StatusCode>,
    pub(crate) version: http::Version,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            extensions: http::Extensions::new(),
            status: None,
            version: http::Version::HTTP_3,
        }
    }
}

pub(crate) type RequestHead = Head<Request>;
pub(crate) type ResponseHead = Head<Response>;

impl RequestHead {
    pub(crate) fn decode(fields: Vec<Field>) -> Result<Self> {
        let (pseudo, headers) = parse_fields(fields)?;
        if pseudo.iter().any(|field| {
            !matches!(
                field.name.as_ref(),
                b":method" | b":scheme" | b":authority" | b":path" | b":protocol"
            )
        }) {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("request contains an unsupported pseudo-header")
            );
        }

        let method =
            Method::from_bytes(required_pseudo(&pseudo, b":method")?).map_err(message_error)?;
        let scheme = pseudo_value(&pseudo, b":scheme");
        let authority = pseudo_value(&pseudo, b":authority");
        let path = pseudo_value(&pseudo, b":path");
        let protocol = pseudo_value(&pseudo, b":protocol");
        let protocol = if let Some(protocol) = protocol {
            if method != Method::CONNECT || authority.is_none() {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("invalid Extended CONNECT"));
            }
            Some(crate::Protocol::new(
                from_utf8(protocol).map_err(message_error)?,
            )?)
        } else {
            None
        };
        let plain_connect = method == Method::CONNECT && protocol.is_none();
        let authority = if plain_connect {
            if scheme.is_some() || path.is_some() {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT must not include :scheme or :path")
                );
            }
            let authority: Authority = required_utf8(authority, ":authority")?
                .parse()
                .map_err(message_error)?;
            if authority.port().is_none() {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT authority is missing a port")
                );
            }
            authority
        } else {
            required_utf8(scheme, ":scheme")?;
            let path = required_bytes(path, ":path")?;
            if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("request path must be * or start with /")
                );
            }
            let host = headers.get(HOST).map(HeaderValue::as_bytes);
            if let (Some(authority), Some(host)) = (authority, host)
                && authority != host
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("Host does not match :authority"));
            }
            required_utf8(authority.or(host), ":authority")?
                .parse()
                .map_err(message_error)?
        };
        if authority.as_str().contains('@') {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("userinfo is forbidden"));
        }
        let uri = if plain_connect {
            Uri::builder().authority(authority).build()
        } else {
            Uri::builder()
                .scheme(required_utf8(scheme, ":scheme")?)
                .authority(authority)
                .path_and_query(required_utf8(path, ":path")?)
                .build()
        }
        .map_err(message_error)?;
        Self::from_request_parts(method, uri, headers, protocol)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let method = &self.pseudo.method;
        let uri = &self.pseudo.uri;
        let protocol = self.pseudo.extensions.get::<crate::Protocol>();
        let scheme = uri.scheme_str().map(str::as_bytes);
        let authority = uri.authority().ok_or_else(|| {
            ErrorCode::H3_MESSAGE_ERROR.reason("request URI is missing authority")
        })?;
        let authority = authority.as_str().as_bytes();
        let path = uri.path_and_query().map(|value| value.as_str().as_bytes());

        if protocol.is_some() && method != Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason(":protocol requires CONNECT"));
        }
        if authority.contains(&b'@') {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("userinfo is forbidden"));
        }
        if method == Method::CONNECT && protocol.is_none() {
            if scheme.is_some() || path.is_some() {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT must not include :scheme or :path")
                );
            }
            if uri.authority().unwrap().port().is_none() {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT authority is missing a port")
                );
            }
            return Ok(());
        }

        scheme
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("request URI is missing scheme"))?;
        let path =
            path.ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("request URI is missing path"))?;
        if path.is_empty() || (path != b"*" && !path.starts_with(b"/")) {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("request path must be * or start with /")
            );
        }
        if self
            .headers
            .get(HOST)
            .is_some_and(|host| host.as_bytes() != authority)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("Host does not match request authority"));
        }
        Ok(())
    }

    pub(crate) fn encode(&self, fields: &mut Vec<Field>) -> Result<()> {
        self.validate()?;
        let method = &self.pseudo.method;
        let uri = &self.pseudo.uri;
        let protocol = self.pseudo.extensions.get::<crate::Protocol>();
        let authority = uri.authority().unwrap().as_str().as_bytes();

        fields.reserve(5 + self.headers.len());
        fields.push(pseudo_field(b":method", method.as_str().as_bytes()));
        if let Some(scheme) = uri.scheme_str() {
            fields.push(pseudo_field(b":scheme", scheme.as_bytes()));
        }
        fields.push(pseudo_field(b":authority", authority));
        if let Some(path) = uri.path_and_query() {
            fields.push(pseudo_field(b":path", path.as_str().as_bytes()));
        }
        if let Some(protocol) = protocol {
            fields.push(pseudo_field(b":protocol", protocol.as_str().as_bytes()));
        }
        put_regular_headers(fields, &self.headers);
        Ok(())
    }

    pub(crate) fn request_method(&self) -> &Method {
        &self.pseudo.method
    }

    pub(crate) fn request_uri(&self) -> &Uri {
        &self.pseudo.uri
    }

    pub(crate) fn request_extensions(&self) -> &http::Extensions {
        &self.pseudo.extensions
    }

    pub(crate) fn request_protocol(&self) -> Option<&crate::Protocol> {
        self.request_extensions().get()
    }
}

impl ResponseHead {
    pub(crate) fn decode(fields: Vec<Field>) -> Result<Self> {
        let (pseudo, headers) = parse_fields(fields)?;
        if pseudo.len() != 1 {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("response must contain exactly one :status pseudo-header"));
        }
        let status =
            StatusCode::from_bytes(required_pseudo(&pseudo, b":status")?).map_err(message_error)?;
        Ok(Self::from_response_parts(Some(status), headers))
    }

    pub(crate) fn encode(&self, fields: &mut Vec<Field>) -> Result<()> {
        let status = self.response_status()?;
        fields.reserve(1 + self.headers.len());
        fields.push(pseudo_field(b":status", status.as_str().as_bytes()));
        put_regular_headers(fields, &self.headers);
        Ok(())
    }

    pub(crate) fn response_status(&self) -> Result<StatusCode> {
        self.pseudo
            .status
            .ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason("response is missing :status"))
    }
}

impl RequestHead {
    pub(crate) fn from_request_parts(
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        protocol: Option<crate::Protocol>,
    ) -> Result<Self> {
        let mut extensions = http::Extensions::new();
        if let Some(protocol) = protocol {
            extensions.insert(protocol);
        }
        let head = Self {
            pseudo: Request {
                extensions,
                method,
                uri,
                version: http::Version::HTTP_3,
            },
            headers,
        };
        head.validate()?;
        Ok(head)
    }
}

impl ResponseHead {
    pub(crate) fn from_response_parts(status: Option<StatusCode>, headers: HeaderMap) -> Self {
        Self {
            pseudo: Response {
                extensions: http::Extensions::new(),
                status,
                version: http::Version::HTTP_3,
            },
            headers,
        }
    }
}

impl From<http::request::Parts> for RequestHead {
    fn from(parts: http::request::Parts) -> Self {
        Self {
            pseudo: Request {
                extensions: parts.extensions,
                method: parts.method,
                uri: parts.uri,
                version: parts.version,
            },
            headers: parts.headers,
        }
    }
}

impl From<RequestHead> for http::request::Parts {
    fn from(head: RequestHead) -> Self {
        let mut request = http::Request::new(());
        *request.method_mut() = head.pseudo.method;
        *request.uri_mut() = head.pseudo.uri;
        *request.headers_mut() = head.headers;
        *request.extensions_mut() = head.pseudo.extensions;
        *request.version_mut() = head.pseudo.version;
        request.into_parts().0
    }
}

impl From<http::response::Parts> for ResponseHead {
    fn from(parts: http::response::Parts) -> Self {
        Self {
            pseudo: Response {
                extensions: parts.extensions,
                status: Some(parts.status),
                version: parts.version,
            },
            headers: parts.headers,
        }
    }
}

impl From<ResponseHead> for http::response::Parts {
    fn from(head: ResponseHead) -> Self {
        let mut response = http::Response::new(());
        *response.status_mut() = head.pseudo.status.unwrap_or(StatusCode::OK);
        *response.headers_mut() = head.headers;
        *response.extensions_mut() = head.pseudo.extensions;
        *response.version_mut() = head.pseudo.version;
        response.into_parts().0
    }
}

fn message_error<T: std::error::Error + Send + Sync + 'static>(error: T) -> Error {
    ErrorCode::H3_MESSAGE_ERROR.reason(format!("invalid HTTP field: {error}"))
}

pub(crate) fn content_length(headers: &HeaderMap) -> Result<Option<u64>> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.reason("multiple Content-Length fields are not allowed")
        );
    }
    let value = value.to_str().map_err(message_error)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.reason("Content-Length must contain only decimal digits")
        );
    }
    value.parse::<u64>().map(Some).map_err(message_error)
}

/// Parse and validate an HTTP/3 trailer field section.
pub(crate) fn be_trailers(fields: Vec<Field>) -> Result<HeaderMap> {
    let (pseudo, headers) = parse_fields(fields)?;
    if !pseudo.is_empty() {
        return Err(ErrorCode::H3_MESSAGE_ERROR.reason("trailers must not contain pseudo-headers"));
    }
    Ok(headers)
}

pub(crate) trait WriteRequest {
    fn put_request(&mut self, head: &RequestHead) -> Result<()>;
}

impl WriteRequest for Vec<Field> {
    fn put_request(&mut self, head: &RequestHead) -> Result<()> {
        require_empty(self)?;
        validate_regular_headers(&head.headers)?;
        head.encode(self)
    }
}

pub(crate) trait WriteResponse {
    fn put_response(&mut self, head: &ResponseHead) -> Result<()>;
}

impl WriteResponse for Vec<Field> {
    fn put_response(&mut self, head: &ResponseHead) -> Result<()> {
        require_empty(self)?;
        validate_regular_headers(&head.headers)?;
        head.encode(self)
    }
}

fn require_empty(fields: &[Field]) -> Result<()> {
    if fields.is_empty() {
        Ok(())
    } else {
        Err(ErrorCode::H3_MESSAGE_ERROR
            .reason("field section output must be empty before encoding"))
    }
}

fn parse_fields(fields: Vec<Field>) -> Result<(Vec<Field>, HeaderMap)> {
    let mut pseudo = Vec::new();
    let mut headers = HeaderMap::new();
    let mut regular_seen = false;

    for field in fields {
        if field.name.starts_with(b":") {
            if regular_seen {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .reason("pseudo-header appears after a regular header"));
            }
            if pseudo
                .iter()
                .any(|existing: &Field| existing.name == field.name)
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("duplicate pseudo-header"));
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
    Ok((pseudo, headers))
}

fn validate_regular_field(name: &HeaderName, value: &HeaderValue) -> Result<()> {
    if matches!(name, &CONNECTION | &TRANSFER_ENCODING | &UPGRADE)
        || matches!(name.as_str(), "proxy-connection" | "keep-alive")
    {
        return Err(
            ErrorCode::H3_MESSAGE_ERROR.reason("connection-specific header is forbidden in HTTP/3")
        );
    }
    if name == TE && !value.as_bytes().eq_ignore_ascii_case(b"trailers") {
        return Err(ErrorCode::H3_MESSAGE_ERROR.reason("TE must have the value trailers"));
    }
    Ok(())
}

fn validate_regular_headers(headers: &HeaderMap) -> Result<()> {
    for (name, value) in headers {
        validate_regular_field(name, value)?;
    }
    Ok(())
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

fn required_pseudo<'a>(pseudo: &'a [Field], name: &[u8]) -> Result<&'a [u8]> {
    pseudo_value(pseudo, name).ok_or_else(|| {
        ErrorCode::H3_MESSAGE_ERROR.reason(format!(
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
    value.ok_or_else(|| ErrorCode::H3_MESSAGE_ERROR.reason(format!("missing pseudo-header {name}")))
}

fn required_utf8<'a>(value: Option<&'a [u8]>, name: &str) -> Result<&'a str> {
    from_utf8(required_bytes(value, name)?).map_err(message_error)
}
