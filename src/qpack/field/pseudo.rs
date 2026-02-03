use http::{
    Method, StatusCode, Uri,
    uri::{Authority, PathAndQuery, Scheme},
};

use super::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoHeaders {
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-request-pseudo-header-field
    Request {
        method: Option<Method>,
        scheme: Option<Scheme>,
        authority: Option<Authority>,
        path: Option<PathAndQuery>,
        protocol: Option<Protocol>,
    },
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-response-pseudo-header-fiel
    Response { status: Option<StatusCode> },
}

impl PseudoHeaders {
    pub const METHOD: &str = ":method";
    pub const SCHEME: &str = ":scheme";
    pub const AUTHORITY: &str = ":authority";
    pub const PATH: &str = ":path";
    pub const PROTOOCL: &str = ":protocol";

    pub const STATUS: &str = ":status";

    pub fn request(method: Method, uri: Uri) -> Self {
        let uri = uri.into_parts();
        let path = match uri.path_and_query {
            Some(path_and_query) => Some(path_and_query),
            // This pseudo-header field MUST NOT be empty for "http" or "https"
            // URIs; "http" or "https" URIs that do not contain a path component
            // MUST include a value of / (ASCII 0x2f). An OPTIONS request that
            // does not include a path component includes the value * (ASCII
            // 0x2a) for the :path pseudo-header field; see Section 7.1 of
            // [HTTP].
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#section-4.3.1-2.16.1
            None if uri.scheme == Some(Scheme::HTTP) || uri.scheme == Some(Scheme::HTTPS) => {
                Some(PathAndQuery::from_static("/"))
            }
            None if method == http::Method::OPTIONS => Some(PathAndQuery::from_static("/")),
            None => None,
        };
        PseudoHeaders::Request {
            method: Some(method),
            scheme: uri.scheme,
            authority: uri.authority,
            path,
            protocol: None,
        }
    }

    pub fn response(status: StatusCode) -> Self {
        Self::Response {
            status: Some(status),
        }
    }

    pub const fn unresolved_request() -> Self {
        PseudoHeaders::Request {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            protocol: None,
        }
    }

    pub const fn unresolved_response() -> Self {
        PseudoHeaders::Response { status: None }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
                protocol: protoocl,
            } => {
                method.is_none()
                    && scheme.is_none()
                    && authority.is_none()
                    && path.is_none()
                    && protoocl.is_none()
            }
            PseudoHeaders::Response { status } => status.is_none(),
        }
    }
}
