use http::{
    Method, StatusCode, Uri,
    uri::{Authority, PathAndQuery, Scheme},
};

use super::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoHeaders {
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-request-pseudo-header-field>
    Request {
        method: Option<Method>,
        scheme: Option<Scheme>,
        authority: Option<Authority>,
        path: Option<PathAndQuery>,
        protocol: Option<Protocol>,
    },
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-response-pseudo-header-fiel>
    Response { status: Option<StatusCode> },
}

fn has_missing_path_component(path_and_query: &PathAndQuery) -> bool {
    path_and_query.as_str().is_empty() || path_and_query.as_str().starts_with('?')
}

fn normalize_http_path(path_and_query: PathAndQuery) -> PathAndQuery {
    if path_and_query.as_str().is_empty() {
        return PathAndQuery::from_static("/");
    }

    if path_and_query.as_str().starts_with('?') {
        let mut normalized = String::with_capacity(path_and_query.as_str().len() + 1);
        normalized.push('/');
        normalized.push_str(path_and_query.as_str());
        return PathAndQuery::try_from(normalized)
            .expect("path-and-query with a prefixed slash remains valid");
    }

    path_and_query
}

pub(super) fn asterisk_path() -> PathAndQuery {
    Uri::from_static("*")
        .into_parts()
        .path_and_query
        .expect("asterisk URI carries a path-and-query")
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
        let is_http = uri.scheme == Some(Scheme::HTTP) || uri.scheme == Some(Scheme::HTTPS);
        // RFC 9114 Section 4.3.1 defines :path as path-absolute plus an
        // optional query. For http/https URIs with no path component, use "/"
        // (or "/?query" for query-only targets). OPTIONS requests with no path
        // component use "*".
        let path = match uri.path_and_query {
            Some(path_and_query)
                if method == http::Method::OPTIONS
                    && has_missing_path_component(&path_and_query) =>
            {
                Some(asterisk_path())
            }
            Some(path_and_query) if is_http => Some(normalize_http_path(path_and_query)),
            Some(path_and_query) => Some(path_and_query),
            None if method == http::Method::OPTIONS => Some(asterisk_path()),
            None if is_http => Some(PathAndQuery::from_static("/")),
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

#[cfg(test)]
mod tests {
    use http::{Method, StatusCode, Uri, uri::PathAndQuery};

    use super::PseudoHeaders;

    #[test]
    fn request_extracts_pseudo_headers_from_absolute_uri() {
        let pseudo = PseudoHeaders::request(
            Method::GET,
            Uri::from_static("https://example.com:443/resource?q=1"),
        );

        assert_eq!(
            pseudo,
            PseudoHeaders::Request {
                method: Some(Method::GET),
                scheme: Some(http::uri::Scheme::HTTPS),
                authority: Some(http::uri::Authority::from_static("example.com:443")),
                path: Some(PathAndQuery::from_static("/resource?q=1")),
                protocol: None,
            }
        );
        assert!(!pseudo.is_empty());
    }

    #[test]
    fn request_defaults_http_and_https_missing_path_to_slash() {
        let https = PseudoHeaders::request(Method::GET, Uri::from_static("https://example.com"));
        let http = PseudoHeaders::request(Method::GET, Uri::from_static("http://example.com"));

        for pseudo in [https, http] {
            match pseudo {
                PseudoHeaders::Request { path, .. } => {
                    assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("/"));
                }
                PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
            }
        }
    }

    #[test]
    fn request_normalizes_query_only_http_and_https_uri_to_absolute_path() {
        let https =
            PseudoHeaders::request(Method::GET, Uri::from_static("https://example.com?x=1"));
        let http = PseudoHeaders::request(Method::GET, Uri::from_static("http://example.com?x=1"));

        for pseudo in [https, http] {
            match pseudo {
                PseudoHeaders::Request { path, .. } => {
                    assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("/?x=1"));
                }
                PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
            }
        }
    }

    #[test]
    fn options_asterisk_form_and_authority_form_use_asterisk_but_explicit_paths_are_preserved() {
        let asterisk_form = PseudoHeaders::request(Method::OPTIONS, Uri::from_static("*"));
        let authority_form =
            PseudoHeaders::request(Method::OPTIONS, Uri::from_static("example.com"));
        let explicit_slash =
            PseudoHeaders::request(Method::OPTIONS, Uri::from_static("https://example.com/"));
        let explicit_slash_with_query = PseudoHeaders::request(
            Method::OPTIONS,
            Uri::from_static("https://example.com/?x=1"),
        );

        match asterisk_form {
            PseudoHeaders::Request { path, .. } => {
                assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("*"));
            }
            PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
        }
        match authority_form {
            PseudoHeaders::Request { path, .. } => {
                assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("*"));
            }
            PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
        }
        match explicit_slash {
            PseudoHeaders::Request { path, .. } => {
                assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("/"));
            }
            PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
        }
        match explicit_slash_with_query {
            PseudoHeaders::Request { path, .. } => {
                assert_eq!(path.as_ref().map(PathAndQuery::as_str), Some("/?x=1"));
            }
            PseudoHeaders::Response { .. } => panic!("request should produce request headers"),
        }
    }

    #[test]
    fn response_and_unresolved_headers_report_empty_state() {
        let response = PseudoHeaders::response(StatusCode::NO_CONTENT);
        assert_eq!(
            response,
            PseudoHeaders::Response {
                status: Some(StatusCode::NO_CONTENT),
            }
        );
        assert!(!response.is_empty());

        assert!(PseudoHeaders::unresolved_request().is_empty());
        assert!(PseudoHeaders::unresolved_response().is_empty());
    }
}
