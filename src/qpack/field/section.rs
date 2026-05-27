use std::{pin::pin, sync::Arc};

use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{self, HeaderName, HeaderValue},
    method, status,
    uri::{self, Authority, PathAndQuery, Scheme},
};
use snafu::{ResultExt, Snafu, ensure};

use super::{FieldLine, Protocol, PseudoHeaders};
use crate::{
    codec::DecodeFrom,
    connection::StreamError,
    error::{Code, H3StreamError},
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum MalformedHeaderSection {
    #[snafu(display("invalid pseudo-header field with name {name:?}"))]
    InvalidPseudoHeader { name: Bytes },
    #[snafu(display("duplicate pseudo-header field with name {name:?}"))]
    DuplicatePseudoHeader { name: Bytes },
    // TODO: merge this error into following two errors
    #[snafu(display("field section contains both request and response pseudo-header fields"))]
    MixedRequestResponsePseudoHeader,
    #[snafu(display("request pseudo-header field in response"))]
    RequestPseudoHeaderInResponse,
    #[snafu(display("response pseudo-header field in request"))]
    ResponsePseudoHeaderInRequest,
    #[snafu(display("field section contains pseudo-header fields in trailers"))]
    PseudoHeaderInTrailer,
    #[snafu(display("pseudo-header field appears after regular header field"))]
    PseudoHeaderAfterRegularHeader,
    #[snafu(display("field section too large"))]
    FieldSectionTooLarge,
    #[snafu(display(
        "empty :authority or host header field for scheme with mandatory authority component"
    ))]
    EmptyAuthorityOrHost,
    #[snafu(display("invalid host header field: invalid ASCII"))]
    InvalidHostHeader,
    #[snafu(display("mismatch between :authority and host header fields"))]
    AuthorityHostMismatch,
    #[snafu(display("absence of mandatory pseudo-header fields"))]
    AbsenceOfMandatoryPseudoHeaders { backtrace: snafu::Backtrace },
    #[snafu(display("unexpected :scheme pseudo-header for CONNECT request"))]
    UnexpectedSchemeForConnectRequest,
    #[snafu(display("unexpected :path pseudo-header for CONNECT request"))]
    UnexpectedPathForConnectRequest,
    #[snafu(display("missing :authority pseudo-header for CONNECT request"))]
    MissingAuthorityForConnectRequest,
    #[snafu(display("missing port for CONNECT :authority pseudo-header"))]
    MissingPortForConnectAuthority,
    #[snafu(display("unexpected :protocol pseudo-header in non-CONNECT request"))]
    ProtocolInNonConnectRequest,
    #[snafu(display("invalid :protocol pseudo-header token"))]
    InvalidProtocolToken { source: std::str::Utf8Error },

    #[snafu(transparent)]
    InvalidMessage { source: http::Error },
}

impl H3StreamError for MalformedHeaderSection {
    fn code(&self) -> Code {
        Code::H3_MESSAGE_ERROR
    }
}

impl From<method::InvalidMethod> for MalformedHeaderSection {
    fn from(error: method::InvalidMethod) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<uri::InvalidUri> for MalformedHeaderSection {
    fn from(error: uri::InvalidUri) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<status::InvalidStatusCode> for MalformedHeaderSection {
    fn from(error: status::InvalidStatusCode) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::MaxSizeReached> for MalformedHeaderSection {
    fn from(error: header::MaxSizeReached) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::InvalidHeaderName> for MalformedHeaderSection {
    fn from(error: header::InvalidHeaderName) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::InvalidHeaderValue> for MalformedHeaderSection {
    fn from(error: header::InvalidHeaderValue) -> Self {
        MalformedHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::ToStrError> for MalformedHeaderSection {
    fn from(_: header::ToStrError) -> Self {
        MalformedHeaderSection::InvalidHostHeader
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSection {
    pub(crate) pseudo_headers: Option<super::PseudoHeaders>,
    pub(crate) header_map: Arc<HeaderMap>,
}

impl FieldSection {
    pub fn header(pseudo_headers: PseudoHeaders, header_map: HeaderMap) -> Self {
        Self {
            pseudo_headers: Some(pseudo_headers),
            header_map: Arc::new(header_map),
        }
    }

    pub fn trailer(header_map: HeaderMap) -> Self {
        Self {
            pseudo_headers: None,
            header_map: Arc::new(header_map),
        }
    }

    pub fn header_map(&self) -> &HeaderMap {
        &self.header_map
    }

    pub fn header_map_mut(&mut self) -> &mut HeaderMap {
        Arc::make_mut(&mut self.header_map)
    }

    pub fn into_header_map(self) -> HeaderMap {
        Arc::try_unwrap(self.header_map).unwrap_or_else(|header_map| (*header_map).clone())
    }

    pub fn is_empty(&self) -> bool {
        self.pseudo_headers
            .as_ref()
            .is_none_or(|pseudo_headers| pseudo_headers.is_empty())
            && self.header_map.is_empty()
    }

    pub fn iter(&self) -> Iter<'_> {
        IntoIterator::into_iter(self)
    }

    pub fn is_request_header(&self) -> bool {
        matches!(self.pseudo_headers, Some(PseudoHeaders::Request { .. }))
    }

    pub fn is_response_header(&self) -> bool {
        matches!(self.pseudo_headers, Some(PseudoHeaders::Response { .. }))
    }

    pub fn is_trailer(&self) -> bool {
        self.pseudo_headers.is_none()
    }

    pub fn check_pseudo(&self) -> Result<(), MalformedHeaderSection> {
        let Some(pseudo_headers) = self.pseudo_headers.as_ref() else {
            return Ok(());
        };
        match pseudo_headers {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
                protocol,
            } => {
                // All HTTP/3 requests MUST include exactly one value for the :method,
                // :scheme, and :path pseudo-header fields, unless the request is a
                // CONNECT request; see Section 4.4.
                let Some(method) = method else {
                    return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
                };
                if method != Method::CONNECT && protocol.is_some() {
                    return Err(MalformedHeaderSection::ProtocolInNonConnectRequest);
                }

                // 4.  The Extended CONNECT Method
                //
                //    Usage of the CONNECT method in HTTP/2 is defined by Section 8.3 of
                //    [RFC7540].  This extension modifies the method in the following ways:
                //
                //    o  A new pseudo-header field :protocol MAY be included on request
                //       HEADERS indicating the desired protocol to be spoken on the tunnel
                //       created by CONNECT.  The pseudo-header field is single valued and
                //       contains a value from the "Hypertext Transfer Protocol (HTTP)
                //       Upgrade Token Registry" located at
                //       <https://www.iana.org/assignments/http-upgrade-tokens/>
                //
                //    o  On requests that contain the :protocol pseudo-header field, the
                //       :scheme and :path pseudo-header fields of the target URI (see
                //       Section 5) MUST also be included.
                //
                //    o  On requests bearing the :protocol pseudo-header field, the
                //       :authority pseudo-header field is interpreted according to
                //       Section 8.1.2.3 of [RFC7540] instead of Section 8.3 of that
                //       document.  In particular, the server MUST NOT create a tunnel to
                //       the host indicated by the :authority as it would with a CONNECT
                //       method request that was not modified by this extension.
                //
                //    Upon receiving a CONNECT request bearing the :protocol pseudo-header
                //    field, the server establishes a tunnel to another service of the
                //    protocol type indicated by the pseudo-header field.  This service may
                //    or may not be co-located with the server.
                //
                // https://datatracker.ietf.org/doc/html/rfc8441#section-4
                if method != Method::CONNECT || protocol.is_some() {
                    let Some(scheme) = scheme else {
                        return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu
                            .fail();
                    };
                    let Some(_path) = path else {
                        return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu
                            .fail();
                    };

                    // If the :scheme pseudo-header field identifies a scheme that has a
                    // mandatory authority component (including "http" and "https"), the
                    // request MUST contain either an :authority pseudo-header field or a
                    // Host header field. If these fields are present, they MUST NOT be
                    // empty. If both fields are present, they MUST contain the same value.
                    // If the scheme does not have a mandatory authority component and none
                    // is provided in the request target, the request MUST NOT contain the
                    // :authority pseudo-header or Host header fields.
                    if scheme == &Scheme::HTTP || scheme == &Scheme::HTTPS {
                        match (authority, self.header_map.get("host")) {
                            (Some(authority), Some(host)) => {
                                let host = host.to_str()?;
                                if authority.as_str().is_empty() || host.is_empty() {
                                    return Err(MalformedHeaderSection::EmptyAuthorityOrHost);
                                }
                                if authority.as_str() != host {
                                    return Err(MalformedHeaderSection::AuthorityHostMismatch);
                                }
                            }
                            (Some(authority), None) => {
                                if authority.as_str().is_empty() {
                                    return Err(MalformedHeaderSection::EmptyAuthorityOrHost);
                                }
                            }
                            (None, Some(host)) => {
                                let host = host.to_str()?;
                                if host.is_empty() {
                                    return Err(MalformedHeaderSection::EmptyAuthorityOrHost);
                                }
                            }
                            (None, None) => {
                                return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
                            }
                        }
                    }

                    Ok(())
                } else {
                    // A CONNECT request MUST be constructed as follows:
                    //
                    // * The :method pseudo-header field is set to "CONNECT"
                    //
                    // * The :scheme and :path pseudo-header fields are omitted
                    //
                    // * The :authority pseudo-header field contains the host and port to
                    //   connect to (equivalent to the authority-form of the request-target
                    //   of CONNECT requests; see Section 7.1 of [HTTP]).
                    //
                    // https://datatracker.ietf.org/doc/html/rfc9114#name-the-connect-method
                    if scheme.is_some() {
                        return Err(MalformedHeaderSection::UnexpectedSchemeForConnectRequest);
                    }
                    if path.is_some() {
                        return Err(MalformedHeaderSection::UnexpectedPathForConnectRequest);
                    }
                    let Some(authority) = authority else {
                        return Err(MalformedHeaderSection::MissingAuthorityForConnectRequest);
                    };
                    if authority.port().is_none() {
                        return Err(MalformedHeaderSection::MissingPortForConnectAuthority);
                    }
                    Ok(())
                }
            }
            PseudoHeaders::Response { status } => {
                let Some(_status) = status else {
                    return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
                };
                Ok(())
            }
        }
    }

    pub fn method(&self) -> Method {
        let Some(PseudoHeaders::Request { method, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        method.clone().expect("method is set for request headers")
    }

    pub fn set_method(&mut self, new: Method) {
        let Some(PseudoHeaders::Request { method, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        *method = Some(new)
    }

    pub fn scheme(&self) -> Option<Scheme> {
        let Some(PseudoHeaders::Request { scheme, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        scheme.clone()
    }

    pub fn set_scheme(&mut self, new: Scheme) {
        let Some(PseudoHeaders::Request { scheme, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        *scheme = Some(new)
    }

    pub fn authority(&self) -> Option<Authority> {
        let Some(PseudoHeaders::Request { authority, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        authority.clone()
    }

    pub fn set_authority(&mut self, new: Authority) {
        let Some(PseudoHeaders::Request { authority, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        *authority = Some(new)
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        let Some(PseudoHeaders::Request { path, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        path.clone()
    }

    pub fn set_path(&mut self, new: PathAndQuery) {
        let Some(PseudoHeaders::Request { path, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        *path = Some(new);
    }

    pub fn protocol(&self) -> Option<Protocol> {
        let Some(PseudoHeaders::Request { protocol, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        protocol.clone()
    }

    pub fn set_protocol(&mut self, new: Protocol) {
        let Some(PseudoHeaders::Request { protocol, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not request headers")
        };
        *protocol = Some(new);
    }

    pub fn uri(&self) -> Uri {
        let mut uri = uri::Parts::default();
        uri.scheme = self.scheme();
        uri.authority = self.authority();
        uri.path_and_query = self.path();
        Uri::from_parts(uri).expect("valid URI parts from request headers")
    }

    pub fn set_uri(&mut self, uri: Uri) {
        let uri = uri.into_parts();
        if let Some(scheme) = uri.scheme {
            self.set_scheme(scheme);
        }
        if let Some(authority) = uri.authority {
            self.set_authority(authority);
        }
        if let Some(path) = uri.path_and_query {
            self.set_path(path);
        }
    }

    pub fn status(&self) -> StatusCode {
        let Some(PseudoHeaders::Response { status, .. }) = &self.pseudo_headers else {
            panic!("FieldSection is not response headers")
        };
        status.expect("status is set for response headers")
    }

    pub fn set_status(&mut self, new: StatusCode) {
        let Some(PseudoHeaders::Response { status, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not response headers")
        };
        *status = Some(new)
    }
}

impl<S: Stream<Item = Result<FieldLine, StreamError>> + Send> DecodeFrom<S> for FieldSection {
    type Error = StreamError;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        let mut stream = pin!(stream);

        let mut pseudo_headers = None;
        let mut header_map = HeaderMap::new();
        let mut regular_header_seen = false;
        while let Some(FieldLine { name, value }) = stream.try_next().await? {
            match name {
                name if name == PseudoHeaders::METHOD => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let method = match &mut pseudo {
                        PseudoHeaders::Request { method, .. } => method,
                        PseudoHeaders::Response { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        method.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *method =
                        Some(Method::from_bytes(&value[..]).map_err(MalformedHeaderSection::from)?);
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::PROTOOCL => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let protocol = match &mut pseudo {
                        PseudoHeaders::Request { protocol, .. } => protocol,
                        PseudoHeaders::Response { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        protocol.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *protocol = Some(
                        Protocol::try_from(value.clone())
                            .context(malformed_header_section::InvalidProtocolTokenSnafu)?,
                    );
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::SCHEME => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let scheme = match &mut pseudo {
                        PseudoHeaders::Request { scheme, .. } => scheme,
                        PseudoHeaders::Response { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        scheme.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *scheme =
                        Some(Scheme::try_from(&value[..]).map_err(MalformedHeaderSection::from)?);
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::AUTHORITY => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let authority = match &mut pseudo {
                        PseudoHeaders::Request { authority, .. } => authority,
                        PseudoHeaders::Response { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        authority.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *authority = Some(
                        Authority::from_maybe_shared(value)
                            .map_err(MalformedHeaderSection::from)?,
                    );
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::PATH => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());

                    let path_field = match &mut pseudo {
                        PseudoHeaders::Request { path, .. } => path,
                        PseudoHeaders::Response { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        path_field.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *path_field = Some(if value.as_ref() == b"*" {
                        super::pseudo::asterisk_path()
                    } else {
                        PathAndQuery::from_maybe_shared(value)
                            .map_err(MalformedHeaderSection::from)?
                    });
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::STATUS => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_response());

                    let status = match &mut pseudo {
                        PseudoHeaders::Response { status, .. } => status,
                        PseudoHeaders::Request { .. } => {
                            return Err(
                                MalformedHeaderSection::MixedRequestResponsePseudoHeader.into()
                            );
                        }
                    };
                    ensure!(
                        status.is_none(),
                        malformed_header_section::DuplicatePseudoHeaderSnafu { name }
                    );
                    *status = Some(
                        StatusCode::try_from(&value[..]).map_err(MalformedHeaderSection::from)?,
                    );
                    pseudo_headers = Some(pseudo)
                }

                name if name.starts_with(b":") => {
                    ensure!(
                        !regular_header_seen,
                        malformed_header_section::PseudoHeaderAfterRegularHeaderSnafu
                    );
                    return Err(MalformedHeaderSection::InvalidPseudoHeader { name }.into());
                }
                name => {
                    regular_header_seen = true;
                    header_map
                        .try_append(
                            HeaderName::from_bytes(name.as_ref())
                                .map_err(MalformedHeaderSection::from)?,
                            HeaderValue::from_maybe_shared(value)
                                .map_err(MalformedHeaderSection::from)?,
                        )
                        .map_err(MalformedHeaderSection::from)?;
                }
            }
        }

        Ok(FieldSection {
            pseudo_headers,
            header_map: Arc::new(header_map),
        })
    }
}

impl<'s> IntoIterator for &'s FieldSection {
    type Item = FieldLine;
    type IntoIter = Iter<'s>;

    fn into_iter(self) -> Self::IntoIter {
        let header_map_iter = self.header_map.iter();
        Iter {
            pseudo_headers: self.pseudo_headers.clone(),
            header_map_iter,
        }
    }
}

pub struct Iter<'s> {
    pseudo_headers: Option<PseudoHeaders>,
    header_map_iter: http::header::Iter<'s, HeaderValue>,
}

impl Iterator for Iter<'_> {
    type Item = FieldLine;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pseudo_headers) = self.pseudo_headers.as_mut() {
            match pseudo_headers {
                PseudoHeaders::Request {
                    method,
                    scheme,
                    authority,
                    path,
                    protocol,
                } => {
                    if let Some(method) = method.take() {
                        return Some(method.into());
                    }
                    if let Some(protocol) = protocol.take() {
                        return Some(protocol.into());
                    }
                    if let Some(scheme) = scheme.take() {
                        return Some(scheme.into());
                    }
                    if let Some(authority) = authority.take() {
                        return Some(authority.into());
                    }
                    if let Some(path) = path.take() {
                        return Some(path.into());
                    }
                }
                PseudoHeaders::Response { status } => {
                    if let Some(status) = status.take() {
                        return Some(status.into());
                    }
                }
            }
        };
        self.pseudo_headers = None;

        if let Some((name, value)) = self.header_map_iter.next() {
            return Some(FieldLine {
                name: Bytes::from_owner(name.clone()),
                value: Bytes::from_owner(value.clone()),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::stream;

    use super::*;

    fn field(name: &'static [u8], value: &'static [u8]) -> Result<FieldLine, StreamError> {
        Ok(FieldLine {
            name: Bytes::from_static(name),
            value: Bytes::from_static(value),
        })
    }

    async fn decode_fields(
        fields: impl IntoIterator<Item = Result<FieldLine, StreamError>>,
    ) -> Result<FieldSection, StreamError> {
        let fields: Vec<_> = fields.into_iter().collect();
        FieldSection::decode_from(stream::iter(fields)).await
    }

    fn assert_h3_error(error: StreamError, expected: &str) {
        let StreamError::H3 { source } = error else {
            panic!("expected stream-scope H3 error");
        };
        assert_eq!(source.to_string(), expected);
    }

    fn assert_h3_error_one_of(error: StreamError, expected: &[&str]) {
        let StreamError::H3 { source } = error else {
            panic!("expected stream-scope H3 error");
        };
        let message = source.to_string();
        assert!(
            expected.iter().any(|expected| message == *expected),
            "unexpected H3 error message {message:?}; expected one of {expected:?}"
        );
    }

    fn request_pseudo(
        method: Option<Method>,
        scheme: Option<Scheme>,
        authority: Option<Authority>,
        path: Option<PathAndQuery>,
        protocol: Option<Protocol>,
    ) -> PseudoHeaders {
        PseudoHeaders::Request {
            method,
            scheme,
            authority,
            path,
            protocol,
        }
    }

    #[test]
    fn field_section_accessors_mutators_and_iteration() {
        let mut headers = HeaderMap::new();
        headers.insert("x-test", HeaderValue::from_static("one"));
        let mut section = FieldSection::header(
            PseudoHeaders::request(
                Method::GET,
                Uri::from_static("https://example.test:443/a?b=1"),
            ),
            headers,
        );

        assert!(!section.is_empty());
        assert!(section.is_request_header());
        assert!(!section.is_response_header());
        assert!(!section.is_trailer());
        assert_eq!(section.method(), Method::GET);
        assert_eq!(section.scheme(), Some(Scheme::HTTPS));
        assert_eq!(
            section.authority().as_ref().map(Authority::as_str),
            Some("example.test:443")
        );
        assert_eq!(
            section.path().as_ref().map(PathAndQuery::as_str),
            Some("/a?b=1")
        );
        assert_eq!(
            section.uri(),
            Uri::from_static("https://example.test:443/a?b=1")
        );

        section.set_method(Method::POST);
        section.set_scheme(Scheme::HTTP);
        section.set_authority(Authority::from_static("example.test:80"));
        section.set_path(PathAndQuery::from_static("/changed"));
        section.set_protocol(Protocol::new("webtransport"));
        section.set_uri(Uri::from_static("https://other.test/new"));
        section
            .header_map_mut()
            .insert("x-second", HeaderValue::from_static("two"));

        assert_eq!(section.method(), Method::POST);
        assert_eq!(
            section.protocol().as_ref().map(Protocol::as_str),
            Some("webtransport")
        );
        assert_eq!(section.uri(), Uri::from_static("https://other.test/new"));
        assert_eq!(section.header_map()["x-second"], "two");

        let fields: Vec<_> = section.iter().collect();
        let names: Vec<_> = fields
            .iter()
            .map(|line| std::str::from_utf8(&line.name).expect("field name"))
            .collect();
        assert_eq!(
            &names[..5],
            [":method", ":protocol", ":scheme", ":authority", ":path"]
        );

        let cloned = section.clone();
        assert_eq!(cloned.into_header_map().len(), 2);

        let trailer = FieldSection::trailer(HeaderMap::new());
        assert!(trailer.is_empty());
        assert!(trailer.is_trailer());
        assert!(trailer.check_pseudo().is_ok());
    }

    #[test]
    fn response_field_section_accessors_and_iteration() {
        let mut section =
            FieldSection::header(PseudoHeaders::response(StatusCode::OK), HeaderMap::new());

        assert!(section.is_response_header());
        assert_eq!(section.status(), StatusCode::OK);

        section.set_status(StatusCode::ACCEPTED);
        assert_eq!(section.status(), StatusCode::ACCEPTED);

        let fields: Vec<_> = section.iter().collect();
        assert_eq!(fields, vec![FieldLine::from(StatusCode::ACCEPTED)]);
    }

    #[test]
    fn check_pseudo_validates_request_authority_and_connect_rules() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.test"));
        let valid = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            headers,
        );
        assert!(valid.check_pseudo().is_ok());

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("different.test"));
        let mismatch = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            headers,
        );
        assert!(matches!(
            mismatch.check_pseudo(),
            Err(MalformedHeaderSection::AuthorityHostMismatch)
        ));

        let extended_connect = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/session")),
                Some(Protocol::new("webtransport")),
            ),
            HeaderMap::new(),
        );
        assert!(extended_connect.check_pseudo().is_ok());

        let plain_connect = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                None,
                Some(Authority::from_static("example.test:443")),
                None,
                None,
            ),
            HeaderMap::new(),
        );
        assert!(plain_connect.check_pseudo().is_ok());
    }

    #[test]
    fn check_pseudo_reports_request_error_variants() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            HeaderValue::from_bytes(&[0xff]).expect("opaque header value"),
        );
        let invalid_host = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                None,
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            headers,
        );
        assert!(matches!(
            invalid_host.check_pseudo(),
            Err(MalformedHeaderSection::InvalidHostHeader)
        ));

        let missing = FieldSection::header(PseudoHeaders::unresolved_request(), HeaderMap::new());
        assert!(matches!(
            missing.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));

        let protocol_in_get = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/")),
                Some(Protocol::new("webtransport")),
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            protocol_in_get.check_pseudo(),
            Err(MalformedHeaderSection::ProtocolInNonConnectRequest)
        ));

        let connect_with_scheme = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test:443")),
                None,
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            connect_with_scheme.check_pseudo(),
            Err(MalformedHeaderSection::UnexpectedSchemeForConnectRequest)
        ));

        let connect_with_path = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                None,
                Some(Authority::from_static("example.test:443")),
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            connect_with_path.check_pseudo(),
            Err(MalformedHeaderSection::UnexpectedPathForConnectRequest)
        ));

        let connect_without_authority = FieldSection::header(
            request_pseudo(Some(Method::CONNECT), None, None, None, None),
            HeaderMap::new(),
        );
        assert!(matches!(
            connect_without_authority.check_pseudo(),
            Err(MalformedHeaderSection::MissingAuthorityForConnectRequest)
        ));

        let connect_without_port = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                None,
                Some(Authority::from_static("example.test")),
                None,
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            connect_without_port.check_pseudo(),
            Err(MalformedHeaderSection::MissingPortForConnectAuthority)
        ));
    }

    #[test]
    fn check_pseudo_reports_response_error_variants() {
        let response = FieldSection::header(PseudoHeaders::unresolved_response(), HeaderMap::new());
        assert!(matches!(
            response.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));
    }

    #[test]
    fn check_pseudo_validates_authority_host_presence_and_empty_values() {
        let authority_only = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            HeaderMap::new(),
        );
        assert!(authority_only.check_pseudo().is_ok());

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.test"));
        let host_only = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                None,
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            headers,
        );
        assert!(host_only.check_pseudo().is_ok());

        let missing_authority_and_host = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                None,
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            missing_authority_and_host.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static(""));
        let empty_host = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                None,
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            headers,
        );
        assert!(matches!(
            empty_host.check_pseudo(),
            Err(MalformedHeaderSection::EmptyAuthorityOrHost)
        ));

        let non_http_without_authority_or_host = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::try_from("urn").expect("scheme")),
                None,
                Some(PathAndQuery::from_static("/opaque")),
                None,
            ),
            HeaderMap::new(),
        );
        assert!(non_http_without_authority_or_host.check_pseudo().is_ok());
    }

    #[test]
    fn check_pseudo_requires_scheme_and_path_for_regular_and_extended_requests() {
        let missing_scheme = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                None,
                Some(Authority::from_static("example.test")),
                Some(PathAndQuery::from_static("/")),
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            missing_scheme.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));

        let missing_path = FieldSection::header(
            request_pseudo(
                Some(Method::GET),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                None,
                None,
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            missing_path.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));

        let extended_connect_missing_path = FieldSection::header(
            request_pseudo(
                Some(Method::CONNECT),
                Some(Scheme::HTTPS),
                Some(Authority::from_static("example.test")),
                None,
                Some(Protocol::new("webtransport")),
            ),
            HeaderMap::new(),
        );
        assert!(matches!(
            extended_connect_missing_path.check_pseudo(),
            Err(MalformedHeaderSection::AbsenceOfMandatoryPseudoHeaders { .. })
        ));
    }

    #[tokio::test]
    async fn decode_accepts_request_response_and_trailer_sections() {
        let request = decode_fields([
            field(b":method", b"GET"),
            field(b":scheme", b"https"),
            field(b":authority", b"example.test"),
            field(b":path", b"/hello"),
            field(b"host", b"example.test"),
        ])
        .await
        .expect("request field section");
        assert!(request.is_request_header());
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.uri(),
            Uri::from_static("https://example.test/hello")
        );
        assert_eq!(request.header_map()["host"], "example.test");

        let response = decode_fields([field(b":status", b"204"), field(b"server", b"h3x")])
            .await
            .expect("response field section");
        assert!(response.is_response_header());
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.header_map()["server"], "h3x");

        let trailer = decode_fields([field(b"x-trailer", b"done")])
            .await
            .expect("trailer field section");
        assert!(trailer.is_trailer());
        assert_eq!(trailer.header_map()["x-trailer"], "done");
    }

    #[tokio::test]
    async fn decode_accepts_options_asterisk_path() {
        let request = decode_fields([
            field(b":method", b"OPTIONS"),
            field(b":scheme", b"https"),
            field(b":authority", b"example.test"),
            field(b":path", b"*"),
        ])
        .await
        .expect("options request field section");

        assert!(request.check_pseudo().is_ok());
        assert_eq!(request.method(), Method::OPTIONS);
        assert_eq!(request.path().as_ref().map(PathAndQuery::as_str), Some("*"));
        assert!(request.iter().any(|line| {
            line.name == Bytes::from_static(PseudoHeaders::PATH.as_bytes())
                && line.value == Bytes::from_static(b"*")
        }));
    }

    #[tokio::test]
    async fn decode_rejects_pseudo_header_after_regular_header() {
        let fields = futures::stream::iter([
            Ok(FieldLine {
                name: Bytes::from_static(b"host"),
                value: Bytes::from_static(b"reimu.pilot.genmeta.net"),
            }),
            Ok(FieldLine {
                name: Bytes::from_static(b":method"),
                value: Bytes::from_static(b"GET"),
            }),
        ]);

        let error = FieldSection::decode_from(fields).await.unwrap_err();

        let StreamError::H3 { source } = error else {
            panic!("expected stream-scope H3 error");
        };
        assert_eq!(
            source.to_string(),
            "pseudo-header field appears after regular header field"
        );
    }

    #[tokio::test]
    async fn decode_reports_duplicate_mixed_invalid_and_parse_errors() {
        let duplicate = decode_fields([field(b":method", b"GET"), field(b":method", b"POST")])
            .await
            .expect_err("duplicate pseudo header");
        assert_h3_error(
            duplicate,
            "duplicate pseudo-header field with name b\":method\"",
        );

        let mixed = decode_fields([field(b":method", b"GET"), field(b":status", b"200")])
            .await
            .expect_err("mixed request and response pseudo headers");
        assert_h3_error(
            mixed,
            "field section contains both request and response pseudo-header fields",
        );

        let invalid = decode_fields([field(b":unknown", b"value")])
            .await
            .expect_err("unknown pseudo header");
        assert_h3_error(
            invalid,
            "invalid pseudo-header field with name b\":unknown\"",
        );

        let invalid_protocol =
            decode_fields([field(b":method", b"CONNECT"), field(b":protocol", &[0xff])])
                .await
                .expect_err("invalid protocol token");
        assert_h3_error(invalid_protocol, "invalid :protocol pseudo-header token");

        let invalid_status = decode_fields([field(b":status", b"not-a-status")])
            .await
            .expect_err("invalid status");
        assert_h3_error(invalid_status, "invalid status code");
    }

    #[tokio::test]
    async fn decode_reports_duplicate_request_and_response_pseudo_headers() {
        for (name, first, second) in [
            (
                b":protocol" as &'static [u8],
                b"webtransport" as &'static [u8],
                b"websocket" as &'static [u8],
            ),
            (b":scheme", b"https", b"http"),
            (b":authority", b"example.test", b"other.test"),
            (b":path", b"/one", b"/two"),
            (b":status", b"200", b"204"),
        ] {
            let duplicate = decode_fields([field(name, first), field(name, second)])
                .await
                .expect_err("duplicate pseudo header");
            assert_h3_error(
                duplicate,
                &format!(
                    "duplicate pseudo-header field with name {:?}",
                    Bytes::from_static(name)
                ),
            );
        }
    }

    #[tokio::test]
    async fn decode_reports_parse_errors_for_pseudo_and_regular_fields() {
        let invalid_method = decode_fields([field(b":method", b"bad method")])
            .await
            .expect_err("invalid method");
        assert_h3_error(invalid_method, "invalid HTTP method");

        let invalid_scheme = decode_fields([field(b":scheme", b"://")])
            .await
            .expect_err("invalid scheme");
        assert_h3_error(invalid_scheme, "invalid scheme");

        let invalid_authority = decode_fields([field(b":authority", b"bad authority")])
            .await
            .expect_err("invalid authority");
        assert_h3_error(invalid_authority, "invalid uri character");

        let invalid_path = decode_fields([field(b":path", b"bad path")])
            .await
            .expect_err("invalid path");
        assert_h3_error_one_of(
            invalid_path,
            &["invalid uri character", "path does not start with slash"],
        );

        let invalid_header_name = decode_fields([field(b"bad header", b"value")])
            .await
            .expect_err("invalid header name");
        assert_h3_error(invalid_header_name, "invalid HTTP header name");

        let invalid_header_value = decode_fields([field(b"x-test", b"bad\nvalue")])
            .await
            .expect_err("invalid header value");
        assert_h3_error(invalid_header_value, "failed to parse header value");
    }

    #[tokio::test]
    async fn decode_propagates_source_stream_error() {
        let error = FieldSection::decode_from(stream::iter([Err(StreamError::Reset {
            code: 42u32.into(),
        })]))
        .await
        .expect_err("source stream error");

        assert!(matches!(error, StreamError::Reset { code } if code.into_inner() == 42));
    }

    #[tokio::test]
    async fn malformed_header_section_display_and_source_are_structured() {
        let error = decode_fields([field(b":protocol", &[0xff])])
            .await
            .expect_err("invalid protocol token");
        let StreamError::H3 { source } = error else {
            panic!("expected stream-scope H3 error");
        };
        assert_eq!(source.to_string(), "invalid :protocol pseudo-header token");
        assert!(std::error::Error::source(source.as_ref()).is_some());

        let error = decode_fields([field(b":status", b"not-a-status")])
            .await
            .expect_err("invalid status");
        let StreamError::H3 { source } = error else {
            panic!("expected stream-scope H3 error");
        };
        assert_eq!(source.to_string(), "invalid status code");
        assert!(std::error::Error::source(source.as_ref()).is_none());
    }
}
