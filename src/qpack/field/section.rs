use std::pin::pin;

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
    codec::Decode,
    connection::StreamError,
    error::{Code, HasErrorCode},
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

impl HasErrorCode for MalformedHeaderSection {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSection {
    pub(crate) pseudo_headers: Option<super::PseudoHeaders>,
    pub(crate) header_map: HeaderMap,
}

impl FieldSection {
    pub fn header(pseudo_headers: PseudoHeaders, header_map: HeaderMap) -> Self {
        Self {
            pseudo_headers: Some(pseudo_headers),
            header_map,
        }
    }

    pub fn trailer(header_map: HeaderMap) -> Self {
        Self {
            pseudo_headers: None,
            header_map,
        }
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
                                let host = host
                                    .to_str()
                                    .map_err(|_| MalformedHeaderSection::InvalidHostHeader)?;
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
                                let host = host
                                    .to_str()
                                    .map_err(|_| MalformedHeaderSection::InvalidHostHeader)?;
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
        method.clone().unwrap()
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

    pub fn uri(&self) -> Uri {
        let mut uri = uri::Parts::default();
        uri.scheme = self.scheme();
        uri.authority = self.authority();
        uri.path_and_query = self.path();
        Uri::from_parts(uri).unwrap()
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
        status.unwrap()
    }

    pub fn set_status(&mut self, new: StatusCode) {
        let Some(PseudoHeaders::Response { status, .. }) = &mut self.pseudo_headers else {
            panic!("FieldSection is not response headers")
        };
        *status = Some(new)
    }
}

impl<S: Stream<Item = Result<FieldLine, StreamError>>> Decode<FieldSection> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<FieldSection, Self::Error> {
        let mut stream = pin!(self);

        let mut pseudo_headers = None;
        let mut header_map = HeaderMap::new();
        while let Some(FieldLine { name, value }) = stream.try_next().await? {
            match name {
                name if name == PseudoHeaders::METHOD => {
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
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());

                    let scheme = match &mut pseudo {
                        PseudoHeaders::Request { path, .. } => path,
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
                    *scheme = Some(
                        PathAndQuery::from_maybe_shared(value)
                            .map_err(MalformedHeaderSection::from)?,
                    );
                    pseudo_headers = Some(pseudo)
                }
                name if name == PseudoHeaders::STATUS => {
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
                    return Err(MalformedHeaderSection::InvalidPseudoHeader { name }.into());
                }
                name => {
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
            header_map,
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
