use std::pin::pin;

use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{self, HeaderName, HeaderValue},
    method,
    request::{self, Request},
    response::{self, Response},
    status,
    uri::{self, Authority, PathAndQuery, Scheme},
};
use snafu::{Snafu, ensure};

use crate::{
    codec::Decode,
    connection::StreamError,
    error::{Code, HasErrorCode},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FieldLine {
    pub name: Bytes,
    pub value: Bytes,
}

impl FieldLine {
    /// The size of an entry is the sum of its name's length in bytes, its
    /// value's length in bytes, and 32 additional bytes. The size of an
    /// entry is calculated using the length of its name and value without
    /// Huffman encoding applied.
    ///
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-3.2.1-2
    pub fn size(&self) -> u64 {
        self.name.len() as u64 + self.value.len() as u64 + 32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PseudoHeaders {
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-request-pseudo-header-field
    Request {
        method: Option<Method>,
        scheme: Option<Scheme>,
        authority: Option<Authority>,
        path: Option<PathAndQuery>,
    },
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-response-pseudo-header-fiel
    Response { status: Option<StatusCode> },
}

impl PseudoHeaders {
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
        }
    }

    pub const fn unresolved_response() -> Self {
        PseudoHeaders::Response { status: None }
    }
}

#[derive(Debug, Snafu)]
pub enum InvalidHeaderSection {
    #[snafu(display("Invalid pseudo-header field with name {name:?}"))]
    InvalidPseudoHeader { name: Bytes },
    #[snafu(display("Duplicate pseudo-header field with name {name:?}"))]
    DuplicatePseudoHeader { name: Bytes },
    #[snafu(display("Field section contains both request and response pseudo-header fields"))]
    DualKindedPseudoHeader,
    #[snafu(display("Request Pseudo-header field in response"))]
    RequestPseudoHeaderInResponse,
    #[snafu(display("Response Pseudo-header field in request"))]
    ResponsePseudoHeaderInRequest,
    #[snafu(display("Field section contains pseudo-header fields in tailers"))]
    PseudoHeaderInTailers,
    #[snafu(display("Field section too large"))]
    FieldSectionTooLarge,
    #[snafu(display("Absence of mandatory pseudo-header fields"))]
    AbsenceOfMandatoryPseudoHeaders,
    #[snafu(transparent)]
    InvalidMessage { source: http::Error },
}

impl HasErrorCode for InvalidHeaderSection {
    fn code(&self) -> Code {
        Code::H3_MESSAGE_ERROR
    }
}

impl From<method::InvalidMethod> for InvalidHeaderSection {
    fn from(error: method::InvalidMethod) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<uri::InvalidUri> for InvalidHeaderSection {
    fn from(error: uri::InvalidUri) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<status::InvalidStatusCode> for InvalidHeaderSection {
    fn from(error: status::InvalidStatusCode) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::MaxSizeReached> for InvalidHeaderSection {
    fn from(error: header::MaxSizeReached) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::InvalidHeaderName> for InvalidHeaderSection {
    fn from(error: header::InvalidHeaderName) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

impl From<header::InvalidHeaderValue> for InvalidHeaderSection {
    fn from(error: header::InvalidHeaderValue) -> Self {
        InvalidHeaderSection::InvalidMessage {
            source: error.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSection {
    pub(crate) pseudo_headers: Option<PseudoHeaders>,
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

    pub fn iter(&self) -> Iter<'_> {
        IntoIterator::into_iter(self)
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
            match name.as_ref() {
                b":method" => {
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let method = match &mut pseudo {
                        PseudoHeaders::Request { method, .. } => method,
                        PseudoHeaders::Response { .. } => {
                            return Err(InvalidHeaderSection::DualKindedPseudoHeader.into());
                        }
                    };
                    ensure!(method.is_none(), DuplicatePseudoHeaderSnafu { name });
                    *method =
                        Some(Method::from_bytes(&value[..]).map_err(InvalidHeaderSection::from)?);
                    pseudo_headers = Some(pseudo)
                }
                b":scheme" => {
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let scheme = match &mut pseudo {
                        PseudoHeaders::Request { scheme, .. } => scheme,
                        PseudoHeaders::Response { .. } => {
                            return Err(InvalidHeaderSection::DualKindedPseudoHeader.into());
                        }
                    };
                    ensure!(scheme.is_none(), DuplicatePseudoHeaderSnafu { name });
                    *scheme =
                        Some(Scheme::try_from(&value[..]).map_err(InvalidHeaderSection::from)?);
                    pseudo_headers = Some(pseudo)
                }
                b":authority" => {
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());
                    let authority = match &mut pseudo {
                        PseudoHeaders::Request { authority, .. } => authority,
                        PseudoHeaders::Response { .. } => {
                            return Err(InvalidHeaderSection::DualKindedPseudoHeader.into());
                        }
                    };
                    ensure!(authority.is_none(), DuplicatePseudoHeaderSnafu { name });
                    *authority = Some(
                        Authority::from_maybe_shared(value).map_err(InvalidHeaderSection::from)?,
                    );
                    pseudo_headers = Some(pseudo)
                }
                b":path" => {
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_request());

                    let scheme = match &mut pseudo {
                        PseudoHeaders::Request { path, .. } => path,
                        PseudoHeaders::Response { .. } => {
                            return Err(InvalidHeaderSection::DualKindedPseudoHeader.into());
                        }
                    };
                    ensure!(scheme.is_none(), DuplicatePseudoHeaderSnafu { name });
                    *scheme = Some(
                        PathAndQuery::from_maybe_shared(value)
                            .map_err(InvalidHeaderSection::from)?,
                    );
                    pseudo_headers = Some(pseudo)
                }
                b"status" => {
                    let mut pseudo = pseudo_headers
                        .take()
                        .unwrap_or(PseudoHeaders::unresolved_response());

                    let status = match &mut pseudo {
                        PseudoHeaders::Response { status, .. } => status,
                        PseudoHeaders::Request { .. } => {
                            return Err(InvalidHeaderSection::DualKindedPseudoHeader.into());
                        }
                    };
                    ensure!(status.is_none(), DuplicatePseudoHeaderSnafu { name });
                    *status =
                        Some(StatusCode::try_from(&value[..]).map_err(InvalidHeaderSection::from)?);
                    pseudo_headers = Some(pseudo)
                }

                invalid_pseudo if invalid_pseudo.starts_with(b":") => {
                    return Err(InvalidHeaderSection::InvalidPseudoHeader { name }.into());
                }
                name => {
                    header_map
                        .try_append(
                            HeaderName::from_bytes(name).map_err(InvalidHeaderSection::from)?,
                            HeaderValue::from_maybe_shared(value)
                                .map_err(InvalidHeaderSection::from)?,
                        )
                        .map_err(InvalidHeaderSection::from)?;
                }
            }
        }

        Ok(FieldSection {
            pseudo_headers,
            header_map,
        })
    }
}

impl From<request::Parts> for FieldSection {
    fn from(request: request::Parts) -> Self {
        Self {
            pseudo_headers: Some(PseudoHeaders::request(request.method, request.uri)),
            header_map: request.headers,
        }
    }
}

impl TryFrom<FieldSection> for request::Parts {
    type Error = InvalidHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Request {
            method,
            scheme,
            authority,
            path,
        } = value
            .pseudo_headers
            .ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?
        else {
            return Err(InvalidHeaderSection::ResponsePseudoHeaderInRequest);
        };

        let mut uri = Uri::builder();
        if let Some(scheme) = scheme {
            uri = uri.scheme(scheme);
        }
        if let Some(authority) = authority {
            uri = uri.authority(authority)
        }
        if let Some(path) = path {
            uri = uri.path_and_query(path);
        }
        let uri = uri.build()?;
        let method = method.ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?;
        let mut request = Request::builder().uri(uri).method(method).body(())?;
        *request.headers_mut() = value.header_map;

        Ok(request.into_parts().0)
    }
}

impl From<response::Parts> for FieldSection {
    fn from(response: response::Parts) -> Self {
        Self {
            pseudo_headers: Some(PseudoHeaders::response(response.status)),
            header_map: response.headers,
        }
    }
}

impl TryFrom<FieldSection> for response::Parts {
    type Error = InvalidHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Response { status } = value
            .pseudo_headers
            .ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?
        else {
            return Err(InvalidHeaderSection::RequestPseudoHeaderInResponse);
        };

        let status = status.ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?;
        let response = Response::builder().status(status).body(())?;
        Ok(response.into_parts().0)
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
                } => {
                    if let Some(method) = method.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":method"),
                            value: Bytes::copy_from_slice(method.as_str().as_bytes()),
                        });
                    }
                    if let Some(scheme) = scheme.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":scheme"),
                            value: Bytes::copy_from_slice(scheme.as_str().as_bytes()),
                        });
                    }
                    if let Some(authority) = authority.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":authority"),
                            value: Bytes::copy_from_slice(authority.as_str().as_bytes()),
                        });
                    }
                    if let Some(path) = path.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":path"),
                            value: Bytes::copy_from_slice(path.as_str().as_bytes()),
                        });
                    }
                }
                PseudoHeaders::Response { status } => {
                    if let Some(status) = status.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":status"),
                            value: Bytes::copy_from_slice(status.as_str().as_bytes()),
                        });
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
