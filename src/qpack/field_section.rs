use bytes::Bytes;
use futures::{Stream, TryStreamExt};
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{self, HeaderName, HeaderValue},
    request::{self, Request},
    response::{self, Response},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::{Snafu, ensure};

use crate::{
    codec::util::DecodeFrom,
    error::{Code, Error, HasErrorCode},
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
        method: Option<HeaderValue>,
        scheme: Option<HeaderValue>,
        authority: Option<HeaderValue>,
        path: Option<HeaderValue>,
    },
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-response-pseudo-header-fiel
    Response { status: Option<HeaderValue> },
}

impl PseudoHeaders {
    const fn empty_request() -> Self {
        PseudoHeaders::Request {
            method: None,
            scheme: None,
            authority: None,
            path: None,
        }
    }

    const fn empty_response() -> Self {
        PseudoHeaders::Response { status: None }
    }

    pub fn get<'s>(&'s self, name: &[u8]) -> &'s Option<HeaderValue> {
        match self {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
            } => match name {
                b":method" => method,
                b":scheme" => scheme,
                b":authority" => authority,
                b":path" => path,
                _ => unreachable!(),
            },
            PseudoHeaders::Response { status } => match name {
                b":status" => status,
                _ => unreachable!(),
            },
        }
    }

    pub fn get_mut<'s>(&'s mut self, name: &[u8]) -> &'s mut Option<HeaderValue> {
        match self {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
            } => match name {
                b":method" => method,
                b":scheme" => scheme,
                b":authority" => authority,
                b":path" => path,
                _ => unreachable!(),
            },
            PseudoHeaders::Response { status } => match name {
                b":status" => status,
                _ => unreachable!(),
            },
        }
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
    #[snafu(display("Invalid header name"))]
    InvalidHeaderName,
    #[snafu(display("Invalid header value"))]
    InvalidHeaderValue,
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

impl From<header::MaxSizeReached> for InvalidHeaderSection {
    fn from(_: header::MaxSizeReached) -> Self {
        InvalidHeaderSection::FieldSectionTooLarge
    }
}

impl From<header::InvalidHeaderName> for InvalidHeaderSection {
    fn from(_: header::InvalidHeaderName) -> Self {
        InvalidHeaderSection::InvalidHeaderName
    }
}

impl From<header::InvalidHeaderValue> for InvalidHeaderSection {
    fn from(_: header::InvalidHeaderValue) -> Self {
        InvalidHeaderSection::InvalidHeaderValue
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSection {
    pseudo_headers: PseudoHeaders,
    header_map: HeaderMap,
}

impl FieldSection {
    pub fn try_into_trailers(self) -> Result<HeaderMap, InvalidHeaderSection> {
        match self.pseudo_headers {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
            } => {
                ensure!(
                    method.is_none() && scheme.is_none() && authority.is_none() && path.is_none(),
                    PseudoHeaderInTailersSnafu
                );
            }
            PseudoHeaders::Response { status } => {
                ensure!(status.is_none(), PseudoHeaderInTailersSnafu);
            }
        }
        Ok(self.header_map)
    }
}

impl From<HeaderMap> for FieldSection {
    fn from(header_map: HeaderMap) -> Self {
        Self {
            pseudo_headers: PseudoHeaders::empty_request(),
            header_map,
        }
    }
}

fn is_request_pseudo_header(name: &[u8]) -> bool {
    matches!(name, b":method" | b":scheme" | b":authority" | b":path")
}

fn is_response_pseudo_header(name: &[u8]) -> bool {
    matches!(name, b":status")
}

impl<S> DecodeFrom<S> for FieldSection
where
    S: Stream<Item = Result<FieldLine, Error>>,
{
    type Error = Error;

    async fn decode_from(stream: S) -> Result<Self, Error> {
        tokio::pin!(stream);

        let mut pseudo_header = None;
        let mut header_map = HeaderMap::new();
        while let Some(FieldLine { name, value }) = stream.try_next().await? {
            match name.as_ref() {
                pseudo if pseudo.starts_with(b":") && is_request_pseudo_header(&name) => {
                    ensure!(
                        matches!(pseudo_header, None | Some(PseudoHeaders::Request { .. })),
                        DualKindedPseudoHeaderSnafu
                    );
                    if pseudo_header.is_none() {
                        pseudo_header = Some(PseudoHeaders::empty_request());
                    }
                    let psudo_header_value = pseudo_header.as_mut().unwrap().get_mut(pseudo);
                    ensure!(
                        psudo_header_value.is_none(),
                        DuplicatePseudoHeaderSnafu { name }
                    );
                    *psudo_header_value = Some(
                        HeaderValue::from_maybe_shared(value)
                            .map_err(InvalidHeaderSection::from)?,
                    );
                }
                pseudo if pseudo.starts_with(b":") && is_response_pseudo_header(&name) => {
                    ensure!(
                        matches!(pseudo_header, None | Some(PseudoHeaders::Response { .. })),
                        DualKindedPseudoHeaderSnafu
                    );
                    if pseudo_header.is_none() {
                        pseudo_header = Some(PseudoHeaders::empty_response());
                    }
                    let psudo_header_value = pseudo_header.as_mut().unwrap().get_mut(pseudo);
                    ensure!(
                        psudo_header_value.is_none(),
                        DuplicatePseudoHeaderSnafu { name }
                    );
                    *psudo_header_value = Some(
                        HeaderValue::from_maybe_shared(value)
                            .map_err(InvalidHeaderSection::from)?,
                    );
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

        Ok(Self {
            pseudo_headers: pseudo_header
                .ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?,
            header_map,
        })
    }
}

impl TryFrom<request::Parts> for FieldSection {
    type Error = InvalidHeaderSection;

    fn try_from(request: request::Parts) -> Result<Self, Self::Error> {
        let path = match request.uri.path_and_query() {
            Some(path_and_query) => Some(HeaderValue::from_str(path_and_query.as_str())?),
            // This pseudo-header field MUST NOT be empty for "http" or "https"
            // URIs; "http" or "https" URIs that do not contain a path component
            // MUST include a value of / (ASCII 0x2f). An OPTIONS request that
            // does not include a path component includes the value * (ASCII
            // 0x2a) for the :path pseudo-header field; see Section 7.1 of
            // [HTTP].
            //
            // https://datatracker.ietf.org/doc/html/rfc9114#section-4.3.1-2.16.1
            None if request.uri.scheme() == Some(&Scheme::HTTP)
                || request.uri.scheme() == Some(&Scheme::HTTPS) =>
            {
                Some(HeaderValue::from_static("/"))
            }
            None if request.method == http::Method::OPTIONS => Some(HeaderValue::from_static("*")),
            None => None,
        };
        Ok(Self {
            pseudo_headers: PseudoHeaders::Request {
                method: Some(HeaderValue::from_str(request.method.as_str())?),
                scheme: (request.uri.scheme())
                    .map(|scheme| HeaderValue::from_str(scheme.as_str()))
                    .transpose()?,
                authority: (request.uri.authority())
                    .map(|authority| HeaderValue::from_str(authority.as_str()))
                    .transpose()?,
                path,
            },
            header_map: request.headers,
        })
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
        } = value.pseudo_headers
        else {
            return Err(InvalidHeaderSection::ResponsePseudoHeaderInRequest);
        };

        let mut uri = Uri::builder();
        if let Some(scheme) = scheme {
            uri = uri.scheme(Scheme::try_from(scheme.as_bytes()).map_err(http::Error::from)?);
        }
        if let Some(authority) = authority {
            uri = uri.authority(Authority::from_maybe_shared(authority).map_err(http::Error::from)?)
        }
        if let Some(path) = path {
            uri = uri
                .path_and_query(PathAndQuery::from_maybe_shared(path).map_err(http::Error::from)?);
        }
        let uri = uri.build()?;
        let method = method.ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?;

        let request = Request::builder()
            .uri(uri)
            .method(Method::from_bytes(method.as_bytes()).map_err(http::Error::from)?)
            .body(())?;

        Ok(request.into_parts().0)
    }
}

impl TryFrom<response::Parts> for FieldSection {
    type Error = InvalidHeaderSection;

    fn try_from(response: response::Parts) -> Result<Self, Self::Error> {
        Ok(Self {
            pseudo_headers: PseudoHeaders::Response {
                status: Some(HeaderValue::from_str(response.status.as_str())?),
            },
            header_map: response.headers,
        })
    }
}

impl TryFrom<FieldSection> for response::Parts {
    type Error = InvalidHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Response { status } = value.pseudo_headers else {
            return Err(InvalidHeaderSection::RequestPseudoHeaderInResponse);
        };

        let status = status.ok_or(InvalidHeaderSection::AbsenceOfMandatoryPseudoHeaders)?;
        let status = StatusCode::from_bytes(status.as_bytes()).map_err(http::Error::from)?;

        let response = Response::builder().status(status).body(())?;
        Ok(response.into_parts().0)
    }
}

impl IntoIterator for FieldSection {
    type Item = FieldLine;
    type IntoIter = IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        let header_map_iter = self.header_map.into_iter();
        let last_field_name = Bytes::new();
        IntoIter {
            pseudo_headers: Some(self.pseudo_headers),
            header_map_iter,
            last_field_name,
        }
    }
}

pub struct IntoIter {
    pseudo_headers: Option<PseudoHeaders>,
    header_map_iter: http::header::IntoIter<HeaderValue>,
    last_field_name: Bytes,
}

impl Iterator for IntoIter {
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
                            value: Bytes::from_owner(method),
                        });
                    }
                    if let Some(scheme) = scheme.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":scheme"),
                            value: Bytes::from_owner(scheme),
                        });
                    }
                    if let Some(authority) = authority.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":authority"),
                            value: Bytes::from_owner(authority),
                        });
                    }
                    if let Some(path) = path.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":path"),
                            value: Bytes::from_owner(path),
                        });
                    }
                }
                PseudoHeaders::Response { status } => {
                    if let Some(status) = status.take() {
                        return Some(FieldLine {
                            name: Bytes::from_static(b":status"),
                            value: Bytes::from_owner(status),
                        });
                    }
                }
            }
        };
        self.pseudo_headers = None;

        if let Some((name, value)) = self.header_map_iter.next() {
            if let Some(name) = name {
                self.last_field_name = Bytes::copy_from_slice(name.as_str().as_bytes());
            }
            return Some(FieldLine {
                name: self.last_field_name.clone(),
                value: Bytes::from_owner(value),
            });
        }

        None
    }
}
