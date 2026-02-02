use std::pin::pin;

use bytes::{Buf, Bytes};
use futures::{Sink, Stream, TryStreamExt};
use http::{
    HeaderMap, Method, StatusCode, Uri,
    header::{self, HeaderName, HeaderValue},
    method,
    request::{self, Request},
    response::{self, Response},
    status,
    uri::{self, Authority, PathAndQuery, Scheme},
};
use snafu::{OptionExt, Snafu, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    buflist::BufList,
    codec::{
        Decode, DecodeError, DecodeStreamError, Encode, EncodeError, EncodeExt, EncodeStreamError,
    },
    connection::StreamError,
    error::{Code, HasErrorCode},
    frame::Frame,
    qpack::{
        integer::{decode_integer, encode_integer},
        string::{decode_string, encode_string},
    },
};

///
/// ``` ignore
///   0   1   2   3   4   5   6   7
/// +---+---+---+---+---+---+---+---+
/// |   Required Insert Count (8+)  |
/// +---+---------------------------+
/// | S |      Delta Base (7+)      |
/// +---+---------------------------+
/// |      Encoded Field Lines    ...
/// +-------------------------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFieldSectionPrefix {
    pub required_insert_count: u64,
    /// The Base is used to resolve references in the dynamic table as
    /// described in Section 3.2.5.
    ///
    /// To save space, the Base is encoded relative to the Required Insert
    /// Count using a one-bit Sign ('S' in Figure 12) and the Delta Base
    /// value. A Sign bit of 0 indicates that the Base is greater than or
    /// equal to the value of the Required Insert Count; the decoder adds the
    /// value of Delta Base to the Required Insert Count to determine the
    /// value of the Base. A Sign bit of 1 indicates that the Base is less
    /// than the Required Insert Count; the decoder subtracts the value of
    /// Delta Base from the Required Insert Count and also subtracts one to
    /// determine the value of the Base. That is:
    ///
    /// ``` fakecode
    /// if Sign == 0:
    ///    Base = ReqInsertCount + DeltaBase
    /// else:
    ///    Base = ReqInsertCount - DeltaBase - 1
    /// ```
    /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2
    // sign: bool,
    // delta_base: u64,
    pub base: u64,
}

impl<S: AsyncRead> Decode<EncodedFieldSectionPrefix> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<EncodedFieldSectionPrefix, Self::Error> {
        let decode = async move {
            let mut stream = pin!(self);
            let ric_prefix = stream.read_u8().await?;
            let required_insert_count = decode_integer(stream.as_mut(), ric_prefix, 8).await?;
            let db_prefix = stream.read_u8().await?;
            let sign = db_prefix & 0b1000_0000;
            let delta_base = decode_integer(stream.as_mut(), db_prefix & 0b0111_1111, 7).await?;
            // The value of Base MUST NOT be negative. Though the protocol might
            // operate correctly with a negative Base using post-Base indexing, it
            // is unnecessary and inefficient. An endpoint MUST treat a field block
            // with a Sign bit of 1 as invalid if the value of Required Insert Count
            // is less than or equal to the value of Delta Base.
            //
            // https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2-5
            let base = if sign == 0 {
                required_insert_count
                    .checked_add(delta_base)
                    .ok_or(DecodeError::ArithmeticOverflow)?
            } else {
                required_insert_count
                    .checked_sub(delta_base)
                    .ok_or(DecodeError::ArithmeticOverflow)?
                    .checked_sub(1)
                    .ok_or(DecodeError::ArithmeticOverflow)?
            };
            Ok(EncodedFieldSectionPrefix {
                required_insert_count,
                base,
            })
        };
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
        })
    }
}

impl<S: AsyncWrite> Encode<EncodedFieldSectionPrefix> for S {
    type Output = ();

    type Error = EncodeStreamError;

    async fn encode(self, item: EncodedFieldSectionPrefix) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(self);
        let ric_prefix = 0;
        encode_integer(stream.as_mut(), ric_prefix, 8, item.required_insert_count).await?;
        // if Sign == 0:
        //    Base = ReqInsertCount + DeltaBase
        //    -> DeltaBase = Base - ReqInsertCount (Base >= ReqInsertCount)
        // else:
        //    Base = ReqInsertCount - DeltaBase - 1
        //    -> DeltaBase = ReqInsertCount - Base - 1 (Base < ReqInsertCount)
        let (sign, db_value) = if item.base >= item.required_insert_count {
            (false, item.base - item.required_insert_count)
        } else {
            (true, item.required_insert_count - item.base - 1)
        };
        let db_prefix = if sign { 0b1000_0000 } else { 0b0000_0000 };
        encode_integer(stream.as_mut(), db_prefix, 7, db_value).await?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLineRepresentation {
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 | T |      Index (6+)       |
    /// +---+---+-----------------------+
    /// ```
    IndexedFieldLine { is_static: bool, index: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+---+---+---------------+
    /// ```
    IndexedFieldLineWithPostBaseIndex { index: u64 },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 | N | T |Name Index (4+)|
    /// +---+---+---+---+---------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithNameReference {
        /// This representation starts with the '01' 2-bit pattern. The following
        /// bit, 'N', indicates whether an intermediary is permitted to add this
        /// field line to the dynamic table on subsequent hops. When the 'N' bit
        /// is set, the encoded field line MUST always be encoded with a literal
        /// representation. In particular, when a peer sends a field line that it
        /// received represented as a literal field line with the 'N' bit set, it
        /// MUST use a literal representation to forward this field line. This
        /// bit is intended for protecting field values that are not to be put at
        /// risk by compressing them; see Section 7.1 for more details.
        ///
        /// https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.4-3
        //
        never_dynamic: bool,
        is_static: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
    /// +---+---+---+---+---+-----------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithPostBaseNameReference {
        never_dynamic: bool,
        name_index: u64,
        huffman: bool,
        value: Bytes,
    },
    /// ``` ignore
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 | N | H |NameLen(3+)|
    /// +---+---+---+---+---+-----------+
    /// |  Name String (Length bytes)   |
    /// +---+---------------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// |  Value String (Length bytes)  |
    /// +-------------------------------+
    /// ```
    LiteralFieldLineWithLiteralName {
        never_dynamic: bool,
        name_huffman: bool,
        name: Bytes,
        value_huffman: bool,
        value: Bytes,
    },
}

impl<S: AsyncRead> Decode<FieldLineRepresentation> for S {
    type Error = StreamError;

    async fn decode(self) -> Result<FieldLineRepresentation, Self::Error> {
        let decode = async move {
            let mut stream = pin!(self);
            let prefix = stream.read_u8().await?;
            match prefix {
                prefix if prefix & 0b1000_0000 == 0b1000_0000 => {
                    // Indexed Field Line
                    let is_static = (prefix & 0b0100_0000) != 0;
                    let index = decode_integer(stream, prefix, 6).await?;
                    Ok(FieldLineRepresentation::IndexedFieldLine { is_static, index })
                }
                prefix if prefix & 0b1111_0000 == 0b0001_0000 => {
                    // Indexed Field Line with Post-Base Index
                    let index = decode_integer(stream, prefix, 4).await?;
                    Ok(FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index })
                }
                prefix if prefix & 0b1100_0000 == 0b0100_0000 => {
                    // Literal Field Line with Name Reference
                    let never_dynamic = (prefix & 0b0010_0000) != 0;
                    let is_static = (prefix & 0b0001_0000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 4).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithNameReference {
                        never_dynamic,
                        is_static,
                        name_index,
                        huffman,
                        value,
                    })
                }
                prefix if prefix & 0b1110_0000 == 0b0010_0000 => {
                    // Literal Field Line with Literal Name
                    let never_dynamic = (prefix & 0b0001_0000) != 0;
                    let name_prefix = prefix;
                    let (name_huffman, name) =
                        decode_string(stream.as_mut(), name_prefix, 1 + 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (value_huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                        never_dynamic,
                        name_huffman,
                        name,
                        value_huffman,
                        value,
                    })
                }
                prefix if prefix & 0b1111_0000 == 0b0000_0000 => {
                    // Literal Field Line with Post-Base Name Reference
                    let never_dynamic = (prefix & 0b0000_1000) != 0;
                    let name_index = decode_integer(stream.as_mut(), prefix, 3).await?;
                    let value_prefix = stream.read_u8().await?;
                    let (huffman, value) =
                        decode_string(stream.as_mut(), value_prefix, 1 + 7).await?;
                    Ok(
                        FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                            never_dynamic,
                            name_index,
                            huffman,
                            value,
                        },
                    )
                }
                prefix => unreachable!(
                    "unreachable branch(LiteralFieldLineWithPostBaseNameReference should match all other cases)(prefix={prefix:#010b})",
                ),
            }
        };
        decode.await.map_err(|error: DecodeStreamError| {
            error.map_decode_error(|decode_error| Code::H3_FRAME_ERROR.with(decode_error).into())
        })
    }
}

impl<S, E> Encode<FieldLineRepresentation> for S
where
    S: AsyncWrite + Sink<Bytes, Error = E>,
    EncodeStreamError: From<E>,
{
    type Output = ();

    type Error = EncodeStreamError;

    async fn encode(self, repr: FieldLineRepresentation) -> Result<Self::Output, Self::Error> {
        let mut stream = pin!(self);
        match repr {
            FieldLineRepresentation::IndexedFieldLine { is_static, index } => {
                let mut prefix = 0b1000_0000;
                if is_static {
                    prefix |= 0b0100_0000;
                }
                encode_integer(stream, prefix, 6, index).await?;
            }
            FieldLineRepresentation::IndexedFieldLineWithPostBaseIndex { index } => {
                encode_integer(stream, 0b0001_0000, 4, index).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithNameReference {
                never_dynamic,
                is_static,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0100_0000;
                if never_dynamic {
                    prefix |= 0b0010_0000;
                }
                if is_static {
                    prefix |= 0b0001_0000;
                }
                encode_integer(stream.as_mut(), prefix, 4, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithPostBaseNameReference {
                never_dynamic,
                name_index,
                huffman,
                value,
            } => {
                let mut prefix = 0b0000_0000;
                if never_dynamic {
                    prefix |= 0b0000_1000;
                }
                encode_integer(stream.as_mut(), prefix, 3, name_index).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, huffman, value).await?;
            }
            FieldLineRepresentation::LiteralFieldLineWithLiteralName {
                never_dynamic,
                name_huffman,
                name,
                value_huffman,
                value,
            } => {
                let mut prefix = 0b0010_0000;
                if never_dynamic {
                    prefix |= 0b0001_0000;
                }
                encode_string(stream.as_mut(), prefix, 1 + 3, name_huffman, name).await?;
                encode_string(stream.as_mut(), 0, 1 + 7, value_huffman, value).await?;
            }
        }
        Ok(())
    }
}

impl Encode<(EncodedFieldSectionPrefix, Vec<FieldLineRepresentation>)> for BufList {
    type Output = Frame<BufList>;

    type Error = EncodeError;

    async fn encode(
        self,
        (field_section_prefix, field_line_representations): (
            EncodedFieldSectionPrefix,
            Vec<FieldLineRepresentation>,
        ),
    ) -> Result<Self::Output, Self::Error> {
        assert!(
            !self.has_remaining(),
            "Only empty buflist can be used to encode frame"
        );
        let mut header_frame = Frame::new(Frame::HEADERS_FRAME_TYPE, BufList::new())
            .expect("empty buflist has zero size");

        let encode = async move {
            header_frame.encode_one(field_section_prefix).await?;
            for field_line_representation in field_line_representations {
                header_frame.encode_one(field_line_representation).await?;
            }
            Ok(header_frame)
        };
        encode
            .await
            .map_err(|error: EncodeStreamError| match error {
                EncodeStreamError::Stream { .. } => {
                    unreachable!("Stream error should not happen when encoding to BufList")
                }
                EncodeStreamError::Encode { source } => source,
            })
    }
}

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
    pub const METHOD: &str = ":method";
    pub const SCHEME: &str = ":scheme";
    pub const AUTHORITY: &str = ":authority";
    pub const PATH: &str = ":path";
    pub const STATUS: &str = ":status";
    pub const PROTOOCL: &str = ":protocol";

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

    pub const fn is_empty(&self) -> bool {
        match self {
            PseudoHeaders::Request {
                method,
                scheme,
                authority,
                path,
            } => method.is_none() && scheme.is_none() && authority.is_none() && path.is_none(),
            PseudoHeaders::Response { status } => status.is_none(),
        }
    }
}

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
            } => {
                // All HTTP/3 requests MUST include exactly one value for the :method,
                // :scheme, and :path pseudo-header fields, unless the request is a
                // CONNECT request; see Section 4.4.
                let Some(method) = method else {
                    return malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu.fail();
                };

                if method != Method::CONNECT {
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

impl From<request::Parts> for FieldSection {
    fn from(request: request::Parts) -> Self {
        Self {
            pseudo_headers: Some(PseudoHeaders::request(request.method, request.uri)),
            header_map: request.headers,
        }
    }
}

impl TryFrom<FieldSection> for request::Parts {
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Request {
            method,
            scheme,
            authority,
            path,
        } = value
            .pseudo_headers
            .context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?
        else {
            return Err(MalformedHeaderSection::ResponsePseudoHeaderInRequest);
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
        let method =
            method.context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?;

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
    type Error = MalformedHeaderSection;

    fn try_from(value: FieldSection) -> Result<Self, Self::Error> {
        let PseudoHeaders::Response { status } = value
            .pseudo_headers
            .context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?
        else {
            return Err(MalformedHeaderSection::RequestPseudoHeaderInResponse);
        };

        let status =
            status.context(malformed_header_section::AbsenceOfMandatoryPseudoHeadersSnafu)?;
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
