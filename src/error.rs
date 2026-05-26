use std::{error::Error as StdError, fmt::Display};

use snafu::Snafu;

use crate::varint::VarInt;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(VarInt);

impl From<VarInt> for Code {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<Code> for VarInt {
    fn from(value: Code) -> Self {
        value.0
    }
}

impl Code {
    pub const fn into_inner(self) -> VarInt {
        self.0
    }
}

macro_rules! codes {
    (
        $(
            $(#[$meta:meta])*
            pub const $name:ident = $value:expr;
        )*
    ) => {
        impl Code {
            $(
                $(#[$meta])*
                pub const $name: Self = Self(VarInt::from_u32($value));
            )*
        }

        impl Display for Code {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match *self {
                    $(
                        Self::$name => write!(f, "{} (0x{:x})", stringify!($name), $value),
                    )*
                    _ => write!(f, "Code 0x{:x}", self.0),
                }
            }
        }
    };
}

codes! {
    // https://datatracker.ietf.org/doc/html/rfc9114#name-http-3-error-codes
    /// No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
    pub const H3_NO_ERROR = 0x0100;
    /// Peer violated protocol requirements in a way that does not match a more specific error code or endpoint declines to use the more specific error code.
    pub const H3_GENERAL_PROTOCOL_ERROR = 0x0101;
    /// An internal error has occurred in the HTTP stack.
    pub const H3_INTERNAL_ERROR = 0x0102;
    /// The endpoint detected that its peer created a stream that it will not accept.
    pub const H3_STREAM_CREATION_ERROR = 0x0103;
    /// A stream required by the HTTP/3 connection was closed or reset.
    pub const H3_CLOSED_CRITICAL_STREAM = 0x0104;
    /// A frame was received that was not permitted in the current state or on the current stream.
    pub const H3_FRAME_UNEXPECTED = 0x0105;
    /// A frame that fails to satisfy layout requirements or with an invalid size was received.
    pub const H3_FRAME_ERROR = 0x0106;
    /// The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load.
    pub const H3_EXCESSIVE_LOAD = 0x0107;
    /// A stream ID or push ID was used incorrectly, such as exceeding a limit, reducing a limit, or being reused.
    pub const H3_ID_ERROR = 0x0108;
    /// An endpoint detected an error in the payload of a SETTINGS frame.
    pub const H3_SETTINGS_ERROR = 0x0109;
    /// No SETTINGS frame was received at the beginning of the control stream.
    pub const H3_MISSING_SETTINGS = 0x010a;
    /// A server rejected a request without performing any application processing.
    pub const H3_REQUEST_REJECTED = 0x010b;
    /// The request or its response (including pushed response) is cancelled.
    pub const H3_REQUEST_CANCELLED = 0x010c;
    /// The client's stream terminated without containing a fully formed request.
    pub const H3_REQUEST_INCOMPLETE = 0x010d;
    /// An HTTP message was malformed and cannot be processed.
    ///
    /// A malformed request or response is one that is an otherwise valid sequence of frames but is invalid due to:
    ///
    /// - the presence of prohibited fields or pseudo-header fields,
    /// - the absence of mandatory pseudo-header fields,
    /// - invalid values for pseudo-header fields,
    /// - pseudo-header fields after fields,
    /// - an invalid sequence of HTTP messages,
    /// - the inclusion of uppercase field names, or
    /// - the inclusion of invalid characters in field names or values.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc9114#name-malformed-requests-and-resp>
    pub const H3_MESSAGE_ERROR = 0x010e;
    /// The TCP connection established in response to a CONNECT request was reset or abnormally closed.
    pub const H3_CONNECT_ERROR = 0x010f;
    /// The requested operation cannot be served over HTTP/3. The peer should retry over HTTP/1.1.
    pub const H3_VERSION_FALLBACK = 0x0110;

    // https://datatracker.ietf.org/doc/html/rfc9204#name-error-handling
    /// The decoder failed to interpret an encoded field section and is not able to continue decoding that field section.
    pub const QPACK_DECOMPRESSION_FAILED = 0x200;
    /// The decoder failed to interpret an encoder instruction received on the encoder stream.
    pub const QPACK_ENCODER_STREAM_ERROR = 0x201;
    /// The encoder failed to interpret a decoder instruction received on the decoder stream.
    pub const QPACK_DECODER_STREAM_ERROR = 0x202;
}

impl Code {
    pub const fn new(code: VarInt) -> Self {
        Self(code)
    }

    pub const fn value(&self) -> VarInt {
        self.0
    }
}

#[non_exhaustive]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3StreamCreationError {
    #[snafu(display("control stream already exists"))]
    DuplicateControlStream,
    #[snafu(display("qpack encoder stream already exists"))]
    DuplicateQpackEncoderStream,
    #[snafu(display("qpack decoder stream already exists"))]
    DuplicateQpackDecoderStream,
}

impl H3ConnectionError for H3StreamCreationError {
    fn code(&self) -> Code {
        Code::H3_STREAM_CREATION_ERROR
    }
}

// TODO: add reset code info(if any)
#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum H3CriticalStreamClosed {
    #[snafu(display("qpack encoder stream closed unexpectedly"))]
    QPackEncoder,
    #[snafu(display("qpack decoder stream closed unexpectedly"))]
    QPackDecoder,
    #[snafu(display("control stream closed unexpectedly"))]
    Control,
}

impl H3ConnectionError for H3CriticalStreamClosed {
    fn code(&self) -> Code {
        Code::H3_CLOSED_CRITICAL_STREAM
    }
}

// todo: more error variants instead of direct Code::H3_FRAME_UNEXPECTED usage
#[non_exhaustive]
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3FrameUnexpected {
    #[snafu(display("received subsequent SETTINGS frame"))]
    DuplicateSettings,
    #[snafu(display("unexpected frame type on request stream"))]
    UnexpectedFrameType,
    #[snafu(display("unexpected frame during trailer reading"))]
    UnexpectedFrameDuringTrailer,
}
impl H3ConnectionError for H3FrameUnexpected {
    fn code(&self) -> Code {
        Code::H3_FRAME_UNEXPECTED
    }
}

// TODO: use Error::provide api in the future
/// H3 error whose scope is a single stream (will cause `RESET_STREAM`).
///
/// Static scope dispatch: types that are always stream-scoped implement this
/// trait and convert to [`crate::connection::StreamError`] via a blanket
/// `From` impl.
pub trait H3StreamError: StdError + Send + Sync {
    fn code(&self) -> Code;
}

/// H3 error whose scope is the whole connection (will cause `CONNECTION_CLOSE`).
///
/// Static scope dispatch: types that are always connection-scoped implement
/// this trait and convert to [`crate::connection::ConnectionError`] via a
/// blanket `From` impl.
pub trait H3ConnectionError: StdError + Send + Sync {
    fn code(&self) -> Code;
}

#[derive(Debug, Snafu, Clone, Copy)]
#[snafu(display("no error"))]
pub struct H3NoError;

impl H3ConnectionError for H3NoError {
    fn code(&self) -> Code {
        Code::H3_NO_ERROR
    }
}

#[non_exhaustive]
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3MessageError {
    #[snafu(display("missing header section in HTTP message"))]
    MissingHeaderSection,
    #[snafu(display("unexpected headers frame in message body"))]
    UnexpectedHeadersInBody,
}

impl H3StreamError for H3MessageError {
    fn code(&self) -> Code {
        Code::H3_MESSAGE_ERROR
    }
}

#[derive(Debug, Snafu, Clone, Copy)]
#[snafu(display("no SETTINGS frame at beginning of control stream"))]
pub struct H3MissingSettings;

impl H3ConnectionError for H3MissingSettings {
    fn code(&self) -> Code {
        Code::H3_MISSING_SETTINGS
    }
}

#[non_exhaustive]
#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum H3GeneralProtocolError {
    #[snafu(display("trailing payload in GOAWAY frame"))]
    TrailingPayload,
    #[snafu(display("protocol decode error"))]
    Decode { source: crate::codec::DecodeError },
}

impl H3ConnectionError for H3GeneralProtocolError {
    fn code(&self) -> Code {
        Code::H3_GENERAL_PROTOCOL_ERROR
    }
}

#[non_exhaustive]
#[derive(Debug, Snafu)]
pub enum H3InternalError {
    #[snafu(display("QPACK encoder encode failure"))]
    QPackEncoderEncode { source: crate::codec::EncodeError },
    #[snafu(display("missing server name (SNI) on incoming connection"))]
    MissingServerName,
}

impl H3ConnectionError for H3InternalError {
    fn code(&self) -> Code {
        Code::H3_INTERNAL_ERROR
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(display("frame decode error"))]
pub struct H3FrameDecodeError {
    pub source: crate::codec::DecodeError,
}

impl H3ConnectionError for H3FrameDecodeError {
    fn code(&self) -> Code {
        Code::H3_FRAME_ERROR
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum QpackDecompressionFailed {
    #[snafu(display("QPACK decompression decode error"))]
    Decode { source: crate::codec::DecodeError },
}

impl H3ConnectionError for QpackDecompressionFailed {
    fn code(&self) -> Code {
        Code::QPACK_DECOMPRESSION_FAILED
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(display("field section size {actual} exceeds limit {limit}"))]
pub struct H3ExcessiveFieldSectionSize {
    pub actual: u64,
    pub limit: u64,
}

impl H3StreamError for H3ExcessiveFieldSectionSize {
    fn code(&self) -> Code {
        Code::H3_EXCESSIVE_LOAD
    }
}

#[non_exhaustive]
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3IdError {
    #[snafu(display("push ID exceeds limit"))]
    PushIdExceedsLimit,
    #[snafu(display("GOAWAY stream ID ordering violation"))]
    GoawayStreamIdOrdering,
}
impl H3ConnectionError for H3IdError {
    fn code(&self) -> Code {
        Code::H3_ID_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec::{DecodeError, EncodeError},
        connection::{ConnectionError, StreamError},
    };

    fn varint(value: u32) -> VarInt {
        VarInt::from_u32(value)
    }

    fn assert_connection_error<E>(error: E, expected_code: Code, expected_display: &str)
    where
        E: H3ConnectionError + 'static,
    {
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.to_string(), expected_display);

        let ConnectionError::H3 { source } = ConnectionError::from(error) else {
            panic!("expected h3 connection error");
        };
        assert_eq!(source.code(), expected_code);
        assert_eq!(source.to_string(), expected_display);
    }

    fn assert_stream_error<E>(error: E, expected_code: Code, expected_display: &str)
    where
        E: H3StreamError + 'static,
    {
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.to_string(), expected_display);

        let StreamError::H3 { source } = StreamError::from(error) else {
            panic!("expected h3 stream error");
        };
        assert_eq!(source.code(), expected_code);
        assert_eq!(source.to_string(), expected_display);
    }

    #[test]
    fn code_conversions_and_display_cover_known_and_unknown_codes() {
        let known = Code::H3_NO_ERROR;
        assert_eq!(known.into_inner(), varint(0x100));
        assert_eq!(known.value(), varint(0x100));
        assert_eq!(VarInt::from(known), varint(0x100));
        assert_eq!(known.to_string(), "H3_NO_ERROR (0x100)");

        let custom = Code::from(varint(0x12345));
        assert_eq!(custom.into_inner(), varint(0x12345));
        assert_eq!(custom.value(), varint(0x12345));
        assert_eq!(custom.to_string(), "Code 0x12345");

        let constructed = Code::new(varint(0x201));
        assert_eq!(constructed, Code::QPACK_ENCODER_STREAM_ERROR);
        assert_eq!(
            constructed.to_string(),
            "QPACK_ENCODER_STREAM_ERROR (0x201)"
        );
    }

    #[test]
    fn connection_error_types_report_their_codes_and_messages() {
        for error in [
            H3StreamCreationError::DuplicateControlStream,
            H3StreamCreationError::DuplicateQpackEncoderStream,
            H3StreamCreationError::DuplicateQpackDecoderStream,
        ] {
            assert_connection_error(
                error,
                Code::H3_STREAM_CREATION_ERROR,
                match error {
                    H3StreamCreationError::DuplicateControlStream => {
                        "control stream already exists"
                    }
                    H3StreamCreationError::DuplicateQpackEncoderStream => {
                        "qpack encoder stream already exists"
                    }
                    H3StreamCreationError::DuplicateQpackDecoderStream => {
                        "qpack decoder stream already exists"
                    }
                },
            );
        }

        assert_connection_error(
            H3CriticalStreamClosed::QPackEncoder,
            Code::H3_CLOSED_CRITICAL_STREAM,
            "qpack encoder stream closed unexpectedly",
        );
        assert_connection_error(
            H3CriticalStreamClosed::QPackDecoder,
            Code::H3_CLOSED_CRITICAL_STREAM,
            "qpack decoder stream closed unexpectedly",
        );
        assert_connection_error(
            H3CriticalStreamClosed::Control,
            Code::H3_CLOSED_CRITICAL_STREAM,
            "control stream closed unexpectedly",
        );

        for error in [
            H3FrameUnexpected::DuplicateSettings,
            H3FrameUnexpected::UnexpectedFrameType,
            H3FrameUnexpected::UnexpectedFrameDuringTrailer,
        ] {
            assert_connection_error(
                error,
                Code::H3_FRAME_UNEXPECTED,
                match error {
                    H3FrameUnexpected::DuplicateSettings => "received subsequent SETTINGS frame",
                    H3FrameUnexpected::UnexpectedFrameType => {
                        "unexpected frame type on request stream"
                    }
                    H3FrameUnexpected::UnexpectedFrameDuringTrailer => {
                        "unexpected frame during trailer reading"
                    }
                },
            );
        }

        assert_connection_error(H3NoError, Code::H3_NO_ERROR, "no error");
        assert_connection_error(
            H3MissingSettings,
            Code::H3_MISSING_SETTINGS,
            "no SETTINGS frame at beginning of control stream",
        );
        assert_connection_error(
            H3GeneralProtocolError::TrailingPayload,
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "trailing payload in GOAWAY frame",
        );
        assert_connection_error(
            H3GeneralProtocolError::Decode {
                source: DecodeError::ArithmeticOverflow,
            },
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "protocol decode error",
        );
        assert_connection_error(
            H3InternalError::QPackEncoderEncode {
                source: EncodeError::HuffmanEncoding,
            },
            Code::H3_INTERNAL_ERROR,
            "QPACK encoder encode failure",
        );
        assert_connection_error(
            H3InternalError::MissingServerName,
            Code::H3_INTERNAL_ERROR,
            "missing server name (SNI) on incoming connection",
        );
        assert_connection_error(
            H3FrameDecodeError {
                source: DecodeError::IntegerOverflow,
            },
            Code::H3_FRAME_ERROR,
            "frame decode error",
        );
        assert_connection_error(
            QpackDecompressionFailed::Decode {
                source: DecodeError::DecompressionFailed,
            },
            Code::QPACK_DECOMPRESSION_FAILED,
            "QPACK decompression decode error",
        );

        for error in [
            H3IdError::PushIdExceedsLimit,
            H3IdError::GoawayStreamIdOrdering,
        ] {
            assert_connection_error(
                error,
                Code::H3_ID_ERROR,
                match error {
                    H3IdError::PushIdExceedsLimit => "push ID exceeds limit",
                    H3IdError::GoawayStreamIdOrdering => "GOAWAY stream ID ordering violation",
                },
            );
        }
    }

    #[test]
    fn stream_error_types_report_their_codes_and_messages() {
        assert_stream_error(
            H3MessageError::MissingHeaderSection,
            Code::H3_MESSAGE_ERROR,
            "missing header section in HTTP message",
        );
        assert_stream_error(
            H3MessageError::UnexpectedHeadersInBody,
            Code::H3_MESSAGE_ERROR,
            "unexpected headers frame in message body",
        );
        assert_stream_error(
            H3ExcessiveFieldSectionSize {
                actual: 8192,
                limit: 4096,
            },
            Code::H3_EXCESSIVE_LOAD,
            "field section size 8192 exceeds limit 4096",
        );
    }
}
