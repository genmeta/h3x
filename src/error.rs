use std::{error::Error as StdError, fmt::Display};

use snafu::Snafu;

use crate::varint::VarInt;

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

    pub const fn with<E: StdError>(self, source: E) -> CodeWith<E> {
        CodeWith { code: self, source }
    }
}

impl StdError for Code {}

impl HasErrorCode for Code {
    fn code(&self) -> Code {
        *self
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
    /// https://datatracker.ietf.org/doc/html/rfc9114#name-malformed-requests-and-resp
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

    pub const fn is_known_stream_error(&self) -> bool {
        matches!(
            *self,
            Code::H3_FRAME_UNEXPECTED
                | Code::H3_MESSAGE_ERROR
                | Code::H3_CONNECT_ERROR
                | Code::H3_REQUEST_CANCELLED
                | Code::H3_REQUEST_INCOMPLETE
                | Code::H3_REQUEST_REJECTED
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeWith<E: StdError> {
    code: Code,
    source: E,
}

impl<E: StdError> Display for CodeWith<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.source, f)
    }
}

impl<E: StdError + 'static> StdError for CodeWith<E> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}

impl<E: StdError + 'static> HasErrorCode for CodeWith<E> {
    fn code(&self) -> Code {
        self.code
    }
}

// TODO: add reset code info(if any)
#[derive(Debug, Snafu)]
pub enum H3CriticalStreamClosed {
    #[snafu(display("qpack encoder stream closed unexpectedly"))]
    QPackEncoder,
    #[snafu(display("qpack decoder stream closed unexpectedly"))]
    QPackDecoder,
    #[snafu(display("control stream closed unexpectedly"))]
    Control,
}

impl HasErrorCode for H3CriticalStreamClosed {
    fn code(&self) -> Code {
        Code::H3_CLOSED_CRITICAL_STREAM
    }
}

// todo: more error variants instead of direct Code::H3_FRAME_UNEXPECTED usage
#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3FrameUnexpected {
    #[snafu(display("received subsequent SETTINGS frame"))]
    DuplicateSettings,
}

impl HasErrorCode for H3FrameUnexpected {
    fn code(&self) -> Code {
        Code::H3_FRAME_UNEXPECTED
    }
}

// TODO: use Error::provide api in the future
pub trait HasErrorCode: StdError {
    fn code(&self) -> Code;
}
