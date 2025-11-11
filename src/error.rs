use std::{borrow::Cow, error::Error, io};

use snafu::Snafu;

use crate::varint::VarInt;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum StreamError {
    #[snafu(transparent)]
    Connection {
        source: ConnectionError,
    },
    Reset {
        code: u64,
    },
    #[snafu(transparent)]
    Unknown {
        source: Box<dyn Error + Send + Sync>,
    },
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            e @ (StreamError::Connection { .. } | StreamError::Reset { .. }) => {
                io::Error::new(io::ErrorKind::BrokenPipe, e)
            }
            StreamError::Unknown { source } => io::Error::other(source),
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(value: io::Error) -> Self {
        match value.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => StreamError::Unknown {
                source: Box::new(error),
            },
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ConnectionError {
    Transport {
        code: Code,
        reason: Cow<'static, str>,
    },
    Application {
        code: Code,
        reason: Cow<'static, str>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(VarInt);

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Code {}

impl From<Code> for io::Error {
    fn from(value: Code) -> Self {
        io::Error::other(value)
    }
}

impl Code {
    // https://datatracker.ietf.org/doc/html/rfc9114#name-http-3-error-codes
    /// No error. This is used when the connection or stream needs to be closed, but there is no error to signal.
    pub const H3_NO_ERROR: Self = Self(VarInt::from_u32(0x0100));
    /// Peer violated protocol requirements in a way that does not match a more specific error code or endpoint declines to use the more specific error code.
    pub const H3_GENERAL_PROTOCOL_ERROR: Self = Self(VarInt::from_u32(0x0101));
    /// An internal error has occurred in the HTTP stack.
    pub const H3_INTERNAL_ERROR: Self = Self(VarInt::from_u32(0x0102));
    /// The endpoint detected that its peer created a stream that it will not accept.
    pub const H3_STREAM_CREATION_ERROR: Self = Self(VarInt::from_u32(0x0103));
    /// A stream required by the HTTP/3 connection was closed or reset.
    pub const H3_CLOSED_CRITICAL_STREAM: Self = Self(VarInt::from_u32(0x0104));
    /// A frame was received that was not permitted in the current state or on the current stream.
    pub const H3_FRAME_UNEXPECTED: Self = Self(VarInt::from_u32(0x0105));
    /// A frame that fails to satisfy layout requirements or with an invalid size was received.
    pub const H3_FRAME_ERROR: Self = Self(VarInt::from_u32(0x0106));
    /// The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load.
    pub const H3_EXCESSIVE_LOAD: Self = Self(VarInt::from_u32(0x0107));
    /// A stream ID or push ID was used incorrectly, such as exceeding a limit, reducing a limit, or being reused.
    pub const H3_ID_ERROR: Self = Self(VarInt::from_u32(0x0108));
    /// An endpoint detected an error in the payload of a SETTINGS frame.
    pub const H3_SETTINGS_ERROR: Self = Self(VarInt::from_u32(0x0109));
    /// No SETTINGS frame was received at the beginning of the control stream.
    pub const H3_MISSING_SETTINGS: Self = Self(VarInt::from_u32(0x010a));
    /// A server rejected a request without performing any application processing.
    pub const H3_REQUEST_REJECTED: Self = Self(VarInt::from_u32(0x010b));
    /// The request or its response (including pushed response) is cancelled.
    pub const H3_REQUEST_CANCELLED: Self = Self(VarInt::from_u32(0x010c));
    /// The client's stream terminated without containing a fully formed request.
    pub const H3_REQUEST_INCOMPLETE: Self = Self(VarInt::from_u32(0x010d));
    /// An HTTP message was malformed and cannot be processed.
    pub const H3_MESSAGE_ERROR: Self = Self(VarInt::from_u32(0x010e));
    /// The TCP connection established in response to a CONNECT request was reset or abnormally closed.
    pub const H3_CONNECT_ERROR: Self = Self(VarInt::from_u32(0x010f));
    /// The requested operation cannot be served over HTTP/3. The peer should retry over HTTP/1.1.
    pub const H3_VERSION_FALLBACK: Self = Self(VarInt::from_u32(0x0110));

    // https://datatracker.ietf.org/doc/html/rfc9204#name-error-handling
    /// The decoder failed to interpret an encoded field section and is not able to continue decoding that field section.
    pub const QPACK_DECOMPRESSION_FAILED: Self = Self(VarInt::from_u32(0x200));
    /// The decoder failed to interpret an encoder instruction received on the encoder stream.
    pub const QPACK_ENCODER_STREAM_ERROR: Self = Self(VarInt::from_u32(0x201));
    /// The encoder failed to interpret a decoder instruction received on the decoder stream.
    pub const QPACK_DECODER_STREAM_ERROR: Self = Self(VarInt::from_u32(0x202));

    pub const fn new(code: VarInt) -> Self {
        Self(code)
    }

    pub const fn value(&self) -> VarInt {
        self.0
    }
}

#[derive(Debug, Snafu)]
pub enum H3CriticalStreamClosed {
    #[snafu(display("QPack encoder stream closed unexpectedly"))]
    QPackEncoderStream,
    #[snafu(display("QPack decoder stream closed unexpectedly"))]
    QPackDecoderStream,
}

impl HasErrorCode for H3CriticalStreamClosed {
    const CODE: Code = Code::H3_CLOSED_CRITICAL_STREAM;
}

pub(crate) trait HasErrorCode {
    const CODE: Code;
}

#[derive(Debug)]
pub struct ErrorWithCode {
    pub code: Code,
    pub source: Option<Box<dyn Error + Send + Sync>>,
}

impl ErrorWithCode {
    pub fn new(code: Code, source: Option<impl Error + Send + Sync + 'static>) -> Self {
        Self {
            code,
            source: source.map(|s| Box::new(s) as Box<dyn Error + Send + Sync>),
        }
    }
}

impl From<Code> for ErrorWithCode {
    fn from(value: Code) -> Self {
        Self {
            code: value,
            source: None,
        }
    }
}

impl<E: HasErrorCode + Error + Send + Sync + 'static> From<E> for ErrorWithCode {
    fn from(value: E) -> Self {
        Self::new(E::CODE, Some(value))
    }
}

impl From<ErrorWithCode> for io::Error {
    fn from(value: ErrorWithCode) -> Self {
        io::Error::other(value)
    }
}

impl std::fmt::Display for ErrorWithCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)?;
        Ok(())
    }
}

impl std::error::Error for ErrorWithCode {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}
