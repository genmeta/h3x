use std::{borrow::Cow, error::Error, io, sync::Arc};

use snafu::Snafu;

use crate::{stream::UnidirectionalStream, varint::VarInt};

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum StreamError {
    #[snafu(transparent)]
    Connection {
        source: ConnectionError,
    },
    Reset {
        code: VarInt,
    },
}

impl StreamError {
    /// Returns `true` if the stream error is [`Reset`].
    ///
    /// [`Reset`]: StreamError::Reset
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset { .. })
    }
}

impl From<StreamError> for io::Error {
    fn from(value: StreamError) -> Self {
        match value {
            error @ StreamError::Reset { .. } => io::Error::new(io::ErrorKind::BrokenPipe, error),
            StreamError::Connection { source } => io::Error::from(source),
        }
    }
}

impl From<io::Error> for StreamError {
    fn from(value: io::Error) -> Self {
        value
            .downcast::<Self>()
            .expect("io::Error is not StreamError")
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub struct TransportError {
    pub kind: VarInt,
    pub frame_type: VarInt,
    pub reason: Cow<'static, str>,
}

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub struct ApplicationError {
    pub code: Code,
    pub reason: Cow<'static, str>,
}

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum ConnectionError {
    #[snafu(transparent)]
    Transport { source: TransportError },
    #[snafu(transparent)]
    Application { source: ApplicationError },
}

impl From<ConnectionError> for io::Error {
    fn from(value: ConnectionError) -> Self {
        io::Error::new(io::ErrorKind::BrokenPipe, value)
    }
}

impl ConnectionError {
    pub const fn is_transport(&self) -> bool {
        matches!(self, ConnectionError::Transport { .. })
    }

    pub const fn is_application(&self) -> bool {
        matches!(self, ConnectionError::Application { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code(VarInt);

impl Code {
    pub const fn into_inner(self) -> VarInt {
        self.0
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Code {}", self.0)
    }
}

impl std::error::Error for Code {}

impl From<Code> for io::Error {
    fn from(value: Code) -> Self {
        io::Error::other(value)
    }
}

impl From<Code> for ApplicationError {
    fn from(value: Code) -> Self {
        ApplicationError {
            code: value,
            reason: Cow::Borrowed(""),
        }
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
    QPackEncoder,
    #[snafu(display("QPack decoder stream closed unexpectedly"))]
    QPackDecoder,
    #[snafu(display("Control stream closed unexpectedly"))]
    Control,
}

impl HasErrorCode for H3CriticalStreamClosed {
    fn code(&self) -> Code {
        Code::H3_CLOSED_CRITICAL_STREAM
    }
}

#[derive(Debug, Snafu, Clone, Copy)]
pub enum H3FrameUnexpected {
    #[snafu(display("Received subsequent SETTINGS frame"))]
    DuplicateSettings,
}

impl HasErrorCode for H3FrameUnexpected {
    fn code(&self) -> Code {
        Code::H3_FRAME_UNEXPECTED
    }
}

pub trait HasErrorCode {
    fn code(&self) -> Code {
        Code::H3_CLOSED_CRITICAL_STREAM
    }
}

#[derive(Debug, Clone)]
pub struct ErrorWithCode {
    pub code: Code,
    pub source: Option<Arc<dyn Error + Send + Sync>>,
}

impl ErrorWithCode {
    pub fn new(code: Code, source: Option<impl Error + Send + Sync + 'static>) -> Self {
        Self {
            code,
            source: source.map(|s| Arc::new(s) as Arc<dyn Error + Send + Sync>),
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
    fn from(error: E) -> Self {
        Self::new(error.code(), Some(error))
    }
}

impl From<ErrorWithCode> for io::Error {
    fn from(value: ErrorWithCode) -> Self {
        io::Error::other(value)
    }
}

impl From<&ErrorWithCode> for ApplicationError {
    fn from(value: &ErrorWithCode) -> Self {
        ApplicationError {
            code: value.code,
            reason: match &value.source {
                Some(source) => Cow::Owned(source.to_string()),
                None => Cow::Borrowed(""),
            },
        }
    }
}

impl From<ErrorWithCode> for ApplicationError {
    fn from(value: ErrorWithCode) -> Self {
        ApplicationError::from(&value)
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

pub trait ResultExt<Ok, Err> {
    fn with_code<C>(self, code: C) -> Result<Ok, ErrorWithCode>
    where
        C: Into<Code>;
}

pub trait OptionExt<T> {
    fn ok_or_code<C>(self, code: C) -> Result<T, ErrorWithCode>
    where
        C: Into<Code>;
}

impl<Ok, Err> ResultExt<Ok, Err> for Result<Ok, Err>
where
    Err: Error + Send + Sync + 'static,
{
    fn with_code<C>(self, code: C) -> Result<Ok, ErrorWithCode>
    where
        C: Into<Code>,
    {
        self.map_err(|e| ErrorWithCode::new(code.into(), Some(e)))
    }
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_code<C>(self, code: C) -> Result<T, ErrorWithCode>
    where
        C: Into<Code>,
    {
        self.ok_or_else(|| ErrorWithCode::from(code.into()))
    }
}
