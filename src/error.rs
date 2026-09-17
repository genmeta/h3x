use std::{fmt, io, sync::Arc};

/// A protocol error and the reason for this particular failure.
#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct Error {
    pub code: ErrorCode,
    pub reason: String,
}

impl Error {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// Preserve embedded protocol errors, using `fallback` for plain I/O failures.
    pub(crate) fn from_io(error: io::Error, code: ErrorCode) -> Self {
        Self::from_io_with(error, |_| code)
    }

    /// Frame truncation is a framing error; other plain I/O failures are internal.
    pub(crate) fn from_frame_io(error: io::Error) -> Self {
        Self::from_io_with(error, |kind| match kind {
            io::ErrorKind::UnexpectedEof => ErrorCode::H3_FRAME_ERROR,
            _ => ErrorCode::H3_INTERNAL_ERROR,
        })
    }

    fn from_io_with(error: io::Error, fallback: impl FnOnce(io::ErrorKind) -> ErrorCode) -> Self {
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Arc<io::Error>>())
            .map_or(&error, Arc::as_ref);
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Self>())
            .cloned()
            .unwrap_or_else(|| fallback(error.kind()).reason(error.to_string()))
    }
}

impl From<Error> for ErrorCode {
    fn from(error: Error) -> Self {
        error.code
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::from_io(error, ErrorCode::H3_INTERNAL_ERROR)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ErrorCode {
    H3_NO_ERROR = 0x0100,
    H3_GENERAL_PROTOCOL_ERROR = 0x0101,
    H3_INTERNAL_ERROR = 0x0102,
    H3_STREAM_CREATION_ERROR = 0x0103,
    H3_CLOSED_CRITICAL_STREAM = 0x0104,
    H3_FRAME_UNEXPECTED = 0x0105,
    H3_FRAME_ERROR = 0x0106,
    H3_EXCESSIVE_LOAD = 0x0107,
    H3_ID_ERROR = 0x0108,
    H3_SETTINGS_ERROR = 0x0109,
    H3_MISSING_SETTINGS = 0x010a,
    H3_REQUEST_REJECTED = 0x010b,
    H3_REQUEST_CANCELLED = 0x010c,
    H3_REQUEST_INCOMPLETE = 0x010d,
    H3_MESSAGE_ERROR = 0x010e,
    H3_CONNECT_ERROR = 0x010f,
    H3_VERSION_FALLBACK = 0x0110,
    QPACK_DECOMPRESSION_FAILED = 0x0200,
    QPACK_ENCODER_STREAM_ERROR = 0x0201,
    QPACK_DECODER_STREAM_ERROR = 0x0202,
}

impl ErrorCode {
    /// Attach context explaining why this protocol error occurred.
    pub fn reason(self, reason: impl Into<String>) -> Error {
        Error::new(self, reason)
    }

    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} (0x{:x})", *self as u64)
    }
}

impl From<io::Error> for ErrorCode {
    fn from(error: io::Error) -> Self {
        Error::from(error).code
    }
}

pub type Result<T> = std::result::Result<T, Error>;
