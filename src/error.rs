use std::{fmt, io, sync::Arc};

/// An HTTP/3 error with the transport action required by its context.
#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Stream(ErrorDetail),
    #[error(transparent)]
    Connection(ErrorDetail),
}

/// The protocol code and diagnostic text carried by [`Error`].
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct ErrorDetail {
    pub code: ErrorCode,
    pub reason: String,
}

impl Error {
    pub fn stream(self) -> Self {
        let detail = match self {
            Self::Stream(detail) | Self::Connection(detail) => detail,
        };
        Self::Stream(detail)
    }

    pub fn connection(self) -> Self {
        let detail = match self {
            Self::Stream(detail) | Self::Connection(detail) => detail,
        };
        Self::Connection(detail)
    }

    pub(crate) fn is_connection(&self) -> bool {
        matches!(self, Self::Connection(_))
    }
}

impl std::ops::Deref for Error {
    type Target = ErrorDetail;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Stream(detail) | Self::Connection(detail) => detail,
        }
    }
}

impl std::ops::DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Stream(detail) | Self::Connection(detail) => detail,
        }
    }
}

/// Recover an H3 error that crossed an `io::Error` boundary without losing
/// its stream/connection scope.
pub(crate) fn embedded_h3_error(error: &io::Error) -> Option<Error> {
    let error = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Arc<io::Error>>())
        .map_or(error, Arc::as_ref);
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Error>())
        .cloned()
}

impl Error {
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        Self::Connection(ErrorDetail {
            code,
            reason: reason.into(),
        })
    }

    /// Preserve embedded protocol errors, using `fallback` for plain I/O failures.
    pub(crate) fn from_io(error: io::Error, code: ErrorCode) -> Self {
        Self::from_io_with(error, |_| code)
    }

    /// Preserve an embedded HTTP/3 error, treating an unclassified I/O error
    /// as local to the stream.
    pub fn from_stream_io(error: io::Error) -> Self {
        embedded_h3_error(&error).unwrap_or_else(|| Self::from(error).stream())
    }

    fn from_io_with(error: io::Error, fallback: impl FnOnce(io::ErrorKind) -> ErrorCode) -> Self {
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Arc<io::Error>>())
            .map_or(&error, Arc::as_ref);
        embedded_h3_error(error).unwrap_or_else(|| fallback(error.kind()).reason(error.to_string()))
    }
}

impl From<Error> for ErrorCode {
    fn from(error: Error) -> Self {
        error.code
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::from_io(error, ErrorCode::InternalError)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ErrorCode {
    NoError = 0x0100,
    GeneralProtocolError = 0x0101,
    InternalError = 0x0102,
    StreamCreationError = 0x0103,
    ClosedCriticalStream = 0x0104,
    FrameUnexpected = 0x0105,
    FrameError = 0x0106,
    ExcessiveLoad = 0x0107,
    IdError = 0x0108,
    SettingsError = 0x0109,
    MissingSettings = 0x010a,
    RequestRejected = 0x010b,
    RequestCancelled = 0x010c,
    RequestIncomplete = 0x010d,
    MessageError = 0x010e,
    ConnectError = 0x010f,
    VersionFallback = 0x0110,
    QpackDecompressionFailed = 0x0200,
    QpackEncoderStreamError = 0x0201,
    QpackDecoderStreamError = 0x0202,
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
        write!(f, "{self:?} (0x{:x})", self.as_u64())
    }
}

impl From<io::Error> for ErrorCode {
    fn from(error: io::Error) -> Self {
        Error::from(error).code
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl TryFrom<u64> for ErrorCode {
    /// The unrecognized application error code.
    type Error = u64;

    fn try_from(code: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match code {
            0x0100 => Self::NoError,
            0x0101 => Self::GeneralProtocolError,
            0x0102 => Self::InternalError,
            0x0103 => Self::StreamCreationError,
            0x0104 => Self::ClosedCriticalStream,
            0x0105 => Self::FrameUnexpected,
            0x0106 => Self::FrameError,
            0x0107 => Self::ExcessiveLoad,
            0x0108 => Self::IdError,
            0x0109 => Self::SettingsError,
            0x010a => Self::MissingSettings,
            0x010b => Self::RequestRejected,
            0x010c => Self::RequestCancelled,
            0x010d => Self::RequestIncomplete,
            0x010e => Self::MessageError,
            0x010f => Self::ConnectError,
            0x0110 => Self::VersionFallback,
            0x0200 => Self::QpackDecompressionFailed,
            0x0201 => Self::QpackEncoderStreamError,
            0x0202 => Self::QpackDecoderStreamError,
            code => return Err(code),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_preserve_protocol_errors_and_cover_every_registered_code() {
        let protocol = ErrorCode::IdError.reason("id");
        assert_eq!(ErrorCode::from(protocol.clone()), ErrorCode::IdError);
        assert_eq!(
            ErrorCode::from(io::Error::other(protocol)),
            ErrorCode::IdError
        );
        for code in 0x100..=0x110 {
            assert_eq!(ErrorCode::try_from(code).unwrap().as_u64(), code);
        }
        for code in 0x200..=0x202 {
            assert_eq!(ErrorCode::try_from(code).unwrap().as_u64(), code);
        }
        assert_eq!(ErrorCode::try_from(42), Err(42));
        assert_eq!(ErrorCode::NoError.to_string(), "NoError (0x100)");
    }
}
