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
    /// An application error code not named by HTTP/3.
    Other(u64),
}

impl ErrorCode {
    /// Attach context explaining why this protocol error occurred.
    pub fn reason(self, reason: impl Into<String>) -> Error {
        Error::new(self, reason)
    }

    pub const fn as_u64(self) -> u64 {
        match self {
            Self::H3_NO_ERROR => 0x0100,
            Self::H3_GENERAL_PROTOCOL_ERROR => 0x0101,
            Self::H3_INTERNAL_ERROR => 0x0102,
            Self::H3_STREAM_CREATION_ERROR => 0x0103,
            Self::H3_CLOSED_CRITICAL_STREAM => 0x0104,
            Self::H3_FRAME_UNEXPECTED => 0x0105,
            Self::H3_FRAME_ERROR => 0x0106,
            Self::H3_EXCESSIVE_LOAD => 0x0107,
            Self::H3_ID_ERROR => 0x0108,
            Self::H3_SETTINGS_ERROR => 0x0109,
            Self::H3_MISSING_SETTINGS => 0x010a,
            Self::H3_REQUEST_REJECTED => 0x010b,
            Self::H3_REQUEST_CANCELLED => 0x010c,
            Self::H3_REQUEST_INCOMPLETE => 0x010d,
            Self::H3_MESSAGE_ERROR => 0x010e,
            Self::H3_CONNECT_ERROR => 0x010f,
            Self::H3_VERSION_FALLBACK => 0x0110,
            Self::QPACK_DECOMPRESSION_FAILED => 0x0200,
            Self::QPACK_ENCODER_STREAM_ERROR => 0x0201,
            Self::QPACK_DECODER_STREAM_ERROR => 0x0202,
            Self::Other(code) => code,
        }
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

/// Apply the message receive error boundary in a consistent order.
/// QPACK temporarily carries connection failures to the connection task.
pub(crate) fn receive_error<R: tokio::io::AsyncRead + qrecovery::recv::StopSending + Unpin>(
    stream: &crate::protocol::stream::H3ReadStream<R>,
    qpack: &crate::ArcQpack,
    error: &Error,
) {
    use ErrorCode::*;
    stream.close(error.clone());
    let connection_error = match error.code {
        Other(_)
        | H3_NO_ERROR
        | H3_REQUEST_REJECTED
        | H3_REQUEST_CANCELLED
        | H3_REQUEST_INCOMPLETE
        | H3_MESSAGE_ERROR
        | H3_CONNECT_ERROR
        | H3_VERSION_FALLBACK => false,
        H3_GENERAL_PROTOCOL_ERROR
        | H3_INTERNAL_ERROR
        | H3_STREAM_CREATION_ERROR
        | H3_CLOSED_CRITICAL_STREAM
        | H3_FRAME_UNEXPECTED
        | H3_FRAME_ERROR
        | H3_EXCESSIVE_LOAD
        | H3_ID_ERROR
        | H3_SETTINGS_ERROR
        | H3_MISSING_SETTINGS
        | QPACK_DECOMPRESSION_FAILED
        | QPACK_ENCODER_STREAM_ERROR
        | QPACK_DECODER_STREAM_ERROR => true,
    };
    if connection_error {
        qpack.on_error(error.clone());
    }
    let _ = qpack.cancel(stream.stream_id());
}

impl From<u64> for ErrorCode {
    fn from(code: u64) -> Self {
        match code {
            0x0100 => Self::H3_NO_ERROR,
            0x0101 => Self::H3_GENERAL_PROTOCOL_ERROR,
            0x0102 => Self::H3_INTERNAL_ERROR,
            0x0103 => Self::H3_STREAM_CREATION_ERROR,
            0x0104 => Self::H3_CLOSED_CRITICAL_STREAM,
            0x0105 => Self::H3_FRAME_UNEXPECTED,
            0x0106 => Self::H3_FRAME_ERROR,
            0x0107 => Self::H3_EXCESSIVE_LOAD,
            0x0108 => Self::H3_ID_ERROR,
            0x0109 => Self::H3_SETTINGS_ERROR,
            0x010a => Self::H3_MISSING_SETTINGS,
            0x010b => Self::H3_REQUEST_REJECTED,
            0x010c => Self::H3_REQUEST_CANCELLED,
            0x010d => Self::H3_REQUEST_INCOMPLETE,
            0x010e => Self::H3_MESSAGE_ERROR,
            0x010f => Self::H3_CONNECT_ERROR,
            0x0110 => Self::H3_VERSION_FALLBACK,
            0x0200 => Self::QPACK_DECOMPRESSION_FAILED,
            0x0201 => Self::QPACK_ENCODER_STREAM_ERROR,
            0x0202 => Self::QPACK_DECODER_STREAM_ERROR,
            code => Self::Other(code),
        }
    }
}
