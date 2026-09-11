use std::{error::Error as StdError, fmt, io};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum Error {
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

impl Error {
    pub const fn as_u64(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?} (0x{:x})", *self as u64)
    }
}

impl StdError for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        error
            .get_ref()
            .and_then(|source| source.downcast_ref().copied())
            .unwrap_or(Self::H3_INTERNAL_ERROR)
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        Self::new(io::ErrorKind::InvalidData, error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_rfc_error_through_io() {
        let error = Error::from(io::Error::from(Error::H3_MESSAGE_ERROR));
        assert_eq!(error, Error::H3_MESSAGE_ERROR);
        assert_eq!(error.as_u64(), 0x010e);
    }
}
