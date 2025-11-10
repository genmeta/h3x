use std::{error::Error, io};

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
    Transport { reason: String },
    Application { reason: String },
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
    /// A stream required by the HTTP/3 connection was closed or reset.
    pub const H3_CLOSED_CRITICAL_STREAM: Self = Self(VarInt::from_u32(0x104));

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
