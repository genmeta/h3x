use std::{convert::Infallible, io};

use snafu::Snafu;

use crate::{connection, quic, varint::VarInt};

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(visibility(pub), module)]
pub enum DecodeError {
    #[snafu(display("stream closed unexpectedly"))]
    Incomplete,
    #[snafu(display("integer too large (overflow u64)"))]
    IntegerOverflow,
    // #[snafu(display("huffman padding error"))]
    // HuffmanPadding,
    #[snafu(display("invalid huffman code"))]
    InvalidHuffmanCode,
    /// e.g: eval Base (https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2)
    #[snafu(display("arithmetic overflow while decoding"))]
    ArithmeticOverflow,
}

impl From<DecodeError> for io::Error {
    fn from(error: DecodeError) -> Self {
        let kind = match error {
            DecodeError::Incomplete => io::ErrorKind::UnexpectedEof,
            DecodeError::IntegerOverflow => io::ErrorKind::InvalidData,
            DecodeError::InvalidHuffmanCode | DecodeError::ArithmeticOverflow => {
                io::ErrorKind::InvalidData
            }
        };
        io::Error::new(kind, error)
    }
}

impl From<httlib_huffman::DecoderError> for DecodeError {
    fn from(error: httlib_huffman::DecoderError) -> Self {
        match error {
            httlib_huffman::DecoderError::InvalidInput => DecodeError::InvalidHuffmanCode,
        }
    }
}

impl TryFrom<io::Error> for DecodeError {
    type Error = io::Error;

    fn try_from(error: io::Error) -> Result<Self, Self::Error> {
        match error.downcast::<Self>() {
            Ok(error) => Ok(error),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(Self::Incomplete),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug, Snafu, Clone)]
pub enum DecodeStreamError {
    #[snafu(transparent)]
    Stream { source: quic::StreamError },
    #[snafu(transparent)]
    Decode { source: DecodeError },
}

impl DecodeStreamError {
    pub fn map_decode_error(
        self,
        map: impl FnOnce(DecodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            DecodeStreamError::Decode { source } => map(source),
            DecodeStreamError::Stream { source } => connection::StreamError::Quic { source },
        }
    }

    pub fn map_stream_closed(
        self,
        map_stream_closed: impl FnOnce(Option<VarInt>) -> connection::StreamError,
        map_decode_error: impl FnOnce(DecodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            DecodeStreamError::Decode {
                source: DecodeError::Incomplete,
            } => map_stream_closed(None),
            DecodeStreamError::Stream {
                source: quic::StreamError::Reset { code },
            } => map_stream_closed(Some(code)),
            DecodeStreamError::Decode { source } => map_decode_error(source),
            DecodeStreamError::Stream { source } => connection::StreamError::Quic { source },
        }
    }
}

impl From<DecodeStreamError> for io::Error {
    fn from(value: DecodeStreamError) -> Self {
        match value {
            DecodeStreamError::Stream { source } => io::Error::from(source),
            DecodeStreamError::Decode { source } => io::Error::from(source),
        }
    }
}

impl From<quic::ConnectionError> for DecodeStreamError {
    fn from(value: quic::ConnectionError) -> Self {
        DecodeStreamError::Stream {
            source: value.into(),
        }
    }
}

impl From<io::Error> for DecodeStreamError {
    fn from(error: io::Error) -> Self {
        let try_into = || {
            let error = match quic::StreamError::try_from(error) {
                Ok(error) => return Ok(error.into()),
                Err(error) => error,
            };
            let error = match DecodeError::try_from(error) {
                Ok(error) => return Ok(error.into()),
                Err(error) => error,
            };
            error.downcast::<Self>()
        };
        match try_into() {
            Ok(error) => error,
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to DecodeStreamError, this is a bug"
            ),
        }
    }
}

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(visibility(pub), module)]
pub enum EncodeError {
    #[snafu(display("frame payload too large (overflow 2^62-1)"))]
    FramePayloadTooLarge,
    #[snafu(display("header name/value contains bytes out of QPACK allowed range"))]
    HuffmanEncoding,
}

impl From<EncodeError> for io::Error {
    fn from(error: EncodeError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}

impl From<httlib_huffman::EncoderError> for EncodeError {
    fn from(error: httlib_huffman::EncoderError) -> Self {
        match error {
            httlib_huffman::EncoderError::InvalidInput => EncodeError::FramePayloadTooLarge,
        }
    }
}

impl TryFrom<io::Error> for EncodeError {
    type Error = io::Error;

    fn try_from(error: io::Error) -> Result<Self, Self::Error> {
        error.downcast::<Self>()
    }
}

#[derive(Debug, Snafu, Clone)]
pub enum EncodeStreamError {
    #[snafu(transparent)]
    Stream { source: quic::StreamError },
    #[snafu(transparent)]
    Encode { source: EncodeError },
}

impl EncodeStreamError {
    pub fn map_decode_error(
        self,
        map: impl FnOnce(EncodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            EncodeStreamError::Encode { source } => map(source),
            EncodeStreamError::Stream { source } => connection::StreamError::Quic { source },
        }
    }

    pub fn map_stream_closed(
        self,
        map_stream_closed: impl FnOnce(VarInt) -> connection::StreamError,
        map_encode_error: impl FnOnce(EncodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            EncodeStreamError::Encode { source } => map_encode_error(source),
            EncodeStreamError::Stream {
                source: quic::StreamError::Reset { code },
            } => map_stream_closed(code),
            EncodeStreamError::Stream { source } => connection::StreamError::Quic { source },
        }
    }
}

impl From<Infallible> for EncodeStreamError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<EncodeStreamError> for io::Error {
    fn from(value: EncodeStreamError) -> Self {
        match value {
            EncodeStreamError::Stream { source } => io::Error::from(source),
            EncodeStreamError::Encode { source } => io::Error::from(source),
        }
    }
}

impl From<io::Error> for EncodeStreamError {
    fn from(error: io::Error) -> Self {
        let try_into = || {
            let error = match quic::StreamError::try_from(error) {
                Ok(error) => return Ok(error.into()),
                Err(error) => error,
            };
            match EncodeError::try_from(error) {
                Ok(error) => Ok(Self::from(error)),
                Err(error) => error.downcast::<Self>(),
            }
        };
        match try_into() {
            Ok(error) => error,
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to EncodeStreamError, this is a bug"
            ),
        }
    }
}
