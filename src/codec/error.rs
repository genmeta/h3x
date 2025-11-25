use std::io;

use snafu::Snafu;

use crate::{connection, error::Code, quic, varint::VarInt};

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(visibility(pub), context(suffix(DecodeSanfu)))]
pub enum DecodeError {
    #[snafu(display("Stream closed unexpectedly"))]
    Incomplete,
    #[snafu(display("Integer too large(overflow u64)"))]
    IntegerOverflow,
    // #[snafu(display("Huffman padding error"))]
    // HuffmanPadding,
    #[snafu(display("Invalid Huffman code"))]
    InvalidHuffmanCode,
    /// e.g: eval Base (https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2)
    #[snafu(display("Arithmetic overflow while decoding"))]
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

#[derive(Debug, Snafu, Clone)]
#[snafu(visibility(pub))]
pub enum DecodeStreamError {
    #[snafu(transparent)]
    Stream { source: quic::StreamError },
    #[snafu(transparent)]
    Decode { source: DecodeError },
}

impl DecodeStreamError {
    pub fn map_stream_reset(self, map: impl FnOnce(VarInt) -> Self) -> Self {
        match self {
            DecodeStreamError::Stream {
                source: quic::StreamError::Reset { code },
            } => map(code),
            error => error,
        }
    }

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
        stream_closed: impl FnOnce() -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            DecodeStreamError::Decode {
                source: DecodeError::Incomplete,
            } => stream_closed(),
            DecodeStreamError::Stream {
                source: quic::StreamError::Reset { .. },
            } => stream_closed(),
            DecodeStreamError::Decode { source } => {
                Code::H3_GENERAL_PROTOCOL_ERROR.with(source).into()
            }
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
    fn from(source: io::Error) -> Self {
        let source = match source.downcast::<quic::ConnectionError>() {
            Ok(error) => {
                return DecodeStreamError::Stream {
                    source: error.into(),
                };
            }
            Err(source) => source,
        };
        let source = match source.downcast::<quic::StreamError>() {
            Ok(error) => return DecodeStreamError::Stream { source: error },
            Err(source) => source,
        };
        let source = match source.downcast::<DecodeError>() {
            Ok(error) => return DecodeStreamError::Decode { source: error },
            Err(source) => source,
        };

        let source = match source.downcast::<DecodeStreamError>() {
            Ok(error) => return error,
            Err(source) => source,
        };
        if source.kind() == io::ErrorKind::UnexpectedEof {
            DecodeStreamError::Decode {
                source: DecodeError::Incomplete,
            }
        } else {
            panic!("io::Error({source:?}) is neither from StreamReader nor Decoder")
        }
    }
}
