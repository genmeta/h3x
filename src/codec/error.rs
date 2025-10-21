use std::io;

use snafu::Snafu;

use crate::error::StreamError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(DecodeSanfu)))]
pub enum DecodeError {
    #[snafu(display("Stream ended unexpectedly"))]
    Incomplete,
    #[snafu(display("Integer too large(overflow u64)"))]
    IntegerOverflow,
    // #[snafu(display("Huffman padding error"))]
    // HuffmanPadding,
    #[snafu(display("Invalid Huffman code"))]
    InvalidValue,
}

impl From<DecodeError> for io::Error {
    fn from(error: DecodeError) -> Self {
        let kind = match error {
            DecodeError::Incomplete => io::ErrorKind::UnexpectedEof,
            DecodeError::IntegerOverflow => io::ErrorKind::InvalidData,
            DecodeError::InvalidValue => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, error)
    }
}

impl From<httlib_huffman::DecoderError> for DecodeError {
    fn from(error: httlib_huffman::DecoderError) -> Self {
        match error {
            httlib_huffman::DecoderError::InvalidInput => DecodeError::InvalidValue,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum DecodeStreamError {
    #[snafu(transparent)]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Decode { source: DecodeError },
}

impl From<DecodeStreamError> for io::Error {
    fn from(value: DecodeStreamError) -> Self {
        match value {
            DecodeStreamError::Stream { source } => io::Error::from(source),
            DecodeStreamError::Decode { source } => io::Error::from(source),
        }
    }
}

impl From<io::Error> for DecodeStreamError {
    fn from(source: io::Error) -> Self {
        let source = match source.downcast::<StreamError>() {
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
            unreachable!("io::Error is not from StreamReader nor Decoder")
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), context(suffix(EncodeSanfu)))]
pub enum EncodeError {
    #[snafu(display("Zero byte written while encoding"))]
    WriteZero,
    #[snafu(display("Invalid input"))]
    InvalidInput,
}

impl From<httlib_huffman::EncoderError> for EncodeError {
    fn from(error: httlib_huffman::EncoderError) -> Self {
        match error {
            httlib_huffman::EncoderError::InvalidInput => EncodeError::InvalidInput,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum EncodeStreamError {
    #[snafu(transparent)]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Encode { source: EncodeError },
}

impl From<io::Error> for EncodeStreamError {
    fn from(source: io::Error) -> Self {
        let source = match source.downcast::<StreamError>() {
            Ok(error) => return EncodeStreamError::Stream { source: error },
            Err(source) => source,
        };
        let source = match source.downcast::<EncodeError>() {
            Ok(error) => return EncodeStreamError::Encode { source: error },
            Err(source) => source,
        };
        match source.downcast::<EncodeStreamError>() {
            Ok(error) => error,
            Err(_) => unreachable!("io::Error is not from StreamReader, Encoder nor Decoder"),
        }
    }
}
