use std::{convert::Infallible, error::Error, io};

use snafu::Snafu;

use crate::error::{Code, ErrorWithCode, HasErrorCode, StreamError};

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

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum DecodeStreamError {
    #[snafu(transparent)]
    Stream { source: StreamError },
    #[snafu(transparent)]
    Decode { source: DecodeError },
    #[snafu(transparent)]
    Code { source: ErrorWithCode },
}

impl<E: HasErrorCode + Error + Send + Sync + 'static> From<E> for DecodeStreamError {
    fn from(value: E) -> Self {
        DecodeStreamError::Code {
            source: value.into(),
        }
    }
}

impl From<DecodeStreamError> for io::Error {
    fn from(value: DecodeStreamError) -> Self {
        match value {
            DecodeStreamError::Stream { source } => io::Error::from(source),
            DecodeStreamError::Decode { source } => io::Error::from(source),
            DecodeStreamError::Code { source } => io::Error::from(source),
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
        let source = match source.downcast::<Code>() {
            Ok(error) => {
                return DecodeStreamError::Code {
                    source: error.into(),
                };
            }
            Err(source) => source,
        };
        let source = match source.downcast::<ErrorWithCode>() {
            Ok(error) => {
                return DecodeStreamError::Code { source: error };
            }
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
            panic!("io::Error is not from StreamReader nor Decoder")
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
    #[snafu(display("Frame payload too large"))]
    FramePayloadTooLarge,
}

impl From<EncodeError> for io::Error {
    fn from(error: EncodeError) -> Self {
        let kind = match error {
            EncodeError::WriteZero => io::ErrorKind::WriteZero,
            EncodeError::InvalidInput => io::ErrorKind::InvalidInput,
            EncodeError::FramePayloadTooLarge => io::ErrorKind::Other,
        };
        io::Error::new(kind, error)
    }
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
    #[snafu(transparent)]
    Code { source: ErrorWithCode },
}

impl From<EncodeStreamError> for io::Error {
    fn from(value: EncodeStreamError) -> Self {
        match value {
            EncodeStreamError::Stream { source } => source.into(),
            EncodeStreamError::Encode { source } => source.into(),
            EncodeStreamError::Code { source } => source.into(),
        }
    }
}

impl From<Infallible> for EncodeStreamError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<Code> for EncodeStreamError {
    fn from(value: Code) -> Self {
        EncodeStreamError::Code {
            source: value.into(),
        }
    }
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
        let source = match source.downcast::<Code>() {
            Ok(error) => {
                return EncodeStreamError::Code {
                    source: error.into(),
                };
            }
            Err(source) => source,
        };
        let source = match source.downcast::<ErrorWithCode>() {
            Ok(error) => {
                return EncodeStreamError::Code { source: error };
            }
            Err(source) => source,
        };
        match source.downcast::<EncodeStreamError>() {
            Ok(error) => error,
            Err(_) => panic!("io::Error is not from StreamReader, Encoder nor Decoder"),
        }
    }
}
