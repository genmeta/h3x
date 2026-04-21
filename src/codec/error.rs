use std::{convert::Infallible, io};

use snafu::Snafu;

use crate::{connection, quic, varint::VarInt};

#[non_exhaustive]
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(visibility(pub), module)]
pub enum DecodeError {
    #[snafu(display("stream closed unexpectedly"))]
    Incomplete,
    #[snafu(display("integer too large (overflow u64)"))]
    IntegerOverflow,
    #[snafu(display("invalid huffman code"))]
    InvalidHuffmanCode,
    /// e.g: eval Base (<https://datatracker.ietf.org/doc/html/rfc9204#section-4.5.1.2>)
    #[snafu(display("arithmetic overflow while decoding"))]
    ArithmeticOverflow,
    /// RFC 9204 §4.5.1.1: RIC decode failure or invalid base
    #[snafu(display("QPACK decompression failed"))]
    DecompressionFailed,
}

/// Converts `DecodeError` to `io::Error` for use across tokio I/O boundaries.
impl From<DecodeError> for io::Error {
    fn from(error: DecodeError) -> Self {
        let kind = match error {
            DecodeError::Incomplete => io::ErrorKind::UnexpectedEof,
            DecodeError::IntegerOverflow => io::ErrorKind::InvalidData,
            DecodeError::InvalidHuffmanCode
            | DecodeError::ArithmeticOverflow
            | DecodeError::DecompressionFailed => io::ErrorKind::InvalidData,
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

#[non_exhaustive]
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

/// Codec-level decode error observed on a stream where `RESET_STREAM` is a
/// valid outcome (request/response body, QPACK field section, etc.).
///
/// Mirrors [`connection::StreamError`] at the codec layer: `Connection` /
/// `Reset` carry the transport/protocol failure, `Decode` carries a codec
/// failure.
///
/// For streams where reset is **not** acceptable (critical streams per
/// RFC 9114 §6.2.1), first escalate via [`StreamDecodeError::escalate_reset`]
/// to get [`ConnectionDecodeError`].
#[non_exhaustive]
#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum StreamDecodeError {
    #[snafu(transparent)]
    Connection { source: connection::ConnectionError },
    #[snafu(display("stream reset with code {code}"))]
    Reset { code: VarInt },
    #[snafu(transparent)]
    Decode { source: DecodeError },
}

/// Codec-level decode error on a stream where `RESET_STREAM` has already been
/// escalated to a connection-level protocol error (e.g. closure of a critical
/// stream like the control stream or QPACK encoder/decoder stream).
///
/// Produced by [`StreamDecodeError::escalate_reset`].
#[non_exhaustive]
#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum ConnectionDecodeError {
    #[snafu(transparent)]
    Connection { source: connection::ConnectionError },
    #[snafu(transparent)]
    Decode { source: DecodeError },
}

impl StreamDecodeError {
    /// Escalate a stream reset into a connection-level error.
    ///
    /// Use on critical streams (RFC 9114 §6.2.1: control, QPACK encoder,
    /// QPACK decoder) where peer-initiated stream reset is itself a
    /// connection-level protocol violation.
    pub fn escalate_reset(
        self,
        on_reset: impl FnOnce(VarInt) -> connection::ConnectionError,
    ) -> ConnectionDecodeError {
        match self {
            StreamDecodeError::Connection { source } => {
                ConnectionDecodeError::Connection { source }
            }
            StreamDecodeError::Reset { code } => ConnectionDecodeError::Connection {
                source: on_reset(code),
            },
            StreamDecodeError::Decode { source } => ConnectionDecodeError::Decode { source },
        }
    }

    /// Convert the codec-level error into a stream-level
    /// [`connection::StreamError`], applying `on_decode` to the decode branch.
    pub fn into_stream_error(
        self,
        on_decode: impl FnOnce(DecodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            StreamDecodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            StreamDecodeError::Reset { code } => connection::StreamError::Reset { code },
            StreamDecodeError::Decode { source } => on_decode(source),
        }
    }

    /// Convert the codec-level error into a stream-level
    /// [`connection::StreamError`], treating stream reset and premature EOF
    /// ([`DecodeError::Incomplete`]) as "stream closed". Used on critical
    /// streams (RFC 9114 §6.2.1) where both conditions are a connection-level
    /// protocol violation.
    pub fn map_stream_closed(
        self,
        on_closed: impl FnOnce(Option<VarInt>) -> connection::StreamError,
        on_decode: impl FnOnce(DecodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            StreamDecodeError::Decode {
                source: DecodeError::Incomplete,
            } => on_closed(None),
            StreamDecodeError::Reset { code } => on_closed(Some(code)),
            StreamDecodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            StreamDecodeError::Decode { source } => on_decode(source),
        }
    }
}

impl ConnectionDecodeError {
    /// Convert the codec-level error into a stream-level
    /// [`connection::StreamError`], applying `on_decode` to the decode branch.
    pub fn into_stream_error(
        self,
        on_decode: impl FnOnce(DecodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            ConnectionDecodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            ConnectionDecodeError::Decode { source } => on_decode(source),
        }
    }
}

impl From<quic::StreamError> for StreamDecodeError {
    fn from(error: quic::StreamError) -> Self {
        match error {
            quic::StreamError::Connection { source } => StreamDecodeError::Connection {
                source: source.into(),
            },
            quic::StreamError::Reset { code } => StreamDecodeError::Reset { code },
        }
    }
}

impl From<quic::ConnectionError> for StreamDecodeError {
    fn from(error: quic::ConnectionError) -> Self {
        StreamDecodeError::Connection {
            source: error.into(),
        }
    }
}

impl From<quic::ConnectionError> for ConnectionDecodeError {
    fn from(error: quic::ConnectionError) -> Self {
        ConnectionDecodeError::Connection {
            source: error.into(),
        }
    }
}

impl From<StreamDecodeError> for io::Error {
    fn from(value: StreamDecodeError) -> Self {
        match value {
            StreamDecodeError::Connection { source } => io::Error::from(source),
            StreamDecodeError::Reset { .. } => io::Error::new(io::ErrorKind::BrokenPipe, value),
            StreamDecodeError::Decode { source } => io::Error::from(source),
        }
    }
}

impl From<ConnectionDecodeError> for io::Error {
    fn from(value: ConnectionDecodeError) -> Self {
        match value {
            ConnectionDecodeError::Connection { source } => io::Error::from(source),
            ConnectionDecodeError::Decode { source } => io::Error::from(source),
        }
    }
}

/// Recovers `StreamDecodeError` from `io::Error`.
///
/// Recovery chain: `StreamDecodeError` (downcast) → `quic::StreamError` →
/// `connection::ConnectionError` → `DecodeError`.
impl From<io::Error> for StreamDecodeError {
    fn from(error: io::Error) -> Self {
        let error = match error.downcast::<Self>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match quic::StreamError::try_from(error) {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        let error = match error.downcast::<connection::ConnectionError>() {
            Ok(error) => return Self::Connection { source: error },
            Err(error) => error,
        };
        match DecodeError::try_from(error) {
            Ok(error) => Self::Decode { source: error },
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to StreamDecodeError, this is a bug"
            ),
        }
    }
}

/// Codec-level encode error observed on a stream where `RESET_STREAM` is a
/// valid outcome.
///
/// Mirror of [`StreamDecodeError`] for the write path.
#[non_exhaustive]
#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum StreamEncodeError {
    #[snafu(transparent)]
    Connection { source: connection::ConnectionError },
    #[snafu(display("stream reset with code {code}"))]
    Reset { code: VarInt },
    #[snafu(transparent)]
    Encode { source: EncodeError },
}

/// Codec-level encode error on a stream where `RESET_STREAM` has already been
/// escalated to a connection-level protocol error.
#[non_exhaustive]
#[derive(Debug, Snafu, Clone)]
#[snafu(module)]
pub enum ConnectionEncodeError {
    #[snafu(transparent)]
    Connection { source: connection::ConnectionError },
    #[snafu(transparent)]
    Encode { source: EncodeError },
}

impl StreamEncodeError {
    pub fn escalate_reset(
        self,
        on_reset: impl FnOnce(VarInt) -> connection::ConnectionError,
    ) -> ConnectionEncodeError {
        match self {
            StreamEncodeError::Connection { source } => {
                ConnectionEncodeError::Connection { source }
            }
            StreamEncodeError::Reset { code } => ConnectionEncodeError::Connection {
                source: on_reset(code),
            },
            StreamEncodeError::Encode { source } => ConnectionEncodeError::Encode { source },
        }
    }

    pub fn into_stream_error(
        self,
        on_encode: impl FnOnce(EncodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            StreamEncodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            StreamEncodeError::Reset { code } => connection::StreamError::Reset { code },
            StreamEncodeError::Encode { source } => on_encode(source),
        }
    }

    /// Convert the codec-level error into a stream-level
    /// [`connection::StreamError`], treating stream reset as "stream closed".
    /// Used on critical streams (RFC 9114 §6.2.1).
    pub fn map_stream_closed(
        self,
        on_closed: impl FnOnce(VarInt) -> connection::StreamError,
        on_encode: impl FnOnce(EncodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            StreamEncodeError::Reset { code } => on_closed(code),
            StreamEncodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            StreamEncodeError::Encode { source } => on_encode(source),
        }
    }
}

impl ConnectionEncodeError {
    pub fn into_stream_error(
        self,
        on_encode: impl FnOnce(EncodeError) -> connection::StreamError,
    ) -> connection::StreamError {
        match self {
            ConnectionEncodeError::Connection { source } => {
                connection::StreamError::Connection { source }
            }
            ConnectionEncodeError::Encode { source } => on_encode(source),
        }
    }
}

impl From<Infallible> for StreamEncodeError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl From<quic::StreamError> for StreamEncodeError {
    fn from(error: quic::StreamError) -> Self {
        match error {
            quic::StreamError::Connection { source } => StreamEncodeError::Connection {
                source: source.into(),
            },
            quic::StreamError::Reset { code } => StreamEncodeError::Reset { code },
        }
    }
}

impl From<quic::ConnectionError> for StreamEncodeError {
    fn from(error: quic::ConnectionError) -> Self {
        StreamEncodeError::Connection {
            source: error.into(),
        }
    }
}

impl From<quic::ConnectionError> for ConnectionEncodeError {
    fn from(error: quic::ConnectionError) -> Self {
        ConnectionEncodeError::Connection {
            source: error.into(),
        }
    }
}

impl From<StreamEncodeError> for io::Error {
    fn from(value: StreamEncodeError) -> Self {
        match value {
            StreamEncodeError::Connection { source } => io::Error::from(source),
            StreamEncodeError::Reset { .. } => io::Error::new(io::ErrorKind::BrokenPipe, value),
            StreamEncodeError::Encode { source } => io::Error::from(source),
        }
    }
}

impl From<ConnectionEncodeError> for io::Error {
    fn from(value: ConnectionEncodeError) -> Self {
        match value {
            ConnectionEncodeError::Connection { source } => io::Error::from(source),
            ConnectionEncodeError::Encode { source } => io::Error::from(source),
        }
    }
}

/// Recovers `StreamEncodeError` from `io::Error`.
impl From<io::Error> for StreamEncodeError {
    fn from(error: io::Error) -> Self {
        let error = match error.downcast::<Self>() {
            Ok(error) => return error,
            Err(error) => error,
        };
        let error = match quic::StreamError::try_from(error) {
            Ok(error) => return error.into(),
            Err(error) => error,
        };
        let error = match error.downcast::<connection::ConnectionError>() {
            Ok(error) => return Self::Connection { source: error },
            Err(error) => error,
        };
        match EncodeError::try_from(error) {
            Ok(error) => Self::Encode { source: error },
            Err(error) => unreachable!(
                "io::Error({error:?}) cannot be converted to StreamEncodeError, this is a bug"
            ),
        }
    }
}
