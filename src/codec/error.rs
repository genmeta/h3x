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

    /// Escalate both peer-initiated reset and premature EOF
    /// ([`DecodeError::Incomplete`]) into a single connection-level error.
    ///
    /// Use on critical streams (RFC 9114 §6.2.1: control stream, QPACK
    /// encoder/decoder stream) where any form of stream closure before the
    /// protocol-level end is itself a connection-level violation.
    pub fn escalate_critical_close(
        self,
        on_closed: impl FnOnce() -> connection::ConnectionError,
    ) -> ConnectionDecodeError {
        match self {
            StreamDecodeError::Connection { source } => {
                ConnectionDecodeError::Connection { source }
            }
            StreamDecodeError::Reset { .. } => ConnectionDecodeError::Connection {
                source: on_closed(),
            },
            StreamDecodeError::Decode {
                source: DecodeError::Incomplete,
            } => ConnectionDecodeError::Connection {
                source: on_closed(),
            },
            StreamDecodeError::Decode { source } => ConnectionDecodeError::Decode { source },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{Code, H3NoError};

    fn varint(value: u32) -> VarInt {
        VarInt::from_u32(value)
    }

    fn transport_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: varint(1),
                frame_type: varint(2),
                reason: reason.into(),
            },
        }
    }

    fn application_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Application {
            source: quic::ApplicationError {
                code: Code::H3_INTERNAL_ERROR,
                reason: reason.into(),
            },
        }
    }

    fn connection_error(reason: &'static str) -> connection::ConnectionError {
        transport_error(reason).into()
    }

    fn assert_connection_reason(error: &connection::ConnectionError, expected: &str) {
        let connection::ConnectionError::Quic {
            source: quic::ConnectionError::Transport { source },
        } = error
        else {
            panic!("expected transport connection error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    fn assert_stream_reset(error: connection::StreamError, expected: VarInt) {
        let connection::StreamError::Reset { code } = error else {
            panic!("expected stream reset");
        };
        assert_eq!(code, expected);
    }

    fn assert_stream_h3(error: connection::StreamError) {
        let connection::StreamError::H3 { source } = error else {
            panic!("expected h3 stream error");
        };
        assert_eq!(source.code(), Code::H3_MESSAGE_ERROR);
    }

    fn assert_no_source(error: &(dyn std::error::Error + 'static)) {
        assert!(
            error.source().is_none(),
            "expected no source, got {error:?}"
        );
    }

    #[test]
    fn decode_error_io_roundtrips_and_classifies_plain_eof() {
        let cases = [
            (DecodeError::Incomplete, io::ErrorKind::UnexpectedEof),
            (DecodeError::IntegerOverflow, io::ErrorKind::InvalidData),
            (DecodeError::InvalidHuffmanCode, io::ErrorKind::InvalidData),
            (DecodeError::ArithmeticOverflow, io::ErrorKind::InvalidData),
            (DecodeError::DecompressionFailed, io::ErrorKind::InvalidData),
        ];

        for (error, expected_kind) in cases {
            let io_error = io::Error::from(error);
            assert_eq!(io_error.kind(), expected_kind);
            assert_eq!(
                DecodeError::try_from(io_error).expect("decode error"),
                error
            );
        }

        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "plain eof");
        assert_eq!(
            DecodeError::try_from(eof).expect("plain eof should map to incomplete"),
            DecodeError::Incomplete
        );

        let other = io::Error::new(io::ErrorKind::InvalidData, "plain invalid data");
        let other = DecodeError::try_from(other).expect_err("plain error should be preserved");
        assert_eq!(other.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn encode_error_io_roundtrips() {
        for error in [
            EncodeError::FramePayloadTooLarge,
            EncodeError::HuffmanEncoding,
        ] {
            let io_error = io::Error::from(error);
            assert_eq!(io_error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                EncodeError::try_from(io_error).expect("encode error"),
                error
            );
        }

        let other = io::Error::new(io::ErrorKind::InvalidData, "plain invalid data");
        let other = EncodeError::try_from(other).expect_err("plain error should be preserved");
        assert_eq!(other.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn codec_leaf_errors_have_expected_display_debug_and_source() {
        let decode_cases = [
            (
                DecodeError::Incomplete,
                "stream closed unexpectedly",
                "Incomplete",
            ),
            (
                DecodeError::IntegerOverflow,
                "integer too large (overflow u64)",
                "IntegerOverflow",
            ),
            (
                DecodeError::InvalidHuffmanCode,
                "invalid huffman code",
                "InvalidHuffmanCode",
            ),
            (
                DecodeError::ArithmeticOverflow,
                "arithmetic overflow while decoding",
                "ArithmeticOverflow",
            ),
            (
                DecodeError::DecompressionFailed,
                "QPACK decompression failed",
                "DecompressionFailed",
            ),
        ];

        for (error, display, debug_fragment) in decode_cases {
            assert_eq!(error.to_string(), display);
            assert!(format!("{error:?}").contains(debug_fragment));
            assert_no_source(&error);
        }

        let encode_cases = [
            (
                EncodeError::FramePayloadTooLarge,
                "frame payload too large (overflow 2^62-1)",
                "FramePayloadTooLarge",
            ),
            (
                EncodeError::HuffmanEncoding,
                "header name/value contains bytes out of QPACK allowed range",
                "HuffmanEncoding",
            ),
        ];

        for (error, display, debug_fragment) in encode_cases {
            assert_eq!(error.to_string(), display);
            assert!(format!("{error:?}").contains(debug_fragment));
            assert_no_source(&error);
        }
    }

    #[test]
    fn huffman_library_errors_map_to_codec_errors() {
        assert_eq!(
            DecodeError::from(httlib_huffman::DecoderError::InvalidInput),
            DecodeError::InvalidHuffmanCode
        );
        assert_eq!(
            EncodeError::from(httlib_huffman::EncoderError::InvalidInput),
            EncodeError::FramePayloadTooLarge
        );
    }

    #[test]
    fn stream_decode_escalation_covers_all_branches() {
        let error = StreamDecodeError::Connection {
            source: connection_error("connection"),
        };
        let escalated = error.escalate_reset(|_| connection_error("reset"));
        let ConnectionDecodeError::Connection { source } = escalated else {
            panic!("expected connection branch");
        };
        assert_connection_reason(&source, "connection");

        let escalated = StreamDecodeError::Reset { code: varint(7) }
            .escalate_reset(|code| connection_error(if code == varint(7) { "reset" } else { "" }));
        let ConnectionDecodeError::Connection { source } = escalated else {
            panic!("expected reset escalation");
        };
        assert_connection_reason(&source, "reset");

        let escalated = StreamDecodeError::Decode {
            source: DecodeError::IntegerOverflow,
        }
        .escalate_reset(|_| connection_error("unused"));
        let ConnectionDecodeError::Decode { source } = escalated else {
            panic!("expected decode branch");
        };
        assert_eq!(source, DecodeError::IntegerOverflow);
    }

    #[test]
    fn stream_decode_critical_close_escalates_reset_and_incomplete() {
        let escalated = StreamDecodeError::Connection {
            source: connection_error("connection"),
        }
        .escalate_critical_close(|| connection_error("unused"));
        let ConnectionDecodeError::Connection { source } = escalated else {
            panic!("expected connection branch");
        };
        assert_connection_reason(&source, "connection");

        for error in [
            StreamDecodeError::Reset { code: varint(1) },
            StreamDecodeError::Decode {
                source: DecodeError::Incomplete,
            },
        ] {
            let escalated = error.escalate_critical_close(|| connection_error("closed"));
            let ConnectionDecodeError::Connection { source } = escalated else {
                panic!("expected critical close");
            };
            assert_connection_reason(&source, "closed");
        }

        let escalated = StreamDecodeError::Decode {
            source: DecodeError::InvalidHuffmanCode,
        }
        .escalate_critical_close(|| connection_error("unused"));
        let ConnectionDecodeError::Decode { source } = escalated else {
            panic!("expected decode branch");
        };
        assert_eq!(source, DecodeError::InvalidHuffmanCode);
    }

    #[test]
    fn stream_decode_error_recovers_plain_eof_as_incomplete_decode() {
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "plain eof");
        let StreamDecodeError::Decode { source } = StreamDecodeError::from(eof) else {
            panic!("expected incomplete decode error");
        };
        assert_eq!(source, DecodeError::Incomplete);
    }

    #[test]
    fn stream_decode_into_stream_error_covers_all_branches() {
        let error = StreamDecodeError::Connection {
            source: connection_error("connection"),
        }
        .into_stream_error(|_| H3NoError.into());
        let connection::StreamError::Connection { source } = error else {
            panic!("expected connection stream error");
        };
        assert_connection_reason(&source, "connection");

        assert_stream_reset(
            StreamDecodeError::Reset { code: varint(9) }.into_stream_error(|_| H3NoError.into()),
            varint(9),
        );

        assert_stream_h3(
            StreamDecodeError::Decode {
                source: DecodeError::DecompressionFailed,
            }
            .into_stream_error(|_| crate::error::H3MessageError::UnexpectedHeadersInBody.into()),
        );
    }

    #[test]
    fn connection_decode_into_stream_error_covers_all_branches() {
        let error = ConnectionDecodeError::Connection {
            source: connection_error("connection"),
        }
        .into_stream_error(|_| H3NoError.into());
        let connection::StreamError::Connection { source } = error else {
            panic!("expected connection stream error");
        };
        assert_connection_reason(&source, "connection");

        assert_stream_h3(
            ConnectionDecodeError::Decode {
                source: DecodeError::ArithmeticOverflow,
            }
            .into_stream_error(|_| crate::error::H3MessageError::MissingHeaderSection.into()),
        );
    }

    #[test]
    fn stream_decode_error_recovers_from_io_error_sources() {
        let direct = io::Error::from(StreamDecodeError::Reset { code: varint(1) });
        let StreamDecodeError::Reset { code } = StreamDecodeError::from(direct) else {
            panic!("expected direct stream decode error");
        };
        assert_eq!(code, varint(1));

        let quic_reset = io::Error::from(quic::StreamError::Reset { code: varint(2) });
        let StreamDecodeError::Reset { code } = StreamDecodeError::from(quic_reset) else {
            panic!("expected quic stream reset");
        };
        assert_eq!(code, varint(2));

        let quic_connection = io::Error::from(quic::StreamError::Connection {
            source: transport_error("quic stream connection"),
        });
        let StreamDecodeError::Connection { source } = StreamDecodeError::from(quic_connection)
        else {
            panic!("expected quic connection");
        };
        assert_connection_reason(&source, "quic stream connection");

        let h3_connection = io::Error::from(connection_error("h3 connection"));
        let StreamDecodeError::Connection { source } = StreamDecodeError::from(h3_connection)
        else {
            panic!("expected h3 connection");
        };
        assert_connection_reason(&source, "h3 connection");

        let decode = io::Error::from(DecodeError::ArithmeticOverflow);
        let StreamDecodeError::Decode { source } = StreamDecodeError::from(decode) else {
            panic!("expected decode error");
        };
        assert_eq!(source, DecodeError::ArithmeticOverflow);
    }

    #[test]
    fn connection_decode_error_converts_to_io() {
        let io_error = io::Error::from(ConnectionDecodeError::Connection {
            source: connection_error("connection"),
        });
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);

        let io_error = io::Error::from(ConnectionDecodeError::Decode {
            source: DecodeError::Incomplete,
        });
        assert_eq!(io_error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn stream_decode_error_display_debug_source_and_quic_conversion() {
        let connection = StreamDecodeError::Connection {
            source: connection_error("connection display"),
        };
        assert_eq!(
            connection.to_string(),
            "transport error (0x1 in frame 0x2): connection display"
        );
        assert!(format!("{connection:?}").contains("Connection"));
        assert_no_source(&connection);
        let io_error = io::Error::from(connection);
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            io_error.get_ref().expect("wrapped error").to_string(),
            "transport error (0x1 in frame 0x2): connection display"
        );

        let reset = StreamDecodeError::Reset { code: varint(55) };
        assert_eq!(reset.to_string(), "stream reset with code 55");
        assert!(format!("{reset:?}").contains("Reset"));
        assert_no_source(&reset);
        let io_error = io::Error::from(reset);
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(io_error.to_string(), "stream reset with code 55");

        let decode = StreamDecodeError::Decode {
            source: DecodeError::DecompressionFailed,
        };
        assert_eq!(decode.to_string(), "QPACK decompression failed");
        assert!(format!("{decode:?}").contains("Decode"));
        assert_no_source(&decode);
        assert_eq!(io::Error::from(decode).kind(), io::ErrorKind::InvalidData);

        let converted = StreamDecodeError::from(transport_error("quic decode from conn"));
        let StreamDecodeError::Connection { source } = converted else {
            panic!("expected connection variant");
        };
        assert_connection_reason(&source, "quic decode from conn");

        let converted = ConnectionDecodeError::from(transport_error("quic conn decode"));
        let ConnectionDecodeError::Connection { source } = converted else {
            panic!("expected connection variant");
        };
        assert_connection_reason(&source, "quic conn decode");
    }

    #[test]
    fn connection_decode_error_display_debug_and_source() {
        let connection = ConnectionDecodeError::Connection {
            source: connection_error("connection decode display"),
        };
        assert_eq!(
            connection.to_string(),
            "transport error (0x1 in frame 0x2): connection decode display"
        );
        assert!(format!("{connection:?}").contains("Connection"));
        assert_no_source(&connection);

        let decode = ConnectionDecodeError::Decode {
            source: DecodeError::ArithmeticOverflow,
        };
        assert_eq!(decode.to_string(), "arithmetic overflow while decoding");
        assert!(format!("{decode:?}").contains("Decode"));
        assert_no_source(&decode);
        let io_error = io::Error::from(decode);
        assert_eq!(io_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            io_error.get_ref().expect("wrapped error").to_string(),
            "arithmetic overflow while decoding"
        );
    }

    #[test]
    fn stream_encode_escalation_covers_all_branches() {
        let error = StreamEncodeError::Connection {
            source: connection_error("connection"),
        };
        let escalated = error.escalate_reset(|_| connection_error("reset"));
        let ConnectionEncodeError::Connection { source } = escalated else {
            panic!("expected connection branch");
        };
        assert_connection_reason(&source, "connection");

        let escalated = StreamEncodeError::Reset { code: varint(7) }
            .escalate_reset(|code| connection_error(if code == varint(7) { "reset" } else { "" }));
        let ConnectionEncodeError::Connection { source } = escalated else {
            panic!("expected reset escalation");
        };
        assert_connection_reason(&source, "reset");

        let escalated = StreamEncodeError::Encode {
            source: EncodeError::HuffmanEncoding,
        }
        .escalate_reset(|_| connection_error("unused"));
        let ConnectionEncodeError::Encode { source } = escalated else {
            panic!("expected encode branch");
        };
        assert_eq!(source, EncodeError::HuffmanEncoding);
    }

    #[test]
    fn stream_encode_into_stream_error_covers_all_branches() {
        let error = StreamEncodeError::Connection {
            source: connection_error("connection"),
        }
        .into_stream_error(|_| H3NoError.into());
        let connection::StreamError::Connection { source } = error else {
            panic!("expected connection stream error");
        };
        assert_connection_reason(&source, "connection");

        assert_stream_reset(
            StreamEncodeError::Reset { code: varint(9) }.into_stream_error(|_| H3NoError.into()),
            varint(9),
        );

        assert_stream_h3(
            StreamEncodeError::Encode {
                source: EncodeError::HuffmanEncoding,
            }
            .into_stream_error(|_| crate::error::H3MessageError::UnexpectedHeadersInBody.into()),
        );
    }

    #[test]
    fn connection_encode_into_stream_error_covers_all_branches() {
        let error = ConnectionEncodeError::Connection {
            source: connection_error("connection"),
        }
        .into_stream_error(|_| H3NoError.into());
        let connection::StreamError::Connection { source } = error else {
            panic!("expected connection stream error");
        };
        assert_connection_reason(&source, "connection");

        assert_stream_h3(
            ConnectionEncodeError::Encode {
                source: EncodeError::FramePayloadTooLarge,
            }
            .into_stream_error(|_| crate::error::H3MessageError::MissingHeaderSection.into()),
        );
    }

    #[test]
    fn stream_encode_error_recovers_from_io_error_sources() {
        let direct = io::Error::from(StreamEncodeError::Reset { code: varint(1) });
        let StreamEncodeError::Reset { code } = StreamEncodeError::from(direct) else {
            panic!("expected direct stream encode error");
        };
        assert_eq!(code, varint(1));

        let quic_reset = io::Error::from(quic::StreamError::Reset { code: varint(2) });
        let StreamEncodeError::Reset { code } = StreamEncodeError::from(quic_reset) else {
            panic!("expected quic stream reset");
        };
        assert_eq!(code, varint(2));

        let quic_connection = io::Error::from(quic::StreamError::Connection {
            source: application_error("quic stream connection"),
        });
        let StreamEncodeError::Connection { source } = StreamEncodeError::from(quic_connection)
        else {
            panic!("expected quic connection");
        };
        let connection::ConnectionError::Quic {
            source: quic::ConnectionError::Application { source },
        } = source
        else {
            panic!("expected application error");
        };
        assert_eq!(source.reason.as_ref(), "quic stream connection");

        let h3_connection = io::Error::from(connection_error("h3 connection"));
        let StreamEncodeError::Connection { source } = StreamEncodeError::from(h3_connection)
        else {
            panic!("expected h3 connection");
        };
        assert_connection_reason(&source, "h3 connection");

        let encode = io::Error::from(EncodeError::HuffmanEncoding);
        let StreamEncodeError::Encode { source } = StreamEncodeError::from(encode) else {
            panic!("expected encode error");
        };
        assert_eq!(source, EncodeError::HuffmanEncoding);
    }

    #[test]
    fn connection_encode_error_converts_to_io() {
        let io_error = io::Error::from(ConnectionEncodeError::Connection {
            source: connection_error("connection"),
        });
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);

        let io_error = io::Error::from(ConnectionEncodeError::Encode {
            source: EncodeError::FramePayloadTooLarge,
        });
        assert_eq!(io_error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn stream_encode_error_display_debug_source_and_quic_conversion() {
        let connection = StreamEncodeError::Connection {
            source: connection_error("encode connection display"),
        };
        assert_eq!(
            connection.to_string(),
            "transport error (0x1 in frame 0x2): encode connection display"
        );
        assert!(format!("{connection:?}").contains("Connection"));
        assert_no_source(&connection);
        let io_error = io::Error::from(connection);
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            io_error.get_ref().expect("wrapped error").to_string(),
            "transport error (0x1 in frame 0x2): encode connection display"
        );

        let reset = StreamEncodeError::Reset { code: varint(88) };
        assert_eq!(reset.to_string(), "stream reset with code 88");
        assert!(format!("{reset:?}").contains("Reset"));
        assert_no_source(&reset);
        let io_error = io::Error::from(reset);
        assert_eq!(io_error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(io_error.to_string(), "stream reset with code 88");

        let encode = StreamEncodeError::Encode {
            source: EncodeError::FramePayloadTooLarge,
        };
        assert_eq!(
            encode.to_string(),
            "frame payload too large (overflow 2^62-1)"
        );
        assert!(format!("{encode:?}").contains("Encode"));
        assert_no_source(&encode);
        assert_eq!(io::Error::from(encode).kind(), io::ErrorKind::InvalidData);

        let converted = StreamEncodeError::from(application_error("quic encode from conn"));
        let StreamEncodeError::Connection { source } = converted else {
            panic!("expected connection variant");
        };
        let connection::ConnectionError::Quic {
            source: quic::ConnectionError::Application { source },
        } = source
        else {
            panic!("expected application error");
        };
        assert_eq!(source.reason.as_ref(), "quic encode from conn");

        let converted = ConnectionEncodeError::from(application_error("quic conn encode"));
        let ConnectionEncodeError::Connection { source } = converted else {
            panic!("expected connection variant");
        };
        let connection::ConnectionError::Quic {
            source: quic::ConnectionError::Application { source },
        } = source
        else {
            panic!("expected application error");
        };
        assert_eq!(source.reason.as_ref(), "quic conn encode");
    }

    #[test]
    fn connection_encode_error_display_debug_and_source() {
        let connection = ConnectionEncodeError::Connection {
            source: connection_error("connection encode display"),
        };
        assert_eq!(
            connection.to_string(),
            "transport error (0x1 in frame 0x2): connection encode display"
        );
        assert!(format!("{connection:?}").contains("Connection"));
        assert_no_source(&connection);

        let encode = ConnectionEncodeError::Encode {
            source: EncodeError::HuffmanEncoding,
        };
        assert_eq!(
            encode.to_string(),
            "header name/value contains bytes out of QPACK allowed range"
        );
        assert!(format!("{encode:?}").contains("Encode"));
        assert_no_source(&encode);
        let io_error = io::Error::from(encode);
        assert_eq!(io_error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            io_error.get_ref().expect("wrapped error").to_string(),
            "header name/value contains bytes out of QPACK allowed range"
        );
    }
}
