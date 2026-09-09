use std::{borrow::Cow, error::Error as StdError, fmt, sync::Arc};

use crate::StreamId;

type SharedError = Arc<dyn StdError + Send + Sync + 'static>;

/// An HTTP/3, QPACK, or enabled extension application error code.
///
/// Unknown peer codes are retained, provided they fit in a QUIC variable-length
/// integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Code(u64);

impl Code {
    pub const H3_NO_ERROR: Self = Self(0x0100);
    pub const H3_GENERAL_PROTOCOL_ERROR: Self = Self(0x0101);
    pub const H3_INTERNAL_ERROR: Self = Self(0x0102);
    pub const H3_STREAM_CREATION_ERROR: Self = Self(0x0103);
    pub const H3_CLOSED_CRITICAL_STREAM: Self = Self(0x0104);
    pub const H3_FRAME_UNEXPECTED: Self = Self(0x0105);
    pub const H3_FRAME_ERROR: Self = Self(0x0106);
    pub const H3_EXCESSIVE_LOAD: Self = Self(0x0107);
    pub const H3_ID_ERROR: Self = Self(0x0108);
    pub const H3_SETTINGS_ERROR: Self = Self(0x0109);
    pub const H3_MISSING_SETTINGS: Self = Self(0x010a);
    pub const H3_REQUEST_REJECTED: Self = Self(0x010b);
    pub const H3_REQUEST_CANCELLED: Self = Self(0x010c);
    pub const H3_REQUEST_INCOMPLETE: Self = Self(0x010d);
    pub const H3_MESSAGE_ERROR: Self = Self(0x010e);
    pub const H3_CONNECT_ERROR: Self = Self(0x010f);
    pub const H3_VERSION_FALLBACK: Self = Self(0x0110);

    pub const QPACK_DECOMPRESSION_FAILED: Self = Self(0x0200);
    pub const QPACK_ENCODER_STREAM_ERROR: Self = Self(0x0201);
    pub const QPACK_DECODER_STREAM_ERROR: Self = Self(0x0202);

    #[cfg(feature = "webtransport")]
    pub const H3_DATAGRAM_ERROR: Self = Self(0x0033);
    #[cfg(feature = "webtransport")]
    pub const WT_BUFFERED_STREAM_REJECTED: Self = Self(0x3994_bd84);
    #[cfg(feature = "webtransport")]
    pub const WT_SESSION_GONE: Self = Self(0x170d_7b68);
    #[cfg(feature = "webtransport")]
    pub const WT_FLOW_CONTROL_ERROR: Self = Self(0x045d_4487);
    #[cfg(feature = "webtransport")]
    pub const WT_ALPN_ERROR: Self = Self(0x0817_b3dd);
    #[cfg(feature = "webtransport")]
    pub const WT_REQUIREMENTS_NOT_MET: Self = Self(0x212c_0d48);

    /// Returns the numeric QUIC application error code.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    #[cfg(feature = "webtransport")]
    pub(crate) const fn new_unchecked(value: u64) -> Self {
        Self(value)
    }
}

impl TryFrom<u64> for Code {
    type Error = qbase::varint::err::Overflow;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        qbase::varint::VarInt::try_from(value).map(|_| Self(value))
    }
}

impl From<Code> for u64 {
    fn from(value: Code) -> Self {
        value.as_u64()
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::H3_NO_ERROR => Some("H3_NO_ERROR"),
            Self::H3_GENERAL_PROTOCOL_ERROR => Some("H3_GENERAL_PROTOCOL_ERROR"),
            Self::H3_INTERNAL_ERROR => Some("H3_INTERNAL_ERROR"),
            Self::H3_STREAM_CREATION_ERROR => Some("H3_STREAM_CREATION_ERROR"),
            Self::H3_CLOSED_CRITICAL_STREAM => Some("H3_CLOSED_CRITICAL_STREAM"),
            Self::H3_FRAME_UNEXPECTED => Some("H3_FRAME_UNEXPECTED"),
            Self::H3_FRAME_ERROR => Some("H3_FRAME_ERROR"),
            Self::H3_EXCESSIVE_LOAD => Some("H3_EXCESSIVE_LOAD"),
            Self::H3_ID_ERROR => Some("H3_ID_ERROR"),
            Self::H3_SETTINGS_ERROR => Some("H3_SETTINGS_ERROR"),
            Self::H3_MISSING_SETTINGS => Some("H3_MISSING_SETTINGS"),
            Self::H3_REQUEST_REJECTED => Some("H3_REQUEST_REJECTED"),
            Self::H3_REQUEST_CANCELLED => Some("H3_REQUEST_CANCELLED"),
            Self::H3_REQUEST_INCOMPLETE => Some("H3_REQUEST_INCOMPLETE"),
            Self::H3_MESSAGE_ERROR => Some("H3_MESSAGE_ERROR"),
            Self::H3_CONNECT_ERROR => Some("H3_CONNECT_ERROR"),
            Self::H3_VERSION_FALLBACK => Some("H3_VERSION_FALLBACK"),
            Self::QPACK_DECOMPRESSION_FAILED => Some("QPACK_DECOMPRESSION_FAILED"),
            Self::QPACK_ENCODER_STREAM_ERROR => Some("QPACK_ENCODER_STREAM_ERROR"),
            Self::QPACK_DECODER_STREAM_ERROR => Some("QPACK_DECODER_STREAM_ERROR"),
            #[cfg(feature = "webtransport")]
            Self::H3_DATAGRAM_ERROR => Some("H3_DATAGRAM_ERROR"),
            #[cfg(feature = "webtransport")]
            Self::WT_BUFFERED_STREAM_REJECTED => Some("WT_BUFFERED_STREAM_REJECTED"),
            #[cfg(feature = "webtransport")]
            Self::WT_SESSION_GONE => Some("WT_SESSION_GONE"),
            #[cfg(feature = "webtransport")]
            Self::WT_FLOW_CONTROL_ERROR => Some("WT_FLOW_CONTROL_ERROR"),
            #[cfg(feature = "webtransport")]
            Self::WT_ALPN_ERROR => Some("WT_ALPN_ERROR"),
            #[cfg(feature = "webtransport")]
            Self::WT_REQUIREMENTS_NOT_MET => Some("WT_REQUIREMENTS_NOT_MET"),
            _ => None,
        };

        match name {
            Some(name) => write!(f, "{name} (0x{:x})", self.0),
            None => write!(f, "HTTP/3 application error 0x{:x}", self.0),
        }
    }
}

/// Error returned by every public h3x operation and by [`crate::ChunkBody`].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Error {
    Connection {
        code: Code,
        source: Option<SharedError>,
    },
    Stream {
        code: Code,
        source: Option<SharedError>,
    },
    Goaway {
        boundary: StreamId,
    },
    Draining,
    Cancelled,
    BodyAborted,
    Capacity,
    OwnerStopped,
    NotInitialized,
    AlreadyInitialized,
    AlreadyListening,
    IdentityInUse,
    IdentityMismatch,
    CertificateRevoked,
    TimedOut,
    DrainTimedOut,
    Unsupported {
        operation: &'static str,
    },
    InvalidEndpoint {
        source: SharedError,
    },
    InvalidConfig {
        source: SharedError,
    },
    InvalidState {
        operation: &'static str,
    },
    InvalidSettings {
        source: SharedError,
    },
    InvalidMessage {
        source: SharedError,
    },
    Body {
        source: SharedError,
    },
    Transport {
        source: SharedError,
    },
}

impl Error {
    /// Returns the HTTP/3, QPACK, or extension application code when one exists.
    pub const fn code(&self) -> Option<Code> {
        match self {
            Self::Connection { code, .. } | Self::Stream { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub(crate) const fn is_connection(&self) -> bool {
        matches!(self, Self::Connection { .. } | Self::Transport { .. })
    }

    pub(crate) const fn is_stream(&self) -> bool {
        matches!(self, Self::Stream { .. })
    }

    pub(crate) fn into_invalid_message(self) -> Self {
        match self {
            Self::Stream {
                code: Code::H3_MESSAGE_ERROR,
                source: Some(source),
            } => Self::InvalidMessage { source },
            error => error,
        }
    }

    pub(crate) fn connection(
        code: Option<Code>,
        message: impl Into<Cow<'static, str>>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let source = context_source(message, source);
        match code {
            Some(code) => Self::Connection {
                code,
                source: Some(source),
            },
            None => Self::Transport { source },
        }
    }

    pub(crate) fn connection_protocol(code: Code, message: impl Into<Cow<'static, str>>) -> Self {
        Self::Connection {
            code,
            source: Some(message_source(message)),
        }
    }

    pub(crate) fn stream(code: Option<Code>, message: impl Into<Cow<'static, str>>) -> Self {
        let source = message_source(message);
        match code {
            Some(code) => Self::Stream {
                code,
                source: Some(source),
            },
            None => Self::InvalidMessage { source },
        }
    }

    pub(crate) fn stream_with_source(
        code: Option<Code>,
        message: impl Into<Cow<'static, str>>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        let source = context_source(message, source);
        match code {
            Some(code) => Self::Stream {
                code,
                source: Some(source),
            },
            None => Self::Transport { source },
        }
    }

    pub(crate) fn request_rejected(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Stream {
            code: Code::H3_REQUEST_REJECTED,
            source: Some(message_source(message)),
        }
    }

    pub(crate) fn invalid_stream_id(value: u64) -> Self {
        Self::InvalidMessage {
            source: message_source(format!(
                "stream ID {value} exceeds the QUIC variable-length integer range"
            )),
        }
    }

    pub(crate) const fn invalid_state(operation: &'static str) -> Self {
        Self::InvalidState { operation }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection { code, .. } => write!(f, "HTTP/3 connection error: {code}"),
            Self::Stream { code, .. } => write!(f, "HTTP/3 stream error: {code}"),
            Self::Goaway { boundary } => write!(f, "peer GOAWAY boundary: {boundary}"),
            Self::Draining => f.write_str("HTTP/3 connection is draining"),
            Self::Cancelled => f.write_str("HTTP request was cancelled"),
            Self::BodyAborted => f.write_str("HTTP upload was dropped without finishing"),
            Self::Capacity => f.write_str("HTTP runtime capacity exhausted"),
            Self::OwnerStopped => f.write_str("HTTP runtime owner stopped"),
            Self::NotInitialized => f.write_str("HTTP pool is not initialized"),
            Self::AlreadyInitialized => f.write_str("HTTP pool is already initialized"),
            Self::AlreadyListening => f.write_str("endpoint is already listening"),
            Self::IdentityInUse => f.write_str("endpoint name is owned by another instance"),
            Self::CertificateRevoked => f.write_str("certificate is revoked"),
            Self::IdentityMismatch => f.write_str("handshake identity does not match the request"),
            Self::TimedOut => f.write_str("HTTP connection deadline expired"),
            Self::DrainTimedOut => f.write_str("HTTP drain deadline expired"),
            Self::Unsupported { operation } => write!(f, "transport does not support {operation}"),
            Self::InvalidEndpoint { .. } => f.write_str("invalid endpoint material"),
            Self::InvalidConfig { .. } => f.write_str("invalid HTTP pool configuration"),
            Self::InvalidState { operation } => write!(f, "invalid state for {operation}"),
            Self::InvalidSettings { .. } => f.write_str("invalid HTTP/3 settings"),
            Self::InvalidMessage { .. } => f.write_str("invalid HTTP/3 message"),
            Self::Body { .. } => f.write_str("HTTP body error"),
            Self::Transport { .. } => f.write_str("QUIC transport error"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connection { source, .. } | Self::Stream { source, .. } => source
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static)),
            Self::InvalidSettings { source }
            | Self::InvalidMessage { source }
            | Self::Body { source }
            | Self::Transport { source }
            | Self::InvalidEndpoint { source }
            | Self::InvalidConfig { source } => Some(source.as_ref()),
            Self::Goaway { .. }
            | Self::Draining
            | Self::InvalidState { .. }
            | Self::Cancelled
            | Self::BodyAborted
            | Self::Capacity
            | Self::OwnerStopped
            | Self::NotInitialized
            | Self::AlreadyInitialized
            | Self::AlreadyListening
            | Self::IdentityInUse
            | Self::IdentityMismatch
            | Self::CertificateRevoked
            | Self::TimedOut
            | Self::DrainTimedOut
            | Self::Unsupported { .. } => None,
        }
    }
}

#[derive(Debug)]
struct ContextError {
    message: Cow<'static, str>,
    source: Option<SharedError>,
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl StdError for ContextError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

fn message_source(message: impl Into<Cow<'static, str>>) -> SharedError {
    Arc::new(ContextError {
        message: message.into(),
        source: None,
    })
}

fn context_source(
    message: impl Into<Cow<'static, str>>,
    source: impl StdError + Send + Sync + 'static,
) -> SharedError {
    Arc::new(ContextError {
        message: message.into(),
        source: Some(Arc::new(source)),
    })
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn keeps_variant_code_and_source_chain() {
        let error = Error::connection(
            Some(Code::H3_SETTINGS_ERROR),
            "invalid peer settings",
            io::Error::new(io::ErrorKind::InvalidData, "duplicate setting"),
        );

        assert!(matches!(
            error,
            Error::Connection {
                code: Code::H3_SETTINGS_ERROR,
                ..
            }
        ));
        assert_eq!(
            error.source().expect("source is retained").to_string(),
            "invalid peer settings"
        );
        assert_eq!(
            error.source().unwrap().source().unwrap().to_string(),
            "duplicate setting"
        );
    }

    #[test]
    fn preserves_unknown_application_codes() {
        let code = Code::try_from(0xface).expect("unknown code is a valid varint");

        assert_eq!(code.as_u64(), 0xface);
        assert_eq!(code.to_string(), "HTTP/3 application error 0xface");
    }

    #[test]
    fn body_error_has_a_distinct_variant_and_source() {
        let error = Error::Body {
            source: Arc::new(io::Error::other("producer failed")),
        };

        assert!(matches!(error, Error::Body { .. }));
        assert_eq!(error.source().unwrap().to_string(), "producer failed");
    }

    #[test]
    fn lifecycle_categories_do_not_invent_wire_codes() {
        assert!(matches!(
            Error::request_rejected("not delivered"),
            Error::Stream {
                code: Code::H3_REQUEST_REJECTED,
                ..
            }
        ));
    }
}
