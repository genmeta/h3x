//! Transport boundary consumed by h3x.
//!
//! Connection operations use native dquic StreamReader / StreamWriter values. Connection
//! establishment, TLS identities, DNS, listeners and connection pools belong
//! to the caller.

use std::{error::Error as StdError, fmt, future::Future, sync::Arc};

use bytes::Bytes;
use dquic::prelude::{StreamReader, StreamWriter};
pub use qbase::role::Role;

use crate::{Code, StreamId};

type SharedError = Arc<dyn StdError + Send + Sync + 'static>;

#[derive(Debug, Clone)]
enum ConnectionErrorKind {
    Transport(SharedError),
    Application {
        code: Code,
        reason: Bytes,
        source: Option<SharedError>,
    },
}

/// Terminal failure reported by the QUIC connection adapter.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    kind: ConnectionErrorKind,
}

impl ConnectionError {
    /// Constructs a QUIC transport failure and retains its original source.
    pub fn transport(source: impl StdError + Send + Sync + 'static) -> Self {
        Self {
            kind: ConnectionErrorKind::Transport(Arc::new(source)),
        }
    }

    /// Constructs a peer or local QUIC application close.
    pub fn application(code: Code, reason: impl Into<Bytes>) -> Self {
        Self {
            kind: ConnectionErrorKind::Application {
                code,
                reason: reason.into(),
                source: None,
            },
        }
    }

    /// Constructs an application close while retaining an adapter error.
    pub fn application_with_source(
        code: Code,
        reason: impl Into<Bytes>,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind: ConnectionErrorKind::Application {
                code,
                reason: reason.into(),
                source: Some(Arc::new(source)),
            },
        }
    }

    pub const fn is_transport(&self) -> bool {
        matches!(self.kind, ConnectionErrorKind::Transport(_))
    }

    pub const fn is_application(&self) -> bool {
        matches!(self.kind, ConnectionErrorKind::Application { .. })
    }

    pub const fn code(&self) -> Option<Code> {
        match &self.kind {
            ConnectionErrorKind::Transport(_) => None,
            ConnectionErrorKind::Application { code, .. } => Some(*code),
        }
    }

    /// Returns the QUIC application close reason, or an empty slice for a transport failure.
    pub fn reason(&self) -> &[u8] {
        match &self.kind {
            ConnectionErrorKind::Transport(_) => &[],
            ConnectionErrorKind::Application { reason, .. } => reason,
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ConnectionErrorKind::Transport(_) => f.write_str("QUIC transport failure"),
            ConnectionErrorKind::Application { code, reason, .. } => {
                write!(f, "QUIC application close: {code}")?;
                if !reason.is_empty() {
                    write!(f, ": {}", String::from_utf8_lossy(reason))?;
                }
                Ok(())
            }
        }
    }
}

impl StdError for ConnectionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.kind {
            ConnectionErrorKind::Transport(source) => Some(source.as_ref()),
            ConnectionErrorKind::Application { source, .. } => source
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static)),
        }
    }
}

#[derive(Debug, Clone)]
enum StreamErrorKind {
    Connection(ConnectionError),
    Reset(Code),
}

/// Failure reported by a QUIC receive or send stream.
#[derive(Debug, Clone)]
pub struct StreamError {
    kind: StreamErrorKind,
}

impl StreamError {
    pub fn connection(source: ConnectionError) -> Self {
        Self {
            kind: StreamErrorKind::Connection(source),
        }
    }

    pub const fn reset(code: Code) -> Self {
        Self {
            kind: StreamErrorKind::Reset(code),
        }
    }

    pub const fn is_connection(&self) -> bool {
        matches!(self.kind, StreamErrorKind::Connection(_))
    }

    pub const fn is_reset(&self) -> bool {
        matches!(self.kind, StreamErrorKind::Reset(_))
    }

    pub const fn code(&self) -> Option<Code> {
        match &self.kind {
            StreamErrorKind::Connection(source) => source.code(),
            StreamErrorKind::Reset(code) => Some(*code),
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            StreamErrorKind::Connection(_) => {
                f.write_str("QUIC connection failed while using stream")
            }
            StreamErrorKind::Reset(code) => write!(f, "QUIC stream reset: {code}"),
        }
    }
}

impl StdError for StreamError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.kind {
            StreamErrorKind::Connection(source) => Some(source),
            StreamErrorKind::Reset(_) => None,
        }
    }
}

impl From<ConnectionError> for StreamError {
    fn from(source: ConnectionError) -> Self {
        Self::connection(source)
    }
}

/// An established QUIC connection capable of opening and accepting streams.
pub trait Connection: Send + Sync + 'static {
    /// The local QUIC role, independent of which peer initiates an HTTP request.
    /// Returns the connection error if the transport can no longer provide it.
    fn role(&self) -> Result<Role, ConnectionError>;

    /// Returns a locally initiated bidirectional ID and its matching read/write ends.
    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), ConnectionError>> + Send;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamWriter), ConnectionError>> + Send;

    /// Returns a peer-initiated bidirectional ID and its matching read/write ends.
    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), ConnectionError>> + Send;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamReader), ConnectionError>> + Send;

    fn close(&self, code: Code, reason: &[u8]);

    fn closed(&self) -> impl Future<Output = ConnectionError> + Send;
}

/// Optional QUIC capabilities required by WebTransport over HTTP/3.
#[cfg(feature = "webtransport")]
pub mod webtransport {
    use super::*;

    /// Extends the base stream transport without changing the HTTP/3-only SPI.
    pub trait Connection: super::Connection {
        /// Whether both QUIC endpoints negotiated RESET_STREAM_AT.
        fn supports_reset_stream_at(&self) -> bool;

        /// Largest payload accepted by [`Self::send_datagram`].
        fn max_datagram_size(&self) -> usize;

        fn send_datagram(
            &self,
            datagram: Bytes,
        ) -> impl Future<Output = Result<(), ConnectionError>> + Send;

        fn receive_datagram(&self) -> impl Future<Output = Result<Bytes, ConnectionError>> + Send;

        /// Resets `stream` while reliably delivering at least `reliable_size`
        /// bytes from the beginning of its send direction.
        fn reset_stream_at(
            &self,
            stream: &mut StreamWriter,
            code: Code,
            reliable_size: u64,
        ) -> Result<(), StreamError>;
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn transport_failure_retains_source_without_inventing_an_h3_code() {
        let error = ConnectionError::transport(io::Error::other("network down"));

        assert!(error.is_transport());
        assert_eq!(error.code(), None);
        assert_eq!(error.source().unwrap().to_string(), "network down");
    }

    #[test]
    fn application_and_reset_codes_sources_and_display_are_preserved() {
        let reset = StreamError::reset(Code::H3_REQUEST_CANCELLED);
        assert!(reset.is_reset());
        assert!(!reset.is_connection());
        assert_eq!(reset.code(), Some(Code::H3_REQUEST_CANCELLED));
        assert!(reset.source().is_none());
        assert!(reset.to_string().contains("QUIC stream reset"));
        for (connection, code, reason, source) in [
            (
                ConnectionError::transport(io::Error::other("network down")),
                None,
                "",
                Some("network down"),
            ),
            (
                ConnectionError::application(Code::H3_NO_ERROR, "shutdown"),
                Some(Code::H3_NO_ERROR),
                "shutdown",
                None,
            ),
            (
                ConnectionError::application_with_source(
                    Code::H3_INTERNAL_ERROR,
                    "failed",
                    io::Error::other("cause"),
                ),
                Some(Code::H3_INTERNAL_ERROR),
                "failed",
                Some("cause"),
            ),
        ] {
            let connection = connection.clone();
            assert_eq!(connection.is_application(), code.is_some());
            assert_eq!(connection.is_transport(), code.is_none());
            assert_eq!(connection.code(), code);
            assert_eq!(connection.reason(), reason.as_bytes());
            assert_eq!(
                connection.source().map(ToString::to_string).as_deref(),
                source
            );
            assert!(connection.to_string().contains(reason));
            let stream = StreamError::from(connection.clone());
            assert!(stream.is_connection());
            assert!(!stream.is_reset());
            assert_eq!(stream.code(), code);
            assert_eq!(stream.source().unwrap().to_string(), connection.to_string());
        }
    }
}

impl From<dquic::prelude::Error> for ConnectionError {
    fn from(error: dquic::prelude::Error) -> Self {
        match error {
            dquic::prelude::Error::Quic(error) => {
                crate::transport::ConnectionError::transport(error)
            }
            dquic::prelude::Error::App(error) => {
                crate::transport::ConnectionError::application_with_source(
                    crate::Code::try_from(error.error_code())
                        .expect("QUIC application code fits a varint"),
                    Bytes::copy_from_slice(error.reason().as_bytes()),
                    error,
                )
            }
        }
    }
}

impl From<dquic::prelude::StreamError> for StreamError {
    fn from(error: dquic::prelude::StreamError) -> Self {
        match error {
            dquic::prelude::StreamError::Connection(error) => ConnectionError::from(error).into(),
            dquic::prelude::StreamError::Reset(error) => crate::transport::StreamError::reset(
                crate::Code::try_from(error.error_code()).expect("QUIC reset code fits a varint"),
            ),
            dquic::prelude::StreamError::EosSent => {
                crate::transport::ConnectionError::transport(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "QUIC send direction already finished",
                ))
                .into()
            }
        }
    }
}
