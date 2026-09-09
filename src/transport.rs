//! Transport boundary consumed by h3x.
//!
//! Connection operations use native dquic StreamReader / StreamWriter values. Connection
//! establishment, TLS identities, DNS, listeners and connection pools belong
//! to the caller.

use std::{error::Error as StdError, fmt, future::Future, sync::Arc};

use bytes::Bytes;
use dquic::prelude::{StreamReader, StreamWriter};
use futures::SinkExt;
pub use qbase::role::Role;

use crate::{
    Code, StreamId,
    platform::{MaybeSend, MaybeSync},
};

pub(crate) struct ResetOnDrop {
    writer: Option<StreamWriter>,
    on_finish: Option<Box<dyn FnOnce() + Send>>,
}
impl ResetOnDrop {
    pub(crate) fn new(writer: StreamWriter) -> Self {
        Self {
            writer: Some(writer),
            on_finish: None,
        }
    }

    pub(crate) fn on_finish(&mut self, callback: impl FnOnce() + Send + 'static) {
        self.on_finish = Some(Box::new(callback));
    }

    pub(crate) fn writer(&mut self) -> &mut StreamWriter {
        self.writer.as_mut().unwrap()
    }

    pub(crate) fn reset(&mut self, code: Code) {
        if let Some(mut writer) = self.writer.take() {
            dquic::prelude::CancelStream::cancel(&mut writer, code.as_u64());
        }
        if let Some(callback) = self.on_finish.take() {
            callback();
        }
    }

    pub(crate) async fn finish(&mut self) -> Result<(), dquic::prelude::StreamError> {
        self.writer().close().await?;
        self.writer.take();
        if let Some(callback) = self.on_finish.take() {
            callback();
        }
        Ok(())
    }
}
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        self.reset(Code::H3_REQUEST_CANCELLED);
    }
}

/// Internal cleanup for work that owns a connection until successful handoff.
/// Construct outside async work so cancellation before its first poll also closes.
pub(crate) struct CloseOnDrop<T: Connection>(pub(crate) Option<Arc<T>>, pub(crate) Code);

impl<T: Connection> Drop for CloseOnDrop<T> {
    fn drop(&mut self) {
        if let Some(transport) = &self.0 {
            transport.close(self.1, b"connection work dropped");
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
type SharedError = Arc<dyn StdError + Send + Sync + 'static>;
#[cfg(target_arch = "wasm32")]
type SharedError = Arc<dyn StdError + 'static>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionErrorKind {
    Transport,
    Application,
}

/// Terminal failure reported by the QUIC connection adapter.
#[derive(Debug, Clone)]
pub struct ConnectionError {
    kind: ConnectionErrorKind,
    code: Option<Code>,
    reason: Bytes,
    source: Option<SharedError>,
}

impl ConnectionError {
    /// Constructs a QUIC transport failure and retains its original source.
    pub fn transport(source: impl StdError + MaybeSend + MaybeSync + 'static) -> Self {
        Self {
            kind: ConnectionErrorKind::Transport,
            code: None,
            reason: Bytes::new(),
            source: Some(Arc::new(source)),
        }
    }

    /// Constructs a peer or local QUIC application close.
    pub fn application(code: Code, reason: impl Into<Bytes>) -> Self {
        Self {
            kind: ConnectionErrorKind::Application,
            code: Some(code),
            reason: reason.into(),
            source: None,
        }
    }

    /// Constructs an application close while retaining an adapter error.
    pub fn application_with_source(
        code: Code,
        reason: impl Into<Bytes>,
        source: impl StdError + MaybeSend + MaybeSync + 'static,
    ) -> Self {
        Self {
            kind: ConnectionErrorKind::Application,
            code: Some(code),
            reason: reason.into(),
            source: Some(Arc::new(source)),
        }
    }

    pub const fn is_transport(&self) -> bool {
        matches!(self.kind, ConnectionErrorKind::Transport)
    }

    pub const fn is_application(&self) -> bool {
        matches!(self.kind, ConnectionErrorKind::Application)
    }

    pub const fn code(&self) -> Option<Code> {
        self.code
    }

    /// Returns the QUIC application close reason, or an empty slice for a
    /// transport failure.
    pub fn reason(&self) -> &[u8] {
        &self.reason
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ConnectionErrorKind::Transport => f.write_str("QUIC transport failure"),
            ConnectionErrorKind::Application => {
                let code = self.code.expect("application errors always carry a code");
                write!(f, "QUIC application close: {code}")?;
                if !self.reason.is_empty() {
                    write!(f, ": {}", String::from_utf8_lossy(&self.reason))?;
                }
                Ok(())
            }
        }
    }
}

impl StdError for ConnectionError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamErrorKind {
    Connection,
    Reset,
}

/// Failure reported by a QUIC receive or send stream.
#[derive(Debug, Clone)]
pub struct StreamError {
    kind: StreamErrorKind,
    code: Option<Code>,
    connection: Option<ConnectionError>,
}

impl StreamError {
    pub fn connection(source: ConnectionError) -> Self {
        Self {
            kind: StreamErrorKind::Connection,
            code: source.code(),
            connection: Some(source),
        }
    }

    pub const fn reset(code: Code) -> Self {
        Self {
            kind: StreamErrorKind::Reset,
            code: Some(code),
            connection: None,
        }
    }

    pub const fn is_connection(&self) -> bool {
        matches!(self.kind, StreamErrorKind::Connection)
    }

    pub const fn is_reset(&self) -> bool {
        matches!(self.kind, StreamErrorKind::Reset)
    }

    pub const fn code(&self) -> Option<Code> {
        self.code
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            StreamErrorKind::Connection => f.write_str("QUIC connection failed while using stream"),
            StreamErrorKind::Reset => write!(
                f,
                "QUIC stream reset: {}",
                self.code.expect("reset errors always carry a code")
            ),
        }
    }
}

impl StdError for StreamError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.connection
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

impl From<ConnectionError> for StreamError {
    fn from(source: ConnectionError) -> Self {
        Self::connection(source)
    }
}

/// An established QUIC connection capable of opening and accepting streams.
pub trait Connection: MaybeSend + MaybeSync + 'static {
    /// The local QUIC role, independent of which peer initiates an HTTP request.
    /// Returns the connection error if the transport can no longer provide it.
    fn role(&self) -> Result<Role, ConnectionError>;

    /// Returns a locally initiated bidirectional ID and its matching read/write ends.
    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), ConnectionError>>
    + MaybeSend;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamWriter), ConnectionError>> + MaybeSend;

    /// Returns a peer-initiated bidirectional ID and its matching read/write ends.
    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (StreamReader, StreamWriter)), ConnectionError>>
    + MaybeSend;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, StreamReader), ConnectionError>> + MaybeSend;

    fn close(&self, code: Code, reason: &[u8]);

    fn closed(&self) -> impl Future<Output = ConnectionError> + MaybeSend;
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
        ) -> impl Future<Output = Result<(), ConnectionError>> + MaybeSend;

        fn receive_datagram(
            &self,
        ) -> impl Future<Output = Result<Bytes, ConnectionError>> + MaybeSend;

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
    fn application_and_reset_codes_are_queryable() {
        let connection = ConnectionError::application(Code::H3_NO_ERROR, "shutdown");
        let stream = StreamError::reset(Code::H3_REQUEST_CANCELLED);

        assert!(connection.is_application());
        assert_eq!(connection.code(), Some(Code::H3_NO_ERROR));
        assert_eq!(connection.reason(), b"shutdown");
        assert!(stream.is_reset());
        assert_eq!(stream.code(), Some(Code::H3_REQUEST_CANCELLED));
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
