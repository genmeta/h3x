//! Transport boundary consumed by h3x.
//!
//! Implementations adapt an already-established QUIC connection. Connection
//! establishment, TLS identities, DNS, listeners and connection pools belong
//! to the caller.

use std::{error::Error as StdError, fmt, future::Future, pin::Pin, sync::Arc, task::{Context, Poll}};

use bytes::Bytes;
use futures::Sink;

use crate::{
    Code, StreamId,
    platform::{MaybeSend, MaybeSync},
};

pub use qbase::role::Role;

/// A transport awaiting adoption by the protocol.
/// Authentication and reuse policy belong to the runtime, not the protocol.
/// Dropping before adoption closes the transport.
pub struct PendingTransport<T: Connection> {
    pub(crate) transport: Option<T>,
}

impl<T: Connection> PendingTransport<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport: Some(transport),
        }
    }
}

impl<T: Connection> Drop for PendingTransport<T> {
    fn drop(&mut self) {
        if let Some(transport) = &self.transport {
            transport.close(Code::H3_REQUEST_CANCELLED, b"unadopted transport dropped");
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
    type RecvStream: RecvStream;
    type SendStream: SendStream;

    /// The local QUIC role, independent of which peer initiates an HTTP request.
    /// Returns the connection error if the transport can no longer provide it.
    fn role(&self) -> Result<Role, ConnectionError>;

    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (Self::RecvStream, Self::SendStream)), ConnectionError>> + MaybeSend;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, Self::SendStream), ConnectionError>> + MaybeSend;

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(StreamId, (Self::RecvStream, Self::SendStream)), ConnectionError>> + MaybeSend;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<(StreamId, Self::RecvStream), ConnectionError>> + MaybeSend;

    fn close(&self, code: Code, reason: &[u8]);

    fn closed(&self) -> impl Future<Output = ConnectionError> + MaybeSend;
}

/// Receive half of a QUIC stream; its ID is returned by the connection.
pub trait RecvStream: MaybeSend + Unpin + 'static {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, StreamError>>>;

    /// Submits STOP_SENDING to the transport. It does not wait for a peer ACK.
    fn stop(&mut self, code: Code) -> Result<(), StreamError>;
}

/// Send half of a QUIC stream; its ID is returned by the connection.
pub trait SendStream: MaybeSend + Unpin + 'static {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>>;

    /// Submits bytes to QUIC after poll_ready succeeds, without buffering in the adapter.
    fn start_send(&mut self, item: Bytes) -> Result<(), StreamError>;

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>>;

    /// Submits RESET_STREAM to the transport. It does not wait for a peer ACK.
    fn reset(&mut self, code: Code) -> Result<(), StreamError>;
}

impl Sink<Bytes> for dyn SendStream {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        SendStream::poll_ready(self.get_mut(), cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        SendStream::start_send(self.get_mut(), item)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // start_send submits directly to QUIC; HTTP/3 does not wait for peer ACKs.
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        SendStream::poll_close(self.get_mut(), cx)
    }
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
            stream: &mut Self::SendStream,
            code: Code,
            reliable_size: u64,
        ) -> Result<(), StreamError>;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{Sink, Stream};

    use super::*;

    struct Recv;

    impl Stream for Recv {
        type Item = Result<Bytes, StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    impl RecvStream for Recv {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, StreamError>>> {
        Stream::poll_next(Pin::new(self), cx)
    }

        fn stop(&mut self, _code: Code) -> Result<(), StreamError> {
            Ok(())
        }
    }

    struct Send;

    impl Sink<Bytes> for Send {
        type Error = StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl SendStream for Send {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Sink::poll_ready(Pin::new(self), cx)
    }

    fn start_send(&mut self, item: Bytes) -> Result<(), StreamError> {
        Sink::start_send(Pin::new(self), item)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Sink::poll_close(Pin::new(self), cx)
    }

        fn reset(&mut self, _code: Code) -> Result<(), StreamError> {
            Ok(())
        }
    }

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

    #[test]
    fn stream_traits_use_synchronous_control_actions() {
        let mut recv = Recv;
        let mut send = Send;

        recv.stop(Code::H3_REQUEST_CANCELLED).unwrap();
        send.reset(Code::H3_REQUEST_CANCELLED).unwrap();
    }
}
