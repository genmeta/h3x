//! Error types for the WebTransport protocol layer.

use snafu::Snafu;

use crate::{
    quic::{ConnectionError, StreamError},
    stream_id::StreamId,
};

// ============================================================================
// Registration errors
// ============================================================================

/// Errors from [`WebTransportProtocol::register`](super::WebTransportProtocol::register).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum RegisterError {
    #[snafu(display("session already registered for {session_id}"))]
    AlreadyRegistered { session_id: StreamId },

    #[snafu(display("session registry lock poisoned"))]
    RegistryPoisoned,
}

// ============================================================================
// Stream-opening errors
// ============================================================================

/// Errors from [`WebTransportSession::open_bi`](super::WebTransportSession::open_bi)
/// and [`WebTransportSession::open_uni`](super::WebTransportSession::open_uni).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub))]
pub enum OpenStreamError {
    #[snafu(display("failed to open QUIC stream"))]
    Open { source: ConnectionError },

    #[snafu(display("failed to write stream routing header"))]
    WriteHeader { source: StreamError },
}

// ============================================================================
// Session-closed error
// ============================================================================

/// The WebTransport session has been closed and no more streams will arrive.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(display("webtransport session closed"))]
pub struct Closed;

// ============================================================================
// Datagram errors
// ============================================================================

/// Errors from datagram operations on [`WebTransportSession`](super::WebTransportSession).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum DatagramError {
    #[snafu(display("datagrams are not yet supported"))]
    Unsupported,
}
