use snafu::Snafu;

use crate::{
    qpack::field::Protocol,
    quic::{ConnectionError, StreamError},
    stream_id::StreamId,
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(super)))]
pub enum RegisterSessionError {
    #[snafu(display("extended connect is missing a protocol token"))]
    MissingProtocol,
    #[snafu(display("extended connect protocol {protocol:?} is not webtransport-h3"))]
    UnexpectedProtocol { protocol: Protocol },
    #[snafu(display("webtransport protocol layer is not registered on the connection"))]
    ProtocolLayerMissing,
    #[snafu(display("session already registered for {session_id}"))]
    AlreadyRegistered { session_id: StreamId },
    #[snafu(display("session registry lock poisoned"))]
    RegistryPoisoned,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("webtransport session closed"))]
pub struct SessionClosed;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub))]
pub enum OpenStreamError {
    #[snafu(display("webtransport session closed"))]
    Closed { source: SessionClosed },
    #[snafu(display("failed to open QUIC stream"))]
    Open { source: ConnectionError },
    #[snafu(display("failed to write stream routing header"))]
    WriteHeader { source: StreamError },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub))]
pub enum AcceptStreamError {
    #[snafu(display("webtransport session closed"))]
    Closed { source: SessionClosed },
    #[snafu(display("webtransport connection closed"))]
    Connection { source: ConnectionError },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum DatagramError {
    #[snafu(display("datagrams are not yet supported"))]
    Unsupported,
}
