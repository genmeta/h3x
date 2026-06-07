use snafu::Snafu;

use super::{InvalidSessionId, InvalidWebTransportStreamCount, WebTransportSessionId};
use crate::{
    qpack::field::Protocol,
    quic::{ConnectionError, StreamError},
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(in crate::webtransport)))]
pub enum RegisterSessionError {
    #[snafu(display("extended connect is missing a protocol token"))]
    MissingProtocol,
    #[snafu(display("extended connect protocol {protocol:?} is not webtransport-h3"))]
    UnexpectedProtocol { protocol: Protocol },
    #[snafu(display("webtransport protocol layer is not registered on the connection"))]
    ProtocolLayerMissing,
    #[snafu(display("invalid webtransport session id"))]
    InvalidSessionId { source: InvalidSessionId },
    #[snafu(display("session already registered for {session_id}"))]
    AlreadyRegistered { session_id: WebTransportSessionId },
    #[snafu(display("session registry lock poisoned"))]
    RegistryPoisoned,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("webtransport session closed"))]
pub struct SessionClosed;

#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(module, visibility(pub(in crate::webtransport)))]
pub enum SessionFlowControlError {
    #[snafu(display("peer exceeded webtransport stream credit"))]
    ExceededStreamCredit,
    #[snafu(display("webtransport stream queue capacity invariant failed"))]
    QueueCapacityInvariant,
    #[snafu(display("webtransport stream count overflow"))]
    StreamCount {
        source: InvalidWebTransportStreamCount,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub))]
pub enum OpenStreamError {
    #[snafu(display("webtransport session closed"))]
    Closed { source: SessionClosed },
    #[snafu(display("failed to open QUIC stream"))]
    Open { source: ConnectionError },
    #[snafu(display("failed to observe opened QUIC stream id"))]
    StreamId { source: StreamError },
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
    #[snafu(display("failed to observe accepted QUIC stream id"))]
    StreamId { source: StreamError },
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(super)))]
pub enum DatagramError {
    #[snafu(display("datagrams are not yet supported"))]
    Unsupported,
}
