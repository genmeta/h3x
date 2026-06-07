use snafu::Snafu;

use super::{
    CloseSession, InvalidSessionId, InvalidWebTransportStreamCount, WebTransportSessionId,
};
use crate::{
    dhttp::message::MessageStreamError,
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
    #[snafu(display("peer HTTP/3 settings are not available"))]
    PeerSettingsUnavailable,
    #[snafu(display("webtransport is not enabled by peer settings"))]
    WebTransportNotEnabled,
    #[snafu(display("webtransport stream-count flow control is not enabled by peer settings"))]
    FlowControlNotEnabled,
    #[snafu(display("invalid peer webtransport initial stream count"))]
    InitialStreamCount {
        source: InvalidWebTransportStreamCount,
    },
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
    #[snafu(display("peer decreased webtransport max streams"))]
    DecreasingMaxStreams,
    #[snafu(display("webtransport stream queue capacity invariant failed"))]
    QueueCapacityInvariant,
    #[snafu(display("webtransport stream count overflow"))]
    StreamCount {
        source: InvalidWebTransportStreamCount,
    },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum SessionDrain {
    Requested(DrainReason),
    Closed(CloseReason),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainReason {
    Session(SessionDrainReason),
    HttpGoaway(crate::connection::ConnectionGoaway),
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDrainReason {
    Local,
    Remote,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone)]
pub enum CloseReason {
    Session(SessionCloseReason),
    Connection(crate::quic::ConnectionError),
}

impl PartialEq for CloseReason {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Session(left), Self::Session(right)) => left == right,
            _ => false,
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCloseReason {
    Local(CloseSession),
    Remote(CloseSession),
    Protocol { code: crate::error::Code },
    ControlStreamError,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub))]
pub enum DrainSessionError {
    #[snafu(display("webtransport session closed"))]
    Closed { source: SessionClosed },
    #[snafu(display("failed to send webtransport drain command"))]
    Command { source: ControlCommandError },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub))]
pub enum CloseSessionError {
    #[snafu(display("webtransport session closed"))]
    Closed { source: SessionClosed },
    #[snafu(display("failed to send webtransport close command"))]
    Command { source: ControlCommandError },
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module, visibility(pub(in crate::webtransport)))]
pub enum ControlCommandError {
    #[snafu(display("webtransport control task is closed"))]
    Closed,
    #[snafu(display("webtransport control task dropped response"))]
    ResponseDropped,
    #[snafu(display("failed to write webtransport control capsule"))]
    Write { source: MessageStreamError },
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
    #[snafu(display("failed to send webtransport stream credit command"))]
    Control { source: ControlCommandError },
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
