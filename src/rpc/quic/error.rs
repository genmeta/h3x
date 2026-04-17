use crate::{
    quic::{self, agent},
    varint::VarInt,
    webtransport,
};

/// Lossy: remoc RPC errors must be serialized across process boundaries, so the
/// original error type is stringified into a QUIC transport error reason.
impl From<remoc::rtc::CallError> for quic::ConnectionError {
    fn from(error: remoc::rtc::CallError) -> Self {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                // QUIC INTERNAL_ERROR (0x01)
                // https://datatracker.ietf.org/doc/html/rfc9000#section-20.1-2.4.1
                kind: VarInt::from_u32(0x01),
                // A value of 0 (equivalent to the mention of the PADDING frame) is used when the frame type is unknown.
                // https://datatracker.ietf.org/doc/html/rfc9000#section-19.19-6.4.1
                frame_type: VarInt::from_u32(0x00),
                reason: format!("remoc call error: {error}").into(),
            },
        }
    }
}

impl From<remoc::rtc::CallError> for quic::StreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        quic::ConnectionError::from(error).into()
    }
}

impl From<remoc::rtc::CallError> for agent::SignError {
    fn from(error: remoc::rtc::CallError) -> Self {
        quic::ConnectionError::from(error).into()
    }
}

impl From<remoc::rtc::CallError> for agent::VerifyError {
    fn from(error: remoc::rtc::CallError) -> Self {
        quic::ConnectionError::from(error).into()
    }
}

impl From<remoc::rtc::CallError> for crate::message::stream::MessageStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        quic::StreamError::from(error).into()
    }
}

impl From<remoc::rtc::CallError> for webtransport::OpenStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        webtransport::OpenStreamError::Open {
            source: quic::ConnectionError::from(error),
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::Closed {
    fn from(_error: remoc::rtc::CallError) -> Self {
        webtransport::Closed
    }
}

/// Lossy: errors are stringified for cross-process serialization via remoc RPC.
/// The remoc `Listen`/`Connect` traits require `StringError` (a serializable
/// wrapper) because the concrete error type is not known across the RPC boundary.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
pub struct StringError(String);

impl StringError {
    pub fn new(string: String) -> Self {
        Self(string)
    }
}

impl std::ops::Deref for StringError {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for StringError {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::error::Error for StringError {}

impl std::fmt::Display for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

// Purposefully skip printing "StringError(..)"
impl std::fmt::Debug for StringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}
