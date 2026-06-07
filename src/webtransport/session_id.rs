use std::fmt;

use snafu::Snafu;

use crate::{
    error::{Code, H3ConnectionError},
    stream_id::StreamId,
};

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WebTransportSessionId(StreamId);

impl WebTransportSessionId {
    pub const fn stream_id(self) -> StreamId {
        self.0
    }
}

impl TryFrom<StreamId> for WebTransportSessionId {
    type Error = InvalidSessionId;

    fn try_from(session_id: StreamId) -> Result<Self, Self::Error> {
        if session_id.is_client_initiated_bidirectional() {
            Ok(Self(session_id))
        } else {
            Err(InvalidSessionId { session_id })
        }
    }
}

impl From<WebTransportSessionId> for StreamId {
    fn from(session_id: WebTransportSessionId) -> Self {
        session_id.0
    }
}

impl fmt::Display for WebTransportSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Snafu, Clone, Copy, PartialEq, Eq)]
#[snafu(display(
    "webtransport session id {session_id} is not a client-initiated bidirectional stream id"
))]
pub struct InvalidSessionId {
    session_id: StreamId,
}

impl InvalidSessionId {
    pub const fn session_id(&self) -> StreamId {
        self.session_id
    }
}

impl H3ConnectionError for InvalidSessionId {
    fn code(&self) -> Code {
        Code::H3_ID_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        error::{Code, H3ConnectionError},
        stream_id::StreamId,
        varint::VarInt,
    };

    #[test]
    fn session_id_accepts_only_client_initiated_bidirectional_stream_id() {
        let raw = StreamId::from(VarInt::from_u32(0));
        let session_id = WebTransportSessionId::try_from(raw).expect("valid session id");

        assert_eq!(session_id.stream_id(), raw);
        assert_eq!(StreamId::from(session_id), raw);
    }

    #[test]
    fn invalid_session_id_is_h3_id_error() {
        let error = WebTransportSessionId::try_from(StreamId::from(VarInt::from_u32(3)))
            .expect_err("server uni cannot be a session id");

        assert_eq!(error.session_id(), StreamId::from(VarInt::from_u32(3)));
        assert_eq!(H3ConnectionError::code(&error), Code::H3_ID_ERROR);
    }
}
