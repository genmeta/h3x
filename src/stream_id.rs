use std::fmt;

use crate::varint::VarInt;

/// Request-scoped stream identification metadata.
///
/// This is a simple newtype wrapper around `VarInt` used to represent stream IDs
/// for request extensions. It is distinct from the protocol-specific `StreamId<S>`
/// future type found in `quic.rs`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub VarInt);

impl From<VarInt> for StreamId {
    fn from(varint: VarInt) -> Self {
        StreamId(varint)
    }
}

impl From<StreamId> for VarInt {
    fn from(stream_id: StreamId) -> Self {
        stream_id.0
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
