use std::fmt;

use crate::varint::VarInt;

/// Request-scoped stream identifier for protocol extension access.
///
/// A lightweight newtype around [`VarInt`] representing the QUIC stream ID of the
/// current request/response pair. Injected as a field in
/// [`Request`](crate::server::Request) and [`Response`](crate::server::Response)
/// (native path) or as a request extension (hyper path).
///
/// `StreamId` serves as the per-stream key when deriving protocol-specific session
/// handles from connection-scoped protocol state stored in [`Protocols`](crate::protocol::Protocols):
///
/// ```ignore
/// // Native handler:
/// let proto = request.protocols().get::<MyProtocol>().unwrap();
/// let session = proto.create_session(request.stream_id());
///
/// // Hyper handler:
/// let stream_id = request.extensions().get::<StreamId>().unwrap();
/// let protocols = request.extensions().get::<Arc<Protocols>>().unwrap();
/// let session = protocols.get::<MyProtocol>().unwrap().create_session(*stream_id);
/// ```
///
/// This type is distinct from the generic `StreamId<S>` future found in `quic.rs`,
/// which is a pin-projected stream ID accessor for transport-level stream types.
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
