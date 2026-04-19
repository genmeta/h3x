use std::fmt;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    codec::{DecodeFrom, EncodeInto},
    varint::VarInt,
};

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
/// let connection = request
///     .extensions()
///     .get::<Arc<ConnectionState<dyn DynConnection>>>()
///     .unwrap();
/// let protocols = connection.protocols();
/// let session = protocols.get::<MyProtocol>().unwrap().create_session(*stream_id);
/// ```
///
/// This type is distinct from the generic `StreamId<S>` future found in `quic.rs`,
/// which is a pin-projected stream ID accessor for transport-level stream types.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub VarInt);

impl<S: AsyncWrite + Send> EncodeInto<S> for StreamId {
    type Output = ();
    type Error = <VarInt as EncodeInto<S>>::Error;

    async fn encode_into(self, stream: S) -> Result<Self::Output, Self::Error> {
        self.0.encode_into(stream).await
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for StreamId {
    type Error = <VarInt as DecodeFrom<S>>::Error;

    async fn decode_from(stream: S) -> Result<Self, Self::Error> {
        VarInt::decode_from(stream).await.map(Self)
    }
}

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

impl StreamId {
    pub const fn into_inner(self) -> u64 {
        self.0.into_inner()
    }
}

impl TryFrom<u64> for StreamId {
    type Error = crate::varint::err::Overflow;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(VarInt::try_from(value)?))
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
