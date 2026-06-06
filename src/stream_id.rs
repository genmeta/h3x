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
/// [`UnresolvedRequest`](crate::endpoint::UnresolvedRequest) on the raw
/// endpoint path or as a request extension on the hyper path.
///
/// `StreamId` serves as the per-stream key when deriving protocol-specific session
/// handles from connection-scoped protocol state stored in [`Protocols`](crate::protocol::Protocols):
///
/// ```ignore
/// // Raw handler:
/// let proto = request.connection.protocols().get::<MyProtocol>().unwrap();
/// let session = proto.create_session(request.stream_id);
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

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamInitiator {
    Client,
    Server,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamDirection {
    Bidirectional,
    Unidirectional,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamKind {
    ClientBidirectional,
    ServerBidirectional,
    ClientUnidirectional,
    ServerUnidirectional,
}

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

    pub const fn initiator(self) -> StreamInitiator {
        if self.into_inner() & 0x01 == 0 {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        }
    }

    pub const fn direction(self) -> StreamDirection {
        if self.into_inner() & 0x02 == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }

    pub const fn kind(self) -> StreamKind {
        match (self.is_client_initiated(), self.is_bidirectional()) {
            (true, true) => StreamKind::ClientBidirectional,
            (false, true) => StreamKind::ServerBidirectional,
            (true, false) => StreamKind::ClientUnidirectional,
            (false, false) => StreamKind::ServerUnidirectional,
        }
    }

    pub const fn is_client_initiated(self) -> bool {
        matches!(self.initiator(), StreamInitiator::Client)
    }

    pub const fn is_server_initiated(self) -> bool {
        matches!(self.initiator(), StreamInitiator::Server)
    }

    pub const fn is_bidirectional(self) -> bool {
        matches!(self.direction(), StreamDirection::Bidirectional)
    }

    pub const fn is_unidirectional(self) -> bool {
        matches!(self.direction(), StreamDirection::Unidirectional)
    }

    pub const fn is_client_initiated_bidirectional(self) -> bool {
        self.is_client_initiated() && self.is_bidirectional()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{DecodeFrom, EncodeInto};

    #[test]
    fn conversions_preserve_inner_varint() {
        let raw = VarInt::from_u32(123);
        let stream_id = StreamId::from(raw);

        assert_eq!(stream_id.into_inner(), 123);
        assert_eq!(VarInt::from(stream_id), raw);
    }

    #[test]
    fn try_from_rejects_values_outside_varint_range() {
        let error = StreamId::try_from(1_u64 << 62).expect_err("value exceeds QUIC varint range");

        assert_eq!(
            error.to_string(),
            "value(4611686018427387904) too large for varint encoding"
        );
    }

    #[test]
    fn display_delegates_to_inner_varint() {
        let stream_id = StreamId::from(VarInt::from_u32(7));

        assert_eq!(stream_id.to_string(), "7");
    }

    #[test]
    fn stream_id_exposes_quic_initiator_and_direction() {
        let client_bi = StreamId::from(VarInt::from_u32(0));
        let server_bi = StreamId::from(VarInt::from_u32(1));
        let client_uni = StreamId::from(VarInt::from_u32(2));
        let server_uni = StreamId::from(VarInt::from_u32(3));

        assert_eq!(client_bi.kind(), StreamKind::ClientBidirectional);
        assert_eq!(server_bi.kind(), StreamKind::ServerBidirectional);
        assert_eq!(client_uni.kind(), StreamKind::ClientUnidirectional);
        assert_eq!(server_uni.kind(), StreamKind::ServerUnidirectional);

        assert_eq!(client_bi.initiator(), StreamInitiator::Client);
        assert_eq!(server_bi.initiator(), StreamInitiator::Server);
        assert_eq!(client_uni.direction(), StreamDirection::Unidirectional);
        assert_eq!(server_bi.direction(), StreamDirection::Bidirectional);

        assert!(client_bi.is_client_initiated_bidirectional());
        assert!(!server_bi.is_client_initiated_bidirectional());
        assert!(!client_uni.is_client_initiated_bidirectional());
    }

    #[tokio::test]
    async fn encode_decode_round_trips() {
        let (mut writer, mut reader) = tokio::io::duplex(8);
        let expected = StreamId::from(VarInt::from_u32(0x3fff));

        let write = async move { expected.encode_into(&mut writer).await.expect("encode") };
        let read = async move { StreamId::decode_from(&mut reader).await.expect("decode") };

        let ((), decoded) = tokio::join!(write, read);

        assert_eq!(decoded, expected);
    }
}
