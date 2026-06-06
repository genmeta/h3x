use std::{convert::Infallible, io};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    buflist::BufList,
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    varint::{self, VarInt},
};

const READ_CHUNK_SIZE: u64 = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapsuleType(VarInt);

impl CapsuleType {
    pub const DATAGRAM: Self = Self(VarInt::from_u32(0x00));
    pub const WT_CLOSE_SESSION: Self = Self(VarInt::from_u32(0x2843));
    pub const WT_DRAIN_SESSION: Self = Self(VarInt::from_u32(0x78ae));
    pub const WT_MAX_STREAMS_BIDI: Self = Self(VarInt::from_u32(0x190b4d3f));
    pub const WT_MAX_STREAMS_UNI: Self = Self(VarInt::from_u32(0x190b4d40));
    pub const WT_STREAMS_BLOCKED_BIDI: Self = Self(VarInt::from_u32(0x190b4d43));
    pub const WT_STREAMS_BLOCKED_UNI: Self = Self(VarInt::from_u32(0x190b4d44));

    pub const fn into_inner(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for CapsuleType {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<CapsuleType> for VarInt {
    fn from(value: CapsuleType) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Capsule<P: ?Sized> {
    r#type: CapsuleType,
    length: VarInt,
    payload: P,
}

impl<P: ?Sized> Capsule<P> {
    pub fn new(r#type: CapsuleType, payload: P) -> Result<Self, varint::err::Overflow>
    where
        P: Buf + Sized,
    {
        let length = VarInt::try_from(payload.remaining())?;
        Ok(Self {
            r#type,
            length,
            payload,
        })
    }

    pub const fn r#type(&self) -> CapsuleType {
        self.r#type
    }

    pub const fn length(&self) -> VarInt {
        self.length
    }

    pub const fn payload(&self) -> &P {
        &self.payload
    }

    pub fn into_payload(self) -> P
    where
        P: Sized,
    {
        self.payload
    }

    pub fn map<U>(self, map: impl FnOnce(P) -> U) -> Capsule<U>
    where
        P: Sized,
    {
        Capsule {
            r#type: self.r#type,
            length: self.length,
            payload: map(self.payload),
        }
    }
}

impl<'s, P, S> EncodeInto<&'s mut S> for Capsule<P>
where
    P: Buf + Send,
    S: AsyncWrite + Unpin + Send,
{
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: &'s mut S) -> Result<Self::Output, Self::Error> {
        let Capsule {
            r#type,
            length,
            mut payload,
        } = self;
        stream.encode_one(r#type.into_inner()).await?;
        stream.encode_one(length).await?;
        while payload.has_remaining() {
            let chunk = payload.chunk();
            stream.write_all(chunk).await?;
            let len = chunk.len();
            payload.advance(len);
        }
        Ok(())
    }
}

impl<P> EncodeInto<BufList> for Capsule<P>
where
    P: Buf + Send,
{
    type Output = BufList;
    type Error = Infallible;

    async fn encode_into(self, mut stream: BufList) -> Result<Self::Output, Self::Error> {
        stream
            .encode_one(self)
            .await
            .expect("encoding a capsule into a BufList is infallible");
        Ok(stream)
    }
}

impl<S> DecodeFrom<S> for Capsule<BufList>
where
    S: AsyncRead + Unpin + Send,
{
    type Error = io::Error;

    async fn decode_from(mut stream: S) -> Result<Self, Self::Error> {
        let r#type = CapsuleType::from(stream.decode_one::<VarInt>().await?);
        let length = stream.decode_one::<VarInt>().await?;
        let mut remaining = length.into_inner();
        let mut payload = BufList::new();
        while remaining > 0 {
            let len = remaining.min(READ_CHUNK_SIZE) as usize;
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            payload.write(Bytes::from(bytes));
            remaining -= len as u64;
        }
        Ok(Self {
            r#type,
            length,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};
    use futures::{Stream, stream};

    use super::*;
    use crate::{
        buflist::BufList,
        codec::{DecodeExt, EncodeExt, StreamReader},
        quic,
        varint::VarInt,
    };

    #[test]
    fn capsule_type_constants_use_draft_codepoints() {
        assert_eq!(CapsuleType::DATAGRAM.into_inner(), VarInt::from_u32(0x00));
        assert_eq!(
            CapsuleType::WT_CLOSE_SESSION.into_inner(),
            VarInt::from_u32(0x2843)
        );
        assert_eq!(
            CapsuleType::WT_DRAIN_SESSION.into_inner(),
            VarInt::from_u32(0x78ae)
        );
        assert_eq!(
            CapsuleType::WT_MAX_STREAMS_BIDI.into_inner(),
            VarInt::from_u32(0x190b4d3f)
        );
        assert_eq!(
            CapsuleType::WT_MAX_STREAMS_UNI.into_inner(),
            VarInt::from_u32(0x190b4d40)
        );
        assert_eq!(
            CapsuleType::WT_STREAMS_BLOCKED_BIDI.into_inner(),
            VarInt::from_u32(0x190b4d43)
        );
        assert_eq!(
            CapsuleType::WT_STREAMS_BLOCKED_UNI.into_inner(),
            VarInt::from_u32(0x190b4d44)
        );
    }

    #[tokio::test]
    async fn capsule_encode_decode_round_trips_unknown_types() {
        fn byte_stream(
            data: impl IntoIterator<Item = u8>,
        ) -> impl Stream<Item = Result<Bytes, quic::StreamError>> {
            stream::iter(data.into_iter().map(|byte| Ok(Bytes::from(vec![byte]))))
        }

        let mut payload = BufList::new();
        payload.write(Bytes::from_static(b"hello"));
        let mut encoded = BufList::new()
            .encode(
                Capsule::new(CapsuleType::from(VarInt::from_u32(0x2f)), payload).expect("capsule"),
            )
            .await
            .expect("encode");
        let bytes = encoded.copy_to_bytes(encoded.remaining());
        let mut reader = StreamReader::new(byte_stream(bytes));

        let decoded = reader
            .decode_one::<Capsule<BufList>>()
            .await
            .expect("decode");

        assert_eq!(decoded.r#type(), CapsuleType::from(VarInt::from_u32(0x2f)));
        assert_eq!(decoded.length(), VarInt::from_u32(5));
        let mut payload = decoded.into_payload();
        assert_eq!(payload.copy_to_bytes(5), Bytes::from_static(b"hello"));
    }
}
