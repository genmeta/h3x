use qbase::varint::VarInt;
use tokio::io::AsyncRead;

use crate::{Error, Result, protocol::frame::be_varint};

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UniStream {
    Control = 0x00,
    Push = 0x01,
    QpackEncoder = 0x02,
    QpackDecoder = 0x03,
}

impl TryFrom<VarInt> for UniStream {
    type Error = Error;

    fn try_from(value: VarInt) -> Result<Self> {
        match value.into_u64() {
            0x00 => Ok(Self::Control),
            0x01 => Ok(Self::Push),
            0x02 => Ok(Self::QpackEncoder),
            0x03 => Ok(Self::QpackDecoder),
            _ => Err(Error::H3_STREAM_CREATION_ERROR),
        }
    }
}

impl From<UniStream> for VarInt {
    fn from(value: UniStream) -> Self {
        Self::from_u32(value as u32)
    }
}

#[allow(dead_code, reason = "uni stream dispatch is not wired up yet")]
pub(crate) async fn be_uni_stream<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
) -> Result<UniStream> {
    be_varint(reader).await?.try_into()
}

#[cfg(test)]
mod tests {
    use qbase::varint::WriteVarInt;

    use super::*;

    #[tokio::test]
    async fn stream_types_round_trip_and_reject_unknown() {
        for expected in [
            UniStream::Control,
            UniStream::Push,
            UniStream::QpackEncoder,
            UniStream::QpackDecoder,
        ] {
            let mut encoded = Vec::new();
            encoded.put_varint(&expected.into());
            assert_eq!(
                be_uni_stream(&mut encoded.as_slice()).await.unwrap(),
                expected
            );
        }
        assert_eq!(
            be_uni_stream(&mut &[0x04][..]).await.unwrap_err(),
            Error::H3_STREAM_CREATION_ERROR
        );
    }
}
