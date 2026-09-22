use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, varint::be_varint};
use crate::ErrorCode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaxPushId {
    pub(crate) push_id: VarInt,
}

pub(crate) async fn be_max_push_id_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> std::io::Result<Frame<MaxPushId>> {
    if length.into_u64() > VarInt::MAX_SIZE as u64 {
        return Err(ErrorCode::FrameError
            .connection("MAX_PUSH_ID payload exceeds the maximum identifier size")
            .into());
    }
    let mut payload = reader.take(length.into_u64());
    let id = be_varint(&mut payload).await?.ok_or_else(|| {
        std::io::Error::other(
            ErrorCode::FrameError
                .connection("MAX_PUSH_ID payload is missing a complete identifier"),
        )
    })?;
    if payload.limit() != 0 {
        return Err(ErrorCode::FrameError
            .connection("MAX_PUSH_ID payload has trailing bytes")
            .into());
    }
    Ok(Frame {
        length,
        payload: MaxPushId { push_id: id },
    })
}

impl GetFrameType for MaxPushId {
    fn frame_type(&self) -> FrameType {
        FrameType::MaxPushId
    }
}

impl EncodeSize for MaxPushId {
    fn encoding_size(&self) -> usize {
        self.push_id.encoding_size()
    }
}

impl<B: BufMut> Write<Frame<MaxPushId>> for B {
    fn put_frame(&mut self, frame: &Frame<MaxPushId>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        self.put_varint(&frame.payload.push_id);
    }
}
