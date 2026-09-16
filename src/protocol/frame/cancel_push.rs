use bytes::BufMut;
use qbase::{
    sid::StreamId,
    varint::{VarInt, WriteVarInt},
};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, varint::be_varint};
use crate::{ErrorCode, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CancelPush {
    pub(crate) push_id: StreamId,
}

/// Read the payload after Type and Length have already been consumed.
impl Frame<CancelPush> {
    pub(crate) async fn be_frame<T: AsyncRead + Unpin + ?Sized>(
        reader: &mut T,
        length: VarInt,
    ) -> Result<Self> {
        if length.into_u64() > VarInt::MAX_SIZE as u64 {
            return Err(ErrorCode::H3_FRAME_ERROR);
        }
        let mut payload = reader.take(length.into_u64());
        let id = be_varint(&mut payload)
            .await?
            .ok_or(ErrorCode::H3_FRAME_ERROR)?;
        if payload.limit() != 0 {
            return Err(ErrorCode::H3_FRAME_ERROR);
        }
        Ok(Self {
            length,
            payload: CancelPush { push_id: id.into() },
        })
    }
}

impl GetFrameType for CancelPush {
    fn frame_type(&self) -> FrameType {
        FrameType::CancelPush
    }
}

impl EncodeSize for CancelPush {
    fn encoding_size(&self) -> usize {
        self.push_id.encoding_size()
    }
}

impl<B: BufMut> Write<Frame<CancelPush>> for B {
    fn put_frame(&mut self, frame: &Frame<CancelPush>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        self.put_varint(&VarInt::from(frame.payload.push_id));
    }
}
