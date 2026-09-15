use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, varint::be_varint};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Goaway {
    pub id: VarInt,
}

pub(crate) async fn be_goaway_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<Goaway>> {
    if length.into_u64() > VarInt::MAX_SIZE as u64 {
        return Err(Error::H3_FRAME_ERROR);
    }
    let mut payload = reader.take(length.into_u64());
    let id = be_varint(&mut payload)
        .await?
        .ok_or(Error::H3_FRAME_ERROR)?;
    if payload.limit() != 0 {
        return Err(Error::H3_FRAME_ERROR);
    }
    Ok(Frame {
        length,
        payload: Goaway { id },
    })
}

impl GetFrameType for Goaway {
    fn frame_type(&self) -> FrameType {
        FrameType::Goaway
    }
}

impl EncodeSize for Goaway {
    fn encoding_size(&self) -> usize {
        self.id.encoding_size()
    }
}

impl<B: BufMut> Write<Frame<Goaway>> for B {
    fn put_frame(&mut self, frame: &Frame<Goaway>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        self.put_varint(&frame.payload.id);
    }
}
