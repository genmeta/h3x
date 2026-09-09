use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame, frame_error};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CancelPushFrame {
    pub(crate) push_id: VarInt,
}

pub(super) fn be_cancel_push_frame(input: &Bytes) -> ParseResult<'_, CancelPushFrame> {
    let (remaining, id) = be_varint(input)
        .map_err(|error| error.map(|_| frame_error("invalid frame payload integer")))?;
    Ok((remaining, CancelPushFrame { push_id: id }))
}

impl<B: BufMut> WriteFrame<CancelPushFrame> for B {
    fn put_frame(&mut self, frame: &CancelPushFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::CancelPush,
            length: frame.push_id.encoding_size() as u64,
        })?;
        self.put_varint(&frame.push_id);
        Ok(())
    }
}
