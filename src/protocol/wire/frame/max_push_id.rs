use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame, frame_error};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaxPushIdFrame {
    pub(crate) push_id: VarInt,
}

pub(super) fn be_max_push_id_frame(input: &Bytes) -> ParseResult<'_, MaxPushIdFrame> {
    let (remaining, id) = be_varint(input)
        .map_err(|error| error.map(|_| frame_error("invalid frame payload integer")))?;
    Ok((remaining, MaxPushIdFrame { push_id: id }))
}

impl<B: BufMut> WriteFrame<MaxPushIdFrame> for B {
    fn put_frame(&mut self, frame: &MaxPushIdFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::MaxPushId,
            length: frame.push_id.encoding_size() as u64,
        })?;
        self.put_varint(&frame.push_id);
        Ok(())
    }
}
