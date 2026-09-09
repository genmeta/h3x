use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame, frame_error};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GoawayFrame {
    pub(crate) id: VarInt,
}

pub(super) fn be_goaway_frame(input: &Bytes) -> ParseResult<'_, GoawayFrame> {
    let (remaining, id) = be_varint(input)
        .map_err(|error| error.map(|_| frame_error("invalid frame payload integer")))?;
    Ok((remaining, GoawayFrame { id }))
}

impl<B: BufMut> WriteFrame<GoawayFrame> for B {
    fn put_frame(&mut self, frame: &GoawayFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::Goaway,
            length: frame.id.encoding_size() as u64,
        })?;
        self.put_varint(&frame.id);
        Ok(())
    }
}
