use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt, be_varint};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame, frame_error};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushPromiseFrame {
    pub(crate) push_id: VarInt,
    pub(crate) field_section: Bytes,
}

pub(super) fn be_push_promise_frame(payload: &Bytes) -> ParseResult<'_, PushPromiseFrame> {
    let (remaining, id) =
        be_varint(payload).map_err(|error| error.map(|_| frame_error("invalid push ID")))?;
    Ok((
        &[],
        PushPromiseFrame {
            push_id: id,
            field_section: payload.slice(payload.len() - remaining.len()..),
        },
    ))
}

impl<B: BufMut> WriteFrame<PushPromiseFrame> for B {
    fn put_frame(&mut self, frame: &PushPromiseFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::PushPromise,
            length: (frame.push_id.encoding_size() + frame.field_section.len()) as u64,
        })?;
        self.put_varint(&frame.push_id);
        self.put_slice(&frame.field_section);
        Ok(())
    }
}
