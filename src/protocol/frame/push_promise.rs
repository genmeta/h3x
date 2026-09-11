use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, check_payload_length,
    read_payload, varint::be_varint,
};
use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushPromise {
    pub(crate) push_id: VarInt,
    pub(crate) field_section: Bytes,
}

pub(crate) async fn be_push_promise_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<PushPromise>> {
    check_payload_length(length.into_u64())?;
    let mut payload = reader.take(length.into_u64());
    let id = be_varint(&mut payload).await?;
    let remaining = payload.limit();
    let fields = read_payload(&mut payload, remaining).await?;
    Ok(Frame {
        length,
        payload: PushPromise {
            push_id: id,
            field_section: fields,
        },
    })
}

impl GetFrameType for PushPromise {
    fn frame_type(&self) -> FrameType {
        FrameType::PushPromise
    }
}

impl EncodeSize for PushPromise {
    fn encoding_size(&self) -> usize {
        self.push_id.encoding_size() + self.field_section.len()
    }
}

impl<B: BufMut> Write<Frame<PushPromise>> for B {
    fn put_frame(&mut self, frame: &Frame<PushPromise>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        self.put_varint(&frame.payload.push_id);
        self.put_slice(&frame.payload.field_section);
    }
}
