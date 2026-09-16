use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    EncodeSize, Frame, FrameType, GetFrameType, MAX_BUFFERED_FRAME_PAYLOAD, Write, WriteFrameType,
    read_payload, varint::be_varint,
};
use crate::{ErrorCode, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PushPromise {
    pub(crate) push_id: VarInt,
    pub(crate) field_section: Bytes,
}

pub(crate) async fn be_push_promise_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<PushPromise>> {
    if length.into_u64() > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD.with_reason("configured resource limit exceeded"));
    }
    let mut payload = reader.take(length.into_u64());
    let id = be_varint(&mut payload)
        .await
        .map_err(|error| {
            let error = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
                .map_or(&error, std::sync::Arc::as_ref);
            error
                .get_ref()
                .and_then(|error| error.downcast_ref::<crate::Error>())
                .cloned()
                .unwrap_or_else(|| {
                    let code = if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        ErrorCode::H3_FRAME_ERROR
                    } else {
                        ErrorCode::H3_INTERNAL_ERROR
                    };
                    code.with_reason(error.to_string())
                })
        })?
        .ok_or_else(|| {
            ErrorCode::H3_FRAME_ERROR
                .with_reason("PUSH_PROMISE payload is missing a complete push ID")
        })?;
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
