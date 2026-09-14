use bytes::{BufMut, Bytes};
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::AsyncRead;

use super::{EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, read_payload};
use crate::{
    Result,
    protocol::qpack::{Field, Qpack},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Headers {
    pub(crate) field_section: Bytes,
}

impl Frame<Headers> {
    /// Encode once using this stream's shared QPACK, then calculate the wire length.
    pub(crate) fn encode(fields: Vec<Field>, qpack: &Qpack, stream_id: u64) -> Result<Self> {
        Self::new(Headers {
            field_section: qpack.encode(stream_id, fields)?,
        })
    }

    /// Decode after validating frame placement; missing dynamic entries suspend this future.
    pub(crate) async fn decode(self, qpack: &Qpack, stream_id: u64) -> Result<Vec<Field>> {
        qpack.decode(stream_id, self.payload.field_section).await
    }
}

pub(crate) async fn be_headers_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<Headers>> {
    let payload = read_payload(reader, length.into_u64()).await?;
    Ok(Frame {
        length,
        payload: Headers {
            field_section: payload,
        },
    })
}

impl GetFrameType for Headers {
    fn frame_type(&self) -> FrameType {
        FrameType::Headers
    }
}

impl EncodeSize for Headers {
    fn encoding_size(&self) -> usize {
        self.field_section.len()
    }
}

impl<B: BufMut> Write<Frame<Headers>> for B {
    fn put_frame(&mut self, frame: &Frame<Headers>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        self.put_slice(&frame.payload.field_section);
    }
}
