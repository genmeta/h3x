use bytes::{BufMut, Bytes};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame};
use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeadersFrame {
    pub(crate) field_section: Bytes,
}

pub(super) fn be_headers_frame(field_section: &Bytes) -> ParseResult<'_, HeadersFrame> {
    Ok((
        &[],
        HeadersFrame {
            field_section: field_section.clone(),
        },
    ))
}

impl<B: BufMut> WriteFrame<HeadersFrame> for B {
    fn put_frame(&mut self, frame: &HeadersFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::Headers,
            length: frame.field_section.len() as u64,
        })?;
        self.put_slice(&frame.field_section);
        Ok(())
    }
}
