use bytes::{BufMut, Bytes};

use super::{FrameHeader, FrameType, ParseResult, WriteFrame};
use crate::Error;

/// DATA envelope only. The stream reader delivers the payload in bounded chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DataFrame {
    pub(crate) length: u64,
}

pub(super) fn be_data_frame(input: &Bytes, length: u64) -> ParseResult<'_, DataFrame> {
    Ok((input, DataFrame { length }))
}

/// Write only the envelope; the sender feeds the payload separately.
impl<B: BufMut> WriteFrame<DataFrame> for B {
    fn put_frame(&mut self, frame: &DataFrame) -> Result<(), Error> {
        self.put_frame(&FrameHeader {
            frame_type: FrameType::Data,
            length: frame.length,
        })
    }
}
