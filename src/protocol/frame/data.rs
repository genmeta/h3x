use bytes::BufMut;
use qbase::varint::WriteVarInt;

use super::{EncodeSize, Frame, FrameType, GetFrameType, Write};

/// Declared DATA payload length; the bytes are streamed separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Data(pub(crate) usize);

impl GetFrameType for Data {
    fn frame_type(&self) -> FrameType {
        FrameType::Data
    }
}

impl EncodeSize for Data {
    fn encoding_size(&self) -> usize {
        self.0
    }
}

impl<B: BufMut> Write<Frame<Data>> for B {
    fn put_frame(&mut self, frame: &Frame<Data>) {
        // DATA bytes are fed separately by the caller.
        self.put_varint(&frame.frame_type().into());
        self.put_varint(&frame.length);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{EncodeSize, Frame},
        *,
    };

    #[test]
    fn data_length_is_carried_into_the_frame() {
        for length in [0, 63, 64, 16384] {
            let data = Data(length);
            assert_eq!(data.encoding_size(), length);
            assert_eq!(
                Frame::<Data>::new(data).unwrap().length.into_u64(),
                length as u64
            );
        }
        assert!(Frame::<Data>::new(Data(usize::MAX)).is_err());
    }
}
