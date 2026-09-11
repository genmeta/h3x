use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    EncodeSize, Frame, FrameType, GetFrameType, Write, WriteFrameType, check_payload_length,
    varint::be_varint,
};
use crate::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) values: Vec<(VarInt, VarInt)>,
}

pub(crate) async fn be_setting_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<Settings>> {
    check_payload_length(length.into_u64())?;
    let mut payload = reader.take(length.into_u64());
    let mut values = Vec::new();
    while payload.limit() != 0 {
        let id = be_varint(&mut payload).await?;
        let value = be_varint(&mut payload).await?;
        if id.into_u64() == 0x08 && value.into_u64() > 1 {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        if values.iter().any(|(existing, _)| *existing == id) {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        values.push((id, value));
    }
    Ok(Frame {
        length,
        payload: Settings { values },
    })
}

impl GetFrameType for Settings {
    fn frame_type(&self) -> FrameType {
        FrameType::Settings
    }
}

impl EncodeSize for Settings {
    fn encoding_size(&self) -> usize {
        self.values
            .iter()
            .map(|(id, value)| id.encoding_size() + value.encoding_size())
            .sum()
    }
}

impl<B: BufMut> Write<Frame<Settings>> for B {
    fn put_frame(&mut self, frame: &Frame<Settings>) {
        self.put_frame_type(&frame.frame_type());
        self.put_varint(&frame.length);
        for (id, value) in &frame.payload.values {
            self.put_varint(id);
            self.put_varint(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Write, *};

    #[tokio::test]
    async fn settings_round_trip_and_reject_duplicates() {
        let frame = Frame::<Settings>::new(Settings {
            values: vec![(VarInt::from_u32(1), VarInt::from_u32(64))],
        })
        .unwrap();
        let mut encoded = Vec::new();
        encoded.put_frame(&frame);
        let mut input = &encoded[2..];
        assert_eq!(
            be_setting_frame(&mut input, frame.length).await.unwrap(),
            frame
        );
        assert!(
            be_setting_frame(&mut &[1, 0, 1, 1][..], VarInt::from_u32(4))
                .await
                .is_err()
        );
    }
}
