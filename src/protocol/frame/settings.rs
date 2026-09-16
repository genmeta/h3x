use std::collections::{HashMap, hash_map::Entry};

use bytes::BufMut;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::{
    EncodeSize, Frame, FrameType, GetFrameType, MAX_BUFFERED_FRAME_PAYLOAD, Write, WriteFrameType,
    varint::be_varint,
};
use crate::{ErrorCode, Result};

pub(crate) const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u32 = 0x01;
pub(crate) const SETTINGS_MAX_FIELD_SECTION_SIZE: u32 = 0x06;
pub(crate) const SETTINGS_QPACK_BLOCKED_STREAMS: u32 = 0x07;
pub(crate) const SETTINGS_ENABLE_CONNECT_PROTOCOL: u32 = 0x08;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) values: HashMap<VarInt, VarInt>,
}

impl Settings {
    pub(crate) fn get(&self, id: u32, default: u64) -> u64 {
        self.values
            .get(&VarInt::from_u32(id))
            .map_or(default, |value| value.into_u64())
    }
}

pub(crate) async fn be_setting_frame<T: AsyncRead + Unpin + ?Sized>(
    reader: &mut T,
    length: VarInt,
) -> Result<Frame<Settings>> {
    if length.into_u64() > MAX_BUFFERED_FRAME_PAYLOAD as u64 {
        return Err(ErrorCode::H3_EXCESSIVE_LOAD.with_reason("configured resource limit exceeded"));
    }
    let mut payload = reader.take(length.into_u64());
    let mut values = HashMap::new();
    while payload.limit() != 0 {
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
                ErrorCode::H3_FRAME_ERROR.with_reason("SETTINGS payload is missing an identifier")
            })?;
        let value = be_varint(&mut payload)
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
                ErrorCode::H3_FRAME_ERROR.with_reason("SETTINGS identifier has no value")
            })?;
        if matches!(id.into_u64(), 0x02..=0x05) || (id.into_u64() == 0x08 && value.into_u64() > 1) {
            return Err(ErrorCode::H3_SETTINGS_ERROR.with_reason(
                "reserved SETTINGS identifier or invalid ENABLE_CONNECT_PROTOCOL value",
            ));
        }
        match values.entry(id) {
            Entry::Vacant(entry) => {
                entry.insert(value);
            }
            Entry::Occupied(_) => {
                return Err(
                    ErrorCode::H3_SETTINGS_ERROR.with_reason("duplicate SETTINGS identifier")
                );
            }
        }
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
            values: HashMap::from([
                (
                    VarInt::from_u32(SETTINGS_QPACK_MAX_TABLE_CAPACITY),
                    VarInt::from_u32(64),
                ),
                (
                    VarInt::from_u32(SETTINGS_QPACK_BLOCKED_STREAMS),
                    VarInt::from_u32(16),
                ),
            ]),
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
        for id in 2..=5 {
            assert_eq!(
                (be_setting_frame(&mut &[id, 0][..], VarInt::from_u32(2)).await)
                    .map_err(ErrorCode::from),
                Err(ErrorCode::H3_SETTINGS_ERROR)
            );
        }
    }
}
