//! Local advertised settings and peer settings storage.

use std::sync::Mutex;

use qbase::varint::VarInt;

use crate::{Error, Result, protocol::frame};

/// Local advertised settings and the independently received peer settings.
pub struct Settings {
    pub(crate) local: frame::Settings,
    pub(crate) peer: Mutex<Option<frame::Settings>>,
}

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        if max_field_section_size > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
            || max_table_capacity > frame::MAX_BUFFERED_FRAME_PAYLOAD as u64
        {
            return Err(Error::H3_SETTINGS_ERROR);
        }
        let values = [
            (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, max_table_capacity),
            (
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                max_field_section_size,
            ),
            (frame::SETTINGS_QPACK_BLOCKED_STREAMS, blocked_streams),
        ]
        .into_iter()
        .map(|(id, value)| {
            Ok((
                VarInt::from_u32(id),
                VarInt::try_from(value).map_err(|_| Error::H3_SETTINGS_ERROR)?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self {
            local: frame::Settings { values },
            peer: Mutex::new(None),
        })
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(65536, 4096, 16).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use qbase::varint::VARINT_MAX;

    use super::*;

    #[test]
    fn settings_accept_limits_and_reject_unrepresentable_values() {
        let max = frame::MAX_BUFFERED_FRAME_PAYLOAD as u64;
        for (fields, capacity, blocked) in [(0, 0, 0), (max, max, VARINT_MAX)] {
            let settings = Settings::new(fields, capacity, blocked).unwrap();
            assert_eq!(
                settings
                    .local
                    .get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 1),
                fields
            );
            assert_eq!(
                settings
                    .local
                    .get(frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1),
                capacity
            );
            assert_eq!(
                settings.local.get(frame::SETTINGS_QPACK_BLOCKED_STREAMS, 1),
                blocked
            );
            assert!(settings.peer.lock().unwrap().is_none());
        }
        for (fields, capacity, blocked) in
            [(max + 1, 0, 0), (0, max + 1, 0), (0, 0, VARINT_MAX + 1)]
        {
            assert!(matches!(
                Settings::new(fields, capacity, blocked),
                Err(Error::H3_SETTINGS_ERROR)
            ));
        }
    }
}
