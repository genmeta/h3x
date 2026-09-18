//! Local connection settings.

use qbase::varint::VarInt;

use crate::{ErrorCode, Result, frame};

/// Local settings advertised when constructing an HTTP/3 connection.
/// Extended CONNECT support is always advertised.
#[derive(Clone, Debug)]
pub struct Settings(pub(crate) frame::Settings);

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        let values = [
            (frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
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
                VarInt::try_from(value).map_err(|error| {
                    ErrorCode::H3_SETTINGS_ERROR.reason(format!(
                        "SETTINGS value exceeds the QUIC variable-integer range: {error}"
                    ))
                })?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self(frame::Settings { values }))
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(64 * 1024, 4096, 16).unwrap()
    }
}
