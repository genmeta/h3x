//! Local connection settings.

use qbase::varint::VarInt;

use crate::{ErrorCode, Result, protocol::frame};

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

#[cfg(test)]
mod tests {
    use qbase::varint::VARINT_MAX;

    use super::*;

    #[test]
    fn settings_accept_limits_and_reject_unrepresentable_values() {
        let max_fields = VARINT_MAX;
        let max_capacity = VARINT_MAX;
        for (fields, capacity, blocked) in [(0, 0, 0), (max_fields, max_capacity, VARINT_MAX)] {
            let settings = Settings::new(fields, capacity, blocked).unwrap();
            assert_eq!(
                settings.0.get(frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
                1
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 1),
                fields
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1),
                capacity
            );
            assert_eq!(
                settings.0.get(frame::SETTINGS_QPACK_BLOCKED_STREAMS, 1),
                blocked
            );
        }
        for (fields, capacity, blocked) in [
            (max_fields + 1, 0, 0),
            (0, max_capacity + 1, 0),
            (0, 0, VARINT_MAX + 1),
        ] {
            assert!(matches!(
                Settings::new(fields, capacity, blocked),
                Err(h3x::Error {
                    code: ErrorCode::H3_SETTINGS_ERROR,
                    ..
                })
            ));
        }
    }
}
