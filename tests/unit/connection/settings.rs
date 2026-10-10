use qbase::varint::VARINT_MAX;

use super::*;

#[test]
fn settings_validate_each_wire_value_and_default() {
    let settings = Settings::new(1, 2, 3).unwrap();
    assert_eq!(settings.0.get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, 0), 1);
    assert_eq!(
        settings.0.get(frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0),
        2
    );
    assert_eq!(settings.0.get(frame::SETTINGS_QPACK_BLOCKED_STREAMS, 0), 3);
    assert_eq!(
        settings.0.get(frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0),
        1
    );
    assert!(Settings::default().0.values.len() == 4);
    for values in [
        (VARINT_MAX + 1, 0, 0),
        (0, VARINT_MAX + 1, 0),
        (0, 0, VARINT_MAX + 1),
    ] {
        assert_eq!(
            Settings::new(values.0, values.1, values.2)
                .unwrap_err()
                .code,
            ErrorCode::SettingsError
        );
    }
}

#[test]
fn settings_get_distinguishes_zero_missing_and_extension_values() {
    let settings = Settings::new(0, 0, 0).unwrap();
    assert_eq!(
        settings.get(crate::SETTINGS_MAX_FIELD_SECTION_SIZE),
        Some(0)
    );
    assert_eq!(
        settings.get(crate::SETTINGS_QPACK_MAX_TABLE_CAPACITY),
        Some(0)
    );
    assert_eq!(settings.get(crate::SETTINGS_QPACK_BLOCKED_STREAMS), Some(0));
    assert_eq!(
        settings.get(crate::SETTINGS_ENABLE_CONNECT_PROTOCOL),
        Some(1)
    );
    let mut absent = Settings(frame::Settings::default());
    assert_eq!(absent.get(crate::SETTINGS_ENABLE_CONNECT_PROTOCOL), None);
    let extension_id = (1u64 << 40) + 0x21;
    absent.0.values.insert(
        VarInt::try_from(extension_id).unwrap(),
        VarInt::try_from(VARINT_MAX).unwrap(),
    );
    assert_eq!(absent.get(extension_id), Some(VARINT_MAX));
    assert_eq!(absent.get(0x21), None);
    assert_eq!(absent.get(VARINT_MAX + 1), None);
    assert_eq!(absent.get(u64::MAX), None);
}
