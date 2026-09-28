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
