use super::*;
#[test]
fn default_settings_frame_is_wire_compatible_and_empty() {
    let mut frame = Vec::new();
    frame
        .put_frame(&SettingsFrame {
            settings: Settings::default(),
        })
        .unwrap();

    assert_eq!(frame, [4, 0]);
}

#[test]
fn typed_settings_round_trip_through_the_wire_format() {
    let mut expected = Settings::default();
    expected.set_qpack_max_table_capacity(4096);
    expected.set_max_field_section_size(Some(32 * 1024));
    expected.set_qpack_blocked_streams(12);
    expected.set_enable_connect_protocol(true);
    #[cfg(feature = "webtransport")]
    expected.enable_webtransport();

    let mut frame = Vec::new();
    frame
        .put_frame(&SettingsFrame {
            settings: expected.clone(),
        })
        .unwrap();
    let frame = Bytes::from(frame);
    let (consumed, super::super::Frame::Settings(actual)) =
        super::super::be_complete_frame(&frame).unwrap()
    else {
        panic!("expected SETTINGS")
    };
    let actual = actual.settings;
    assert_eq!(consumed, frame.len());
    assert_eq!(actual, expected);
}

#[test]
fn duplicate_settings_are_rejected() {
    let payload = [
        QPACK_BLOCKED_STREAMS as u8,
        0,
        QPACK_BLOCKED_STREAMS as u8,
        1,
    ];
    let error =
        be_settings_frame(&Bytes::copy_from_slice(&payload)).expect_err("duplicate is invalid");

    let error = match error {
        nom::Err::Error(error) | nom::Err::Failure(error) => error,
        _ => panic!("expected SETTINGS error"),
    };
    assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
}

#[test]
fn unknown_settings_are_ignored() {
    let payload = [0x21, 42];
    let settings = be_settings_frame(&Bytes::copy_from_slice(&payload))
        .map(|(_, frame)| frame)
        .expect("unknown setting is ignored");

    assert_eq!(settings.settings, Settings::default());
}

#[test]
fn invalid_boolean_and_http2_identifiers_are_rejected() {
    for payload in [[ENABLE_CONNECT_PROTOCOL as u8, 2], [0x02, 0]] {
        let error =
            be_settings_frame(&Bytes::copy_from_slice(&payload)).expect_err("invalid settings");
        let error = match error {
            nom::Err::Error(error) | nom::Err::Failure(error) => error,
            _ => panic!("expected SETTINGS error"),
        };
        assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
    }
}

#[cfg(feature = "webtransport")]
#[test]
fn webtransport_settings_use_the_draft_16_codepoints() {
    let mut expected = Settings::default();
    expected.enable_webtransport();

    let mut frame = Vec::new();
    frame
        .put_frame(&SettingsFrame {
            settings: expected.clone(),
        })
        .unwrap();
    let frame = Bytes::from(frame);
    let (_, super::super::Frame::Settings(actual)) =
        super::super::be_complete_frame(&frame).unwrap()
    else {
        panic!("expected SETTINGS")
    };
    let actual = actual.settings;

    assert!(actual.enable_connect_protocol());
    assert!(actual.h3_datagram());
    assert!(actual.webtransport());
}

#[cfg(feature = "webtransport")]
#[test]
fn invalid_webtransport_boolean_settings_are_rejected() {
    for identifier in [H3_DATAGRAM, WEBTRANSPORT] {
        let mut payload = Vec::new();
        payload.put_varint(&VarInt::try_from(identifier).unwrap());
        payload.put_varint(&VarInt::from_u32(2));

        let error = be_settings_frame(&Bytes::copy_from_slice(&payload))
            .expect_err("invalid boolean setting");
        let error = match error {
            nom::Err::Error(error) | nom::Err::Failure(error) => error,
            _ => panic!("expected SETTINGS error"),
        };
        assert_eq!(error.code(), Some(Code::H3_SETTINGS_ERROR));
    }
}
