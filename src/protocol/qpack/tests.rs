use super::*;

#[test]
fn limits_use_protocol_defaults_and_explicit_settings() {
    assert_eq!(
        limits(&frame::Settings::default()),
        (Settings::default(), VARINT_MAX)
    );
    let settings = crate::Settings::new(1024, 128, 3).unwrap();
    assert_eq!(
        limits(&settings.local),
        (
            Settings {
                max_table_capacity: 128,
                blocked_streams: 3
            },
            1024
        )
    );
    let settings = crate::Settings::new(0, 0, 0).unwrap();
    assert_eq!(limits(&settings.local), (Settings::default(), 0));
}

#[tokio::test]
async fn close_preserves_first_error_across_both_directions() {
    let connection = crate::test_support::connection();
    let qpack = connection.qpack();
    assert_eq!(
        qpack.close(ErrorCode::H3_INTERNAL_ERROR),
        ErrorCode::H3_INTERNAL_ERROR
    );
    assert_eq!(
        qpack.close(ErrorCode::H3_EXCESSIVE_LOAD),
        ErrorCode::H3_INTERNAL_ERROR
    );
    assert_eq!(
        qpack.encode(0, Vec::new()),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(
        qpack.decode(0, Bytes::from_static(&[0, 0])).await,
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(qpack.cancel(0), Err(ErrorCode::H3_INTERNAL_ERROR));
    assert_eq!(
        qpack.configure(Settings::default(), VARINT_MAX),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
}

#[tokio::test]
async fn request_errors_leave_qpack_usable() {
    let connection = crate::test_support::connection();
    let qpack = connection.qpack();
    for error in [
        ErrorCode::H3_REQUEST_CANCELLED,
        ErrorCode::H3_REQUEST_REJECTED,
        ErrorCode::H3_REQUEST_INCOMPLETE,
        ErrorCode::H3_MESSAGE_ERROR,
    ] {
        connection.receive_error(error).await;
        assert_eq!(qpack.error(), None);
        let payload = qpack
            .encode(
                0,
                vec![Field {
                    name: Bytes::from_static(b":method"),
                    value: Bytes::from_static(b"GET"),
                    never_index: false,
                }],
            )
            .unwrap();
        let fields = qpack.decode(0, payload).await.unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, ":method");
        assert_eq!(fields[0].value, "GET");
    }
}

#[tokio::test]
async fn malformed_field_section_closes_both_directions() {
    let connection = crate::test_support::connection();
    let qpack = connection.qpack();
    let result = crate::server::read_request(
        crate::H3ReadStream::new(0, &b"\x01\x01\x00"[..]),
        connection.clone(),
    )
    .await;
    assert!(matches!(result, Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)));
    assert_eq!(qpack.error(), Some(ErrorCode::QPACK_DECOMPRESSION_FAILED));
    assert_eq!(
        qpack.encode(4, Vec::new()),
        Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        qpack.decode(4, Bytes::from_static(&[0, 0])).await,
        Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );
}

#[test]
fn construction_does_not_require_a_runtime() {
    let qpack = Qpack::new(&crate::Settings::default()).unwrap();
    assert!(qpack.encode(0, Vec::new()).is_ok());
}
