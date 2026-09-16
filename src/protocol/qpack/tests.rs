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
    let connection = crate::test_support::connection().await;
    let qpack = connection.qpack();
    assert_eq!(
        ErrorCode::from(
            qpack.close(
                ErrorCode::H3_INTERNAL_ERROR.with_reason("test terminates compression state")
            )
        ),
        ErrorCode::H3_INTERNAL_ERROR
    );
    assert_eq!(
        ErrorCode::from(
            qpack.close(
                ErrorCode::H3_EXCESSIVE_LOAD.with_reason("test terminates compression state")
            )
        ),
        ErrorCode::H3_INTERNAL_ERROR
    );
    assert_eq!(
        (qpack.encode(0, Vec::new())).map_err(ErrorCode::from),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(
        (qpack.decode(0, Bytes::from_static(&[0, 0])).await).map_err(ErrorCode::from),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(
        (qpack.cancel(0)).map_err(ErrorCode::from),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(
        (qpack.configure(Settings::default(), VARINT_MAX)).map_err(ErrorCode::from),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
}

#[tokio::test]
async fn malformed_field_section_closes_both_directions() {
    let connection = crate::test_support::connection().await;
    let qpack = connection.qpack();
    let result = crate::server::read_request(
        crate::H3ReadStream::new(0, &b"\x01\x01\x00"[..]),
        connection.clone(),
    )
    .await;
    assert!(matches!(
        result,
        Err(h3x::Error {
            code: ErrorCode::QPACK_DECOMPRESSION_FAILED,
            ..
        })
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while qpack.error().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        (qpack.error()).map(ErrorCode::from),
        Some(ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        (qpack.encode(4, Vec::new())).map_err(ErrorCode::from),
        Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        (qpack.decode(4, Bytes::from_static(&[0, 0])).await).map_err(ErrorCode::from),
        Err(ErrorCode::QPACK_DECOMPRESSION_FAILED)
    );
}

#[test]
fn construction_does_not_require_a_runtime() {
    let qpack = Qpack::new(&crate::Settings::default()).unwrap();
    assert!(qpack.encode(0, Vec::new()).is_ok());
}
