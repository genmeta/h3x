use super::*;

pub(crate) fn shared() -> Arc<Qpack<crate::test_support::TestTransport>> {
    Qpack::new(
        Arc::new(crate::test_support::TestTransport::default()),
        &crate::Settings::default(),
        Arc::new(crate::protocol::stream::bi::BiStreams::default()),
    )
    .unwrap()
}

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
    let qpack = shared();
    assert_eq!(
        qpack.close(Error::H3_INTERNAL_ERROR),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(
        qpack.close(Error::H3_EXCESSIVE_LOAD),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(qpack.encode(0, Vec::new()), Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(
        qpack.decode(0, Bytes::from_static(&[0, 0])).await,
        Err(Error::H3_INTERNAL_ERROR)
    );
    assert_eq!(qpack.cancel(0), Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(
        qpack.configure(Settings::default(), VARINT_MAX),
        Err(Error::H3_INTERNAL_ERROR)
    );
}

#[tokio::test]
async fn request_errors_leave_qpack_usable() {
    let qpack = shared();
    for error in [
        Error::H3_REQUEST_CANCELLED,
        Error::H3_REQUEST_REJECTED,
        Error::H3_REQUEST_INCOMPLETE,
        Error::H3_MESSAGE_ERROR,
    ] {
        qpack.on_error(error);
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
    let qpack = shared();
    assert_eq!(
        qpack.decode(0, Bytes::from_static(&[0])).await,
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(qpack.error(), Some(Error::QPACK_DECOMPRESSION_FAILED));
    assert_eq!(
        qpack.encode(4, Vec::new()),
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        qpack.decode(4, Bytes::from_static(&[0, 0])).await,
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    );
}
