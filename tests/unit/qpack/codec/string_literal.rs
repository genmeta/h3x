use super::*;

#[test]
fn literal_round_trips_for_each_supported_prefix_width() {
    for prefix_bits in 2..=8 {
        let high_bits = if prefix_bits == 8 {
            0
        } else {
            !((1u16 << prefix_bits) - 1) as u8
        };
        let mut wire = Vec::new();
        wire.put_string_literal(b"custom-value", prefix_bits, high_bits)
            .unwrap();
        wire.extend_from_slice(b"tail");

        let (rest, value) = be_string_literal_slice(&wire, prefix_bits).unwrap();
        assert_eq!(value, Bytes::from_static(b"custom-value"));
        assert_eq!(rest, b"tail");
    }
}

#[test]
fn literal_validation_does_not_partially_write() {
    for (prefix_bits, high_bits) in [(1, 0), (9, 0), (4, 0x01)] {
        let mut wire = vec![0xaa];
        assert_eq!(
            wire.put_string_literal(b"value", prefix_bits, high_bits)
                .unwrap_err()
                .code,
            ErrorCode::QpackDecompressionFailed
        );
        assert_eq!(wire, [0xaa]);
    }

    assert_eq!(
        be_string_literal_slice(&[5, b'a'], 8).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
}

#[tokio::test]
async fn async_literals_validate_prefix_lengths_truncation_and_huffman() {
    for prefix_bits in [1, 9] {
        assert_eq!(
            be_string_literal(&mut &[][..], prefix_bits)
                .await
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
        assert_eq!(
            be_string_literal_with_first(&mut &[][..], 0, prefix_bits)
                .await
                .unwrap_err()
                .code,
            ErrorCode::QpackEncoderStreamError
        );
    }

    let mut oversized = Vec::new();
    oversized
        .put_prefixed_integer(MAX_BUFFERED_FRAME_PAYLOAD as u64 + 1, 7, 0)
        .unwrap();
    let first = oversized.remove(0);
    let error = be_string_literal_with_first(&mut oversized.as_slice(), first, 8)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QpackEncoderStreamError);
    assert!(matches!(error, crate::Error::Connection(_)));
    assert_eq!(
        be_string_literal(&mut &[2, b'a'][..], 8)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );

    let mut huffman = Vec::new();
    httlib_huffman::encode(b"hello", &mut huffman).unwrap();
    let mut wire = Vec::new();
    wire.put_prefixed_integer(huffman.len() as u64, 7, 0x80)
        .unwrap();
    wire.extend_from_slice(&huffman);
    assert_eq!(
        be_string_literal(&mut wire.as_slice(), 8).await.unwrap(),
        Bytes::from_static(b"hello")
    );
    let (rest, value) = be_string_literal_slice(&wire, 8).unwrap();
    assert!(rest.is_empty());
    assert_eq!(value, Bytes::from_static(b"hello"));

    assert_eq!(
        be_string_literal(&mut &[0x81, 0xff][..], 8)
            .await
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(
        be_string_literal_slice(&[0x81, 0xff], 8).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
}

#[tokio::test]
async fn huffman_expansion_respects_decoded_buffer_limit() {
    let decoded = vec![b'0'; MAX_BUFFERED_FRAME_PAYLOAD + 1];
    let mut huffman = Vec::new();
    httlib_huffman::encode(&decoded, &mut huffman).unwrap();
    assert!(huffman.len() <= MAX_BUFFERED_FRAME_PAYLOAD);
    let mut wire = Vec::new();
    wire.put_prefixed_integer(huffman.len() as u64, 7, 0x80)
        .unwrap();
    wire.extend_from_slice(&huffman);
    let error = be_string_literal(&mut wire.as_slice(), 8)
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QpackEncoderStreamError);
    assert!(matches!(error, crate::Error::Connection(_)));
}

#[test]
fn buffered_literal_rejects_missing_or_invalid_prefix() {
    assert_eq!(
        be_string_literal_slice(&[], 8).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        be_string_literal_slice(&[0], 1).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
}
