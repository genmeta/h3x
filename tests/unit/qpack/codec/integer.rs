use super::*;

#[test]
fn prefixed_integer_round_trips_rfc_examples_and_preserves_suffix() {
    for (value, expected) in [
        (10, vec![0x0a]),
        (31, vec![0x1f, 0x00]),
        (42, vec![0x1f, 0x0b]),
        (1337, vec![0x1f, 0x9a, 0x0a]),
    ] {
        let mut wire = Vec::new();
        wire.put_prefixed_integer(value, 5, 0xa0).unwrap();
        assert_eq!(
            wire,
            expected
                .iter()
                .enumerate()
                .map(|(i, byte)| if i == 0 { byte | 0xa0 } else { *byte })
                .collect::<Vec<_>>()
        );

        wire.push(0xff);
        let (rest, decoded) = be_prefixed_integer(&wire, 5).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(rest, &[0xff]);
    }
}

#[test]
fn prefixed_integer_rejects_truncation_overflow_and_out_of_range_values() {
    let truncated = be_prefixed_integer(&[0x1f], 5).unwrap_err();
    assert_eq!(truncated.code, ErrorCode::QpackDecompressionFailed);
    assert!(matches!(truncated, crate::Error::Connection(_)));

    let oversized = be_prefixed_integer(&[0xff; 10], 8).unwrap_err();
    assert_eq!(oversized.code, ErrorCode::QpackDecompressionFailed);
    assert!(matches!(oversized, crate::Error::Stream(_)));

    let mut wire = Vec::new();
    assert_eq!(
        wire.put_prefixed_integer(VARINT_MAX + 1, 8, 0)
            .unwrap_err()
            .code,
        ErrorCode::QpackDecompressionFailed
    );
    assert!(wire.is_empty());
}
