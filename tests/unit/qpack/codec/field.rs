use super::*;
use crate::qpack::codec::instruction::EncoderInstruction;

#[test]
fn every_field_line_representation_round_trips() {
    let lines = [
        FieldLine::Indexed {
            static_table: true,
            index: 17,
        },
        FieldLine::Indexed {
            static_table: false,
            index: 1337,
        },
        FieldLine::IndexedPostBase { index: 42 },
        FieldLine::LiteralWithNameReference {
            never_index: true,
            static_table: true,
            index: 1,
            value: Bytes::from_static(b"/other"),
        },
        FieldLine::LiteralWithPostBaseNameReference {
            never_index: true,
            index: 9,
            value: Bytes::from_static(b"value"),
        },
        FieldLine::Literal(Field {
            name: Bytes::from_static(b"x-name"),
            value: Bytes::from_static(b"x-value"),
            never_index: true,
        }),
    ];

    for line in lines {
        let mut wire = Vec::new();
        wire.put_field_line(&line).unwrap();
        wire.push(0xff);
        let (rest, decoded) = be_field_line(&wire).unwrap();
        assert_eq!(decoded, line);
        assert_eq!(rest, &[0xff]);
    }
}

#[test]
fn field_section_prefix_round_trips_both_delta_base_directions() {
    for prefix in [
        FieldSectionPrefix {
            required_insert_count: 0,
            base: 0,
        },
        FieldSectionPrefix {
            required_insert_count: 10,
            base: 14,
        },
        FieldSectionPrefix {
            required_insert_count: 10,
            base: 7,
        },
    ] {
        let mut wire = Vec::new();
        wire.put_field_section_prefix(&prefix, 4096).unwrap();
        wire.push(0xff);
        let (rest, decoded) = be_field_section_prefix(&wire, 4096, 10).unwrap();
        assert_eq!(decoded, prefix);
        assert_eq!(rest, &[0xff]);
    }
}

#[test]
fn field_resolution_preserves_never_index_and_checks_dynamic_bounds() {
    let table = DynamicTable::new(0).unwrap();
    let prefix = FieldSectionPrefix {
        required_insert_count: 0,
        base: 0,
    };
    let resolved = FieldLine::LiteralWithNameReference {
        never_index: true,
        static_table: true,
        index: 1,
        value: Bytes::from_static(b"/private"),
    }
    .resolve(prefix, &table)
    .unwrap();
    assert_eq!(resolved.name, Bytes::from_static(b":path"));
    assert_eq!(resolved.value, Bytes::from_static(b"/private"));
    assert!(resolved.never_index);

    let invalid = FieldLine::Indexed {
        static_table: false,
        index: 0,
    };
    assert_eq!(
        invalid.dynamic_index(prefix).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
}

#[test]
fn field_resolution_rejects_missing_indices_and_preserves_post_base_values() {
    let mut table = DynamicTable::new(128).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(128))
        .unwrap();
    table
        .apply(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"dynamic"),
            value: Bytes::from_static(b"old"),
        })
        .unwrap();
    let prefix = FieldSectionPrefix {
        required_insert_count: 1,
        base: 0,
    };
    let field = FieldLine::LiteralWithPostBaseNameReference {
        never_index: true,
        index: 0,
        value: Bytes::from_static(b"new"),
    }
    .resolve(prefix, &table)
    .unwrap();
    assert_eq!(field.name, "dynamic");
    assert_eq!(field.value, "new");
    assert!(field.never_index);

    assert_eq!(
        FieldLine::IndexedPostBase { index: 1 }
            .dynamic_index(prefix)
            .unwrap_err()
            .code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        FieldLine::IndexedPostBase { index: 0 }
            .resolve(prefix, &DynamicTable::new(128).unwrap())
            .unwrap_err()
            .code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        FieldLine::Indexed {
            static_table: true,
            index: 99,
        }
        .resolve(prefix, &table)
        .unwrap_err()
        .code,
        ErrorCode::QpackDecompressionFailed
    );
}

#[test]
fn malformed_prefixes_and_empty_field_lines_are_rejected() {
    for (prefix, capacity) in [
        (
            FieldSectionPrefix {
                required_insert_count: VARINT_MAX + 1,
                base: 0,
            },
            128,
        ),
        (
            FieldSectionPrefix {
                required_insert_count: 0,
                base: VARINT_MAX + 1,
            },
            128,
        ),
        (
            FieldSectionPrefix {
                required_insert_count: 1,
                base: 0,
            },
            0,
        ),
    ] {
        assert_eq!(
            Vec::new()
                .put_field_section_prefix(&prefix, capacity)
                .unwrap_err()
                .code,
            ErrorCode::QpackDecompressionFailed
        );
    }
    assert_eq!(
        be_field_section_prefix(&[0, 0], VARINT_MAX + 1, 0)
            .unwrap_err()
            .code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        be_field_section_prefix(&[0], 128, 0).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        be_field_section_prefix(&[3, 0], 32, 0).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        be_field_section_prefix(&[0, 0xff], 128, 0)
            .unwrap_err()
            .code,
        ErrorCode::QpackDecompressionFailed
    );
    assert_eq!(
        be_field_line(&[]).unwrap_err().code,
        ErrorCode::QpackDecompressionFailed
    );
}
