use super::*;

#[test]
fn capacity_insert_duplicate_and_eviction() {
    let mut table = DynamicTable::new(68).unwrap();
    let insert = EncoderInstruction::InsertWithLiteralName {
        name: Bytes::from_static(b"x"),
        value: Bytes::from_static(b"y"),
    };
    assert_eq!(table.capacity, 0);
    assert_eq!(
        table.apply(insert.clone()),
        Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
    );
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(68))
        .unwrap();
    table.apply(insert).unwrap();
    table.apply(EncoderInstruction::Duplicate(0)).unwrap();
    assert_eq!(
        (table.size, table.insert_count, table.entries.len()),
        (68, 2, 2)
    );
    table
        .apply(EncoderInstruction::InsertWithNameReference {
            static_table: false,
            index: 0,
            value: Bytes::from_static(b"z"),
        })
        .unwrap();
    assert!(table.get(0).is_none());
    assert_eq!(table.get(2).unwrap().value, "z");
    assert_eq!((table.size, table.insert_count), (68, 3));
    assert_eq!(
        table.apply(EncoderInstruction::Duplicate(2)),
        Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
    );
    assert_eq!(
        table.apply(EncoderInstruction::SetDynamicTableCapacity(69)),
        Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
    );
    assert_eq!(
        (table.capacity, table.size, table.insert_count),
        (68, 68, 3)
    );
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(34))
        .unwrap();
    assert!(table.get(1).is_none());
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(0))
        .unwrap();
    assert!(table.entries.is_empty());
    assert_eq!(
        (table.size, table.insert_count, table.max_capacity),
        (0, 3, 68)
    );
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(68))
        .unwrap();
    table
        .apply(EncoderInstruction::InsertWithNameReference {
            static_table: true,
            index: 0,
            value: Bytes::new(),
        })
        .unwrap();
    assert_eq!(table.get(3).unwrap().name, ":authority");
    assert_eq!(table.size, 42);
    assert!(DynamicTable::new(VARINT_MAX + 1).is_err());
}

#[test]
fn rejected_updates_preserve_entries_and_capacity() {
    let mut table = DynamicTable::new(68).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(68))
        .unwrap();
    table
        .apply(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"y"),
        })
        .unwrap();
    for instruction in [
        EncoderInstruction::SetDynamicTableCapacity(69),
        EncoderInstruction::Duplicate(1),
        EncoderInstruction::InsertWithNameReference {
            static_table: true,
            index: 99,
            value: Bytes::new(),
        },
        EncoderInstruction::InsertWithNameReference {
            static_table: false,
            index: 1,
            value: Bytes::new(),
        },
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from(vec![0; 36]),
        },
    ] {
        assert_eq!(
            table.apply(instruction),
            Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
        );
        assert_eq!(
            (table.capacity(), table.size(), table.insert_count()),
            (68, 34, 1)
        );
        assert_eq!(table.get(0).unwrap().value, "y");
    }
    for maximum in [67, VARINT_MAX + 1] {
        assert_eq!(
            table.set_max_capacity(maximum),
            Err(ErrorCode::H3_SETTINGS_ERROR)
        );
        assert_eq!(table.max_capacity(), 68);
    }
    table.set_max_capacity(128).unwrap();
    assert_eq!(
        (table.capacity(), table.size(), table.insert_count()),
        (68, 34, 1)
    );
    assert_eq!(table.max_capacity(), 128);
}

#[test]
fn lookups_prefer_newest_retained_match_and_survive_clear() {
    let mut table = DynamicTable::new(68).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(68))
        .unwrap();
    for value in [b"a", b"a", b"b"] {
        table
            .apply(EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(value),
            })
            .unwrap();
    }
    assert_eq!(table.oldest_index(), 1);
    assert_eq!(table.find_index(b"x", b"a"), Some(1));
    assert_eq!(table.find_name(b"x"), Some(2));
    assert_eq!(table.find_name(b"missing"), None);
    assert!(table.get(0).is_none());
    assert!(table.get(3).is_none());
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(0))
        .unwrap();
    assert_eq!(table.oldest_index(), 3);
    assert_eq!(table.find_name(b"x"), None);
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(68))
        .unwrap();
    table
        .apply(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"c"),
        })
        .unwrap();
    assert_eq!(table.find_index(b"x", b"c"), Some(3));
}

#[test]
fn insertion_count_overflow_does_not_evict_existing_entry() {
    let mut table = DynamicTable::new(34).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(34))
        .unwrap();
    table
        .apply(EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from_static(b"y"),
        })
        .unwrap();
    table.insert_count = VARINT_MAX;
    assert_eq!(
        table.apply(EncoderInstruction::Duplicate(0)),
        Err(ErrorCode::QPACK_ENCODER_STREAM_ERROR)
    );
    assert_eq!(table.insert_count(), VARINT_MAX);
    assert_eq!(table.size(), 34);
    assert_eq!(table.get(VARINT_MAX - 1).unwrap().value, "y");
}
