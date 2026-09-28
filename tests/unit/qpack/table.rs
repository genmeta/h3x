use super::*;

fn insert(name: &'static [u8], value: &'static [u8]) -> EncoderInstruction {
    EncoderInstruction::InsertWithLiteralName {
        name: Bytes::from_static(name),
        value: Bytes::from_static(value),
    }
}

#[test]
fn dynamic_table_inserts_evicts_and_keeps_absolute_indices() {
    let mut table = DynamicTable::new(69).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(69))
        .unwrap();
    table.apply(insert(b"a", b"1")).unwrap();
    assert_eq!(table.insert_count(), 1);
    assert_eq!(table.oldest_index(), 0);
    assert_eq!(table.find_index(b"a", b"1"), Some(0));

    table.apply(insert(b"bb", b"22")).unwrap();
    assert_eq!(table.insert_count(), 2);
    assert_eq!(table.oldest_index(), 1);
    assert!(table.get(0).is_none());
    assert_eq!(table.find_name(b"bb"), Some(1));
}

#[test]
fn duplicate_uses_relative_index_and_capacity_limits_are_enforced() {
    let mut table = DynamicTable::new(128).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(128))
        .unwrap();
    table.apply(insert(b"name", b"value")).unwrap();
    table.apply(EncoderInstruction::Duplicate(0)).unwrap();
    assert_eq!(table.insert_count(), 2);
    assert_eq!(table.find_index(b"name", b"value"), Some(1));

    assert_eq!(
        table
            .apply(EncoderInstruction::Duplicate(2))
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(
        table
            .apply(EncoderInstruction::SetDynamicTableCapacity(129))
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(table.capacity(), 128);
}

#[test]
fn static_table_lookup_prefers_first_wire_index() {
    assert_eq!(find_index(b":method", b"GET"), Some(17));
    assert_eq!(find_name(b"content-type"), Some(44));
    assert_eq!(get(98), Some(("x-frame-options", "sameorigin")));
    assert_eq!(get(99), None);
}

#[test]
fn rejects_invalid_capacities_and_references() {
    let Err(error) = DynamicTable::new(VARINT_MAX + 1) else {
        panic!("capacity beyond the variable-integer range must fail")
    };
    assert_eq!(error.code, ErrorCode::SettingsError);

    let mut table = DynamicTable::new(64).unwrap();
    table
        .apply(EncoderInstruction::SetDynamicTableCapacity(40))
        .unwrap();
    assert_eq!(
        table.set_max_capacity(39).unwrap_err().code,
        ErrorCode::SettingsError
    );
    assert_eq!(
        table.set_max_capacity(VARINT_MAX + 1).unwrap_err().code,
        ErrorCode::SettingsError
    );
    table.set_max_capacity(80).unwrap();
    assert_eq!(table.max_capacity(), 80);

    assert_eq!(
        table
            .apply(insert(b"too-large", b"value"))
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(
        table
            .apply(EncoderInstruction::InsertWithNameReference {
                static_table: true,
                index: 99,
                value: Bytes::new(),
            })
            .unwrap_err()
            .code,
        ErrorCode::QpackEncoderStreamError
    );
    assert_eq!(get(u64::MAX), None);
}
