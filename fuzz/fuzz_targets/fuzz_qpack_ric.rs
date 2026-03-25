#![no_main]

use h3x::qpack::field::EncodedFieldSectionPrefix;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 25 {
        return;
    }

    // Extract 3 u64 values from the fuzz input for decode_ric.
    let encoded_insert_count = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let max_table_capacity = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let total_number_of_inserts = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let _ = EncodedFieldSectionPrefix::decode_ric(
        encoded_insert_count,
        max_table_capacity,
        total_number_of_inserts,
    );

    // Extract values for resolve_base.
    let required_insert_count = encoded_insert_count;
    let sign = data[24] & 1 == 1;
    let delta_base = total_number_of_inserts;
    let _ = EncodedFieldSectionPrefix::resolve_base(required_insert_count, sign, delta_base);

    // Also test roundtrip: encode_ric → decode_ric.
    if max_table_capacity > 0 {
        let encoded =
            EncodedFieldSectionPrefix::encode_ric(total_number_of_inserts, max_table_capacity);
        let _ = EncodedFieldSectionPrefix::decode_ric(
            encoded,
            max_table_capacity,
            total_number_of_inserts,
        );
    }
});
