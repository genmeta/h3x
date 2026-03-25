#![no_main]

use std::sync::Arc;

use bytes::Bytes;
use h3x::{
    dhttp::settings::{QpackMaxTableCapacity, Settings},
    qpack::decoder::DecoderState,
    varint::VarInt,
};
use libfuzzer_sys::fuzz_target;

// Feed random encoder instructions to DecoderState to find panics/OOM.
//
// The fuzz data is interpreted as a sequence of instructions:
// - Byte 0x00..0x3F: SetDynamicTableCapacity (next 2 bytes = capacity)
// - Byte 0x40..0x7F: InsertWithNameReference (static, next byte = index, rest = value)
// - Byte 0x80..0xBF: InsertWithLiteralName (next bytes = name + value)
// - Byte 0xC0..0xDF: Duplicate (next byte = index)
// - Byte 0xE0..0xFF: InsertWithNameReference (dynamic, next byte = index, rest = value)
fuzz_target!(|data: &[u8]| {
    let mut settings = Settings::default();
    settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(4096)));
    let settings = Arc::new(settings);

    let mut decoder = DecoderState::new(settings);
    let _ = decoder.set_dynamic_table_capacity(4096);

    let mut cursor = data;
    while !cursor.is_empty() {
        let tag = cursor[0];
        cursor = &cursor[1..];

        match tag {
            0x00..0x40 => {
                // SetDynamicTableCapacity
                if cursor.len() < 2 {
                    break;
                }
                let capacity = u16::from_be_bytes([cursor[0], cursor[1]]) as u64;
                cursor = &cursor[2..];
                let _ = decoder.set_dynamic_table_capacity(capacity);
            }
            0x40..0x80 => {
                // InsertWithNameReference (static)
                if cursor.len() < 2 {
                    break;
                }
                let name_index = cursor[0] as u64;
                let value_len = cursor[1] as usize;
                cursor = &cursor[2..];
                if cursor.len() < value_len {
                    break;
                }
                let value = Bytes::copy_from_slice(&cursor[..value_len]);
                cursor = &cursor[value_len..];
                let _ = decoder.insert_with_name_reference(true, name_index, value);
            }
            0x80..0xC0 => {
                // InsertWithLiteralName
                if cursor.len() < 2 {
                    break;
                }
                let name_len = cursor[0] as usize;
                let value_len = cursor[1] as usize;
                cursor = &cursor[2..];
                if cursor.len() < name_len + value_len {
                    break;
                }
                let name = Bytes::copy_from_slice(&cursor[..name_len]);
                let value = Bytes::copy_from_slice(&cursor[name_len..name_len + value_len]);
                cursor = &cursor[name_len + value_len..];
                let _ = decoder.insert_with_literal_name(name, value);
            }
            0xC0..0xE0 => {
                // Duplicate
                if cursor.is_empty() {
                    break;
                }
                let index = cursor[0] as u64;
                cursor = &cursor[1..];
                let _ = decoder.duplicate(index);
            }
            0xE0..=0xFF => {
                // InsertWithNameReference (dynamic)
                if cursor.len() < 2 {
                    break;
                }
                let name_index = cursor[0] as u64;
                let value_len = cursor[1] as usize;
                cursor = &cursor[2..];
                if cursor.len() < value_len {
                    break;
                }
                let value = Bytes::copy_from_slice(&cursor[..value_len]);
                cursor = &cursor[value_len..];
                let _ = decoder.insert_with_name_reference(false, name_index, value);
            }
        }
    }
});
