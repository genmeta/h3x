#![no_main]

use std::sync::Arc;

use bytes::Bytes;
use h3x::{
    dhttp::settings::{QpackBlockedStreams, QpackMaxTableCapacity, Settings},
    qpack::{
        algorithm::{Algorithm, CompressOutput, DynamicCompressAlgo, HuffmanAlways},
        decoder::DecoderState,
        encoder::{EncoderInstruction, EncoderState},
        field::{EncodedFieldSectionPrefix, FieldLine},
    },
    varint::VarInt,
};
use libfuzzer_sys::fuzz_target;

fn parse_field_lines(mut data: &[u8]) -> Vec<FieldLine> {
    let mut lines = Vec::new();
    while data.len() >= 2 {
        let name_len = data[0] as usize;
        data = &data[1..];
        if data.len() < name_len + 1 {
            break;
        }
        let name = Bytes::copy_from_slice(&data[..name_len]);
        data = &data[name_len..];
        let value_len = data[0] as usize;
        data = &data[1..];
        if data.len() < value_len {
            break;
        }
        let value = Bytes::copy_from_slice(&data[..value_len]);
        data = &data[value_len..];
        lines.push(FieldLine { name, value });
    }
    lines
}

fn apply_instructions(
    decoder: &mut DecoderState,
    instructions: &std::collections::VecDeque<EncoderInstruction>,
) {
    for instruction in instructions {
        match instruction {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                let _ = decoder.set_dynamic_table_capacity(*capacity);
            }
            EncoderInstruction::InsertWithNameReference {
                is_static,
                name_index,
                value,
                ..
            } => {
                let abs_index = if *is_static {
                    *name_index
                } else {
                    decoder.table_inserted_count().wrapping_sub(name_index + 1)
                };
                let _ = decoder.insert_with_name_reference(*is_static, abs_index, value.clone());
            }
            EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                let _ = decoder.insert_with_literal_name(name.clone(), value.clone());
            }
            EncoderInstruction::Duplicate { index } => {
                let abs_index = decoder
                    .table_inserted_count()
                    .wrapping_sub(index + 1);
                let _ = decoder.duplicate(abs_index);
            }
        }
    }
}

fn verify_roundtrip(
    settings: &Settings,
    decoder: &DecoderState,
    output: &CompressOutput,
    original: &[FieldLine],
) {
    let max_table_capacity = settings.qpack_max_table_capacity().into_inner();
    let total_inserts = decoder.table_inserted_count();

    let required_insert_count = match EncodedFieldSectionPrefix::decode_ric(
        output.prefix.encoded_insert_count,
        max_table_capacity,
        total_inserts,
    ) {
        Ok(ric) => ric,
        Err(_) => return,
    };

    let base = match EncodedFieldSectionPrefix::resolve_base(
        required_insert_count,
        output.prefix.sign,
        output.prefix.delta_base,
    ) {
        Ok(b) => b,
        Err(_) => return,
    };

    let decoded: Vec<FieldLine> = output
        .representations
        .iter()
        .filter_map(|repr| decoder.decompress(repr, base).ok())
        .collect();

    assert_eq!(decoded.len(), original.len(), "decoded count mismatch");
    for (orig, dec) in original.iter().zip(decoded.iter()) {
        assert_eq!(orig.name, dec.name, "name mismatch");
        assert_eq!(orig.value, dec.value, "value mismatch");
    }
}

fuzz_target!(|data: &[u8]| {
    let field_lines = parse_field_lines(data);
    if field_lines.is_empty() {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut settings = Settings::default();
        settings.set(QpackMaxTableCapacity::setting(VarInt::from_u32(4096)));
        settings.set(QpackBlockedStreams::setting(VarInt::from_u32(100)));
        let settings = Arc::new(settings);

        let mut encoder = EncoderState::new(settings.clone());
        encoder.set_max_table_capacity(4096).unwrap();

        let mut decoder = DecoderState::new(settings.clone());
        decoder.set_dynamic_table_capacity(4096).unwrap();

        let algo = DynamicCompressAlgo::new(HuffmanAlways);
        let output = algo
            .compress(&mut encoder, field_lines.clone(), true)
            .await;

        apply_instructions(&mut decoder, encoder.pending_instructions());
        verify_roundtrip(&settings, &decoder, &output, &field_lines);
    });
});
