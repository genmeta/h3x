#![no_main]

use bytes::Bytes;
use futures::stream;
use h3x::codec::DecodeFrom;
use h3x::connection::StreamError;
use h3x::qpack::field::{FieldLine, FieldSection};
use libfuzzer_sys::fuzz_target;

/// Parse fuzz data into a sequence of FieldLine items.
/// Format: repeated [name_len: u8, name: [u8], value_len: u8, value: [u8]]
fn parse_field_lines(mut data: &[u8]) -> Vec<Result<FieldLine, StreamError>> {
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
        lines.push(Ok(FieldLine { name, value }));
    }
    lines
}

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let field_lines = parse_field_lines(data);
        let field_stream = stream::iter(field_lines);
        let _ = FieldSection::decode_from(field_stream).await;
    });
});
