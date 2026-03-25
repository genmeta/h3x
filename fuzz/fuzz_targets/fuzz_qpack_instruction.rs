#![no_main]

use std::io::Cursor;

use h3x::codec::DecodeFrom;
use h3x::qpack::{decoder::DecoderInstruction, encoder::EncoderInstruction};
use libfuzzer_sys::fuzz_target;
use tokio::io::BufReader;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // Fuzz QPACK encoder instructions (prefix byte pattern matching).
        let reader = BufReader::new(Cursor::new(data));
        let _ = EncoderInstruction::decode_from(reader).await;

        // Fuzz QPACK decoder instructions.
        let reader = BufReader::new(Cursor::new(data));
        let _ = DecoderInstruction::decode_from(reader).await;
    });
});
