#![no_main]

use std::io::Cursor;

use h3x::codec::DecodeFrom;
use h3x::varint::VarInt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let cursor = Cursor::new(data);
        // Should never panic — only Ok or Err.
        let _ = VarInt::decode_from(cursor).await;
    });
});
