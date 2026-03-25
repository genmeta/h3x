#![no_main]

use std::io::Cursor;

use h3x::codec::DecodeFrom;
use h3x::dhttp::settings::Setting;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // Fuzz individual Setting decoding (2 VarInts + validation).
        let cursor = Cursor::new(data);
        let _ = Setting::decode_from(cursor).await;
    });
});
