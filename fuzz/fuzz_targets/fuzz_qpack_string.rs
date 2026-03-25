#![no_main]

use std::io::Cursor;

use h3x::qpack::string::decode_string;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let prefix = data[0];
        let rest = &data[1..];

        // Fuzz with n=7 (typical QPACK string prefix width).
        let cursor = Cursor::new(rest);
        let _ = decode_string(cursor, prefix, 7).await;

        // Also fuzz with n=6 (used in some header representations).
        let cursor = Cursor::new(rest);
        let _ = decode_string(cursor, prefix, 6).await;
    });
});
