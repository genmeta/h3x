#![no_main]

use std::io::Cursor;

use h3x::qpack::integer::decode_integer;
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

        // Fuzz all valid prefix bit widths (1..=8).
        for n in 1..=8u8 {
            let cursor = Cursor::new(rest);
            let _ = decode_integer(cursor, prefix, n).await;
        }
    });
});
