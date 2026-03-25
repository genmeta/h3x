#![no_main]

use std::io::Cursor;

use h3x::codec::DecodeFrom;
use h3x::dhttp::settings::Settings;
use libfuzzer_sys::fuzz_target;
use tokio::io::BufReader;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // Fuzz full SETTINGS frame parsing (multiple settings + validation).
        let reader = BufReader::new(Cursor::new(data));
        let _ = Settings::decode_from(reader).await;
    });
});
