#![no_main]

use std::io::Cursor;

use h3x::codec::DecodeFrom;
use h3x::qpack::field::{EncodedFieldSectionPrefix, FieldLineRepresentation};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // Fuzz the 5-variant FieldLineRepresentation decoder.
        let cursor = Cursor::new(data);
        let _ = FieldLineRepresentation::decode_from(cursor).await;

        // Also fuzz EncodedFieldSectionPrefix (2 varints).
        let cursor = Cursor::new(data);
        let _ = EncodedFieldSectionPrefix::decode_from(cursor).await;
    });
});
