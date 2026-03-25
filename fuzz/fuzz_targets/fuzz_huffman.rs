#![no_main]

use httlib_huffman::DecoderSpeed;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz Huffman decoding directly with arbitrary bytes.
    let mut decoded = Vec::new();
    let _ = httlib_huffman::decode(data, &mut decoded, DecoderSpeed::FourBits);

    // Roundtrip: encode valid ASCII then decode.
    if !data.is_empty() && data.iter().all(|b| b.is_ascii()) {
        let mut encoded = Vec::new();
        if httlib_huffman::encode(data, &mut encoded).is_ok() {
            let mut roundtripped = Vec::new();
            let _ =
                httlib_huffman::decode(&encoded, &mut roundtripped, DecoderSpeed::FourBits);
            assert_eq!(data, &roundtripped[..]);
        }
    }
});
