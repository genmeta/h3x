#![no_main]

use bytes::Bytes;
use h3x::buflist::BufList;
use h3x::codec::DecodeFrom;
use h3x::dhttp::frame::Frame;
use h3x::dhttp::goaway::Goaway;
use h3x::varint::VarInt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        // Construct a GOAWAY frame with fuzzed payload.
        let mut payload = BufList::new();
        payload.write(Bytes::copy_from_slice(data));
        let Ok(mut frame) = Frame::new(VarInt::from_u32(0x07), payload) else {
            return;
        };
        let _ = Goaway::decode_from(&mut frame).await;
    });
});
