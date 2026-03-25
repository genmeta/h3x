#![no_main]

use bytes::Bytes;
use futures::stream;
use h3x::codec::{DecodeFrom, StreamReader};
use h3x::dhttp::frame::Frame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let byte_stream = stream::iter(vec![Ok::<_, h3x::quic::StreamError>(Bytes::copy_from_slice(data))]);
        let mut reader = StreamReader::new(byte_stream);
        let _ = Frame::decode_from(&mut reader).await;
    });
});
