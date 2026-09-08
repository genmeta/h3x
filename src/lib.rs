#![doc = include_str!("../README.md")]

mod body;
mod config;
mod connection;
mod error;
mod qpack;
mod stream_id;
mod wire;

pub mod transport;
#[cfg(feature = "webtransport")]
pub mod webtransport;

pub use body::Body;
pub use config::Settings;
pub use connection::{Connection, RequestStream, Response};
pub use error::{Code, Error};
pub use stream_id::StreamId;

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// ALPN token used by the symmetric HTTP/3 wire profile.
pub const ALPN: &[u8] = b"h3";

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    pub fn frame(data: &[u8]) {
        crate::wire::fuzz_frame(data);
    }

    pub fn field_section(data: &[u8]) {
        crate::qpack::fuzz_field_section(data);
    }

    pub fn qpack_integer(data: &[u8]) {
        for prefix in 1..=8 {
            let _ = crate::qpack::decode_prefixed_integer(data, prefix);
        }
    }

    pub fn qpack_string(data: &[u8]) {
        for prefix in [6, 7] {
            let _ = crate::qpack::decode_string(data, prefix);
        }
    }

    pub fn qpack_instruction(data: &[u8]) {
        crate::qpack::fuzz_instruction(data);
    }

    pub fn goaway(data: &[u8]) {
        if let Ok((0x07, payload, consumed)) = crate::wire::decode_frame(data) {
            let _ = crate::wire::decode_varint(payload)
                .map(|(_, payload_len)| consumed == data.len() && payload_len == payload.len());
        }
    }

    pub fn unidirectional_stream(data: &[u8]) {
        let _ = crate::wire::decode_varint(data);
    }
}
