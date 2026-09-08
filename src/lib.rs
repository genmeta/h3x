#![doc = include_str!("../README.md")]

mod endpoint;
mod error;
pub mod protocol;
mod request;
mod response;
pub mod runtime;
pub mod transport;
pub use endpoint::{Endpoint, RemoteAuthority, RequestAuthority};
pub use error::{Code, Error};
#[cfg(feature = "webtransport")]
pub use protocol::webtransport;
pub use protocol::{
    BodyWriter, Chunk, ChunkBody, Connection, Fixed, ResponseSender, Sender, Settings, StreamId,
};
pub use request::{ChunkRequestFuture, Request, RequestFuture};
pub use response::{Response, ResponseFuture};
#[cfg(not(target_arch = "wasm32"))]
pub use runtime::{Pool, init, shutdown};
pub type EndpointError = Error;
pub type PoolError = Error;
use protocol::{body, connection, platform, qpack, stream_id, wire};

#[cfg(not(target_arch = "wasm32"))]
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
#[cfg(target_arch = "wasm32")]
pub type BoxError = Box<dyn std::error::Error + 'static>;

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
