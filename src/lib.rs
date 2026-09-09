#![doc = include_str!("../README.md")]

pub mod client;
mod endpoint;
mod error;
pub mod protocol;
pub mod runtime;
pub mod server;
pub mod transport;
pub use endpoint::{Endpoint, LocalAuthority, RemoteAuthority};
pub use error::{Code, Error};
#[cfg(feature = "webtransport")]
pub use protocol::webtransport;
pub use protocol::{
    BodyWriter, Chunk, ChunkBody, Connection, Fixed, ResponseSender, Settings, StreamId,
};
#[cfg(not(target_arch = "wasm32"))]
pub use runtime::{Pool, init, shutdown};
pub type EndpointError = Error;
pub type PoolError = Error;
use protocol::{qpack, wire};

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
        let _ = crate::wire::frame::be_complete_frame(&bytes::Bytes::copy_from_slice(data));
    }

    pub fn unidirectional_stream(data: &[u8]) {
        let _ = qbase::varint::be_varint(data);
    }
}
