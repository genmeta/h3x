mod error;

pub use error::{Error, Result};

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";

// Protocol primitives are connected to message I/O in the final stage.
#[allow(dead_code, unused_imports)]
mod protocol;
