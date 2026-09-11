mod error;

pub use error::{Error, Result};

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";
