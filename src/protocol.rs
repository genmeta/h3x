pub(crate) mod body;
pub(crate) mod connection;
pub(crate) mod headers;
pub(crate) mod message;
pub(crate) mod qpack;
mod request;
pub(crate) mod settings;
#[cfg(feature = "webtransport")]
pub mod webtransport;
pub(crate) mod wire;
pub use body::{BodyWriter, Chunk, ChunkBody, Fixed};
pub use connection::{Connection, ResponseSender, new};
pub use qbase::sid::StreamId;
pub use request::ResponseFuture;
pub use settings::Settings;

#[cfg(any(test, feature = "fuzzing"))]
#[path = "../tests/support/streams.rs"]
mod test_streams;
