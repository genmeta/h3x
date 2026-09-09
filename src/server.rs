//! Incoming requests with connection identity, and responses on the original stream.
mod request;
mod response;
pub use request::Request;
pub use response::Response;

pub use crate::protocol::{ChunkBody, Connection, ResponseSender};
