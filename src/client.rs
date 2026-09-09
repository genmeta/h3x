//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
mod request;
mod response;
pub use request::{Executing, Request, Streaming};
pub use response::Response;

pub use crate::protocol::{BodyWriter, Chunk, Connection, Fixed, ResponseFuture};
