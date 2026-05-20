use std::sync::Arc;

pub use crate::message::stream::{MessageStreamError, ReadStream, WriteStream};
use crate::{connection::ConnectionState, quic, stream_id::StreamId};

/// A request that has just been accepted on a QUIC stream but whose HTTP/3
/// header frame has not yet been interpreted by a higher-level HTTP API.
pub struct UnresolvedRequest {
    /// QUIC stream identifier for this request.
    pub stream_id: StreamId,
    /// Incoming request stream.
    pub read_stream: ReadStream,
    /// Outgoing response stream.
    pub write_stream: WriteStream,
    /// Owning h3 connection.
    pub connection: Arc<ConnectionState<dyn quic::DynConnection>>,
}
