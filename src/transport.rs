use std::{future::Future, io};

pub use qbase::role::Role;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Error, Result};

/// A transport stream that can classify its own terminal I/O errors.
///
/// Implement this on an adapter-owned stream wrapper. In particular, a dquic
/// adapter performs its qrecovery/qbase downcasts in this implementation,
/// before the error enters the HTTP/3 protocol layer.
pub trait TransportError {
    fn map_error(error: io::Error) -> Error;
}

/// One established QUIC connection, with stream-local cancellation supplied by its adapter.
/// open/accept futures must leave any unreturned stream owned by the transport when cancelled.
/// HTTP/3 explicitly stops/cancels unfinished halves on protocol or application cancellation.
/// Stop/cancel must be harmless after EOF/FIN, reset, or connection termination.
/// A terminal I/O error must mean the transport direction is already terminated.
/// Connection termination must wake pending open/accept and stream I/O with an error,
/// including when initiated by close. Adapters must preserve the terminal error and
/// stream reset errors where available.
/// The endpoint role must remain fixed for the lifetime of the connection.
#[expect(
    clippy::type_complexity,
    reason = "Keep the agreed stream-ID and reader/writer tuple interface"
)]
pub trait Transport: Send + Sync + 'static {
    /// Report FIN as a successful read of zero bytes and retain RESET metadata in I/O errors.
    type StreamReader: AsyncRead + StopSending + TransportError + Unpin + Send + 'static;
    type StreamWriter: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static;

    fn role(&self) -> Role;

    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, (Self::StreamReader, Self::StreamWriter))>>> + Send;

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(u64, (Self::StreamReader, Self::StreamWriter))>> + Send;

    fn open_uni(&self) -> impl Future<Output = Result<Option<(u64, Self::StreamWriter)>>> + Send;

    fn accept_uni(&self) -> impl Future<Output = Result<(u64, Self::StreamReader)>> + Send;

    fn close(&self, reason: String, code: u64) -> Result<()>;
}
