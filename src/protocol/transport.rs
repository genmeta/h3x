use std::future::Future;

pub use qbase::role::Role;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Error, Result};

/// One established QUIC connection, with stream-local cancellation supplied by its adapter.
/// open/accept futures must leave any unreturned stream owned by the transport when cancelled.
/// Dropping a returned half must cancel unfinished I/O; after EOF/FIN it must be harmless.
/// Explicit stop/cancel must be idempotent with that Drop cleanup.
/// Connection termination must wake pending open/accept and stream I/O with an error,
/// including when initiated by close. Adapters must preserve the terminal error and
/// stream reset errors where available.
/// The endpoint role must remain fixed for the lifetime of the connection.
#[expect(
    clippy::type_complexity,
    reason = "Keep the agreed stream-ID and raw stream tuple interface, without adapter wrapper types"
)]
pub trait Transport: Send + Sync + 'static {
    /// Report FIN as a successful read of zero bytes and retain RESET metadata in I/O errors.
    type StreamReader: AsyncRead + StopSending + Unpin + Send + 'static;
    type StreamWriter: AsyncWrite + CancelStream + Unpin + Send + 'static;

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

    /// Return the terminal protocol code and transport-provided reason.
    /// Graceful termination uses `ErrorCode::H3_NO_ERROR`.
    fn terminated(&self) -> impl Future<Output = Error> + Send;
}
