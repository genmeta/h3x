use std::future::Future;

use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{Error, Result};

/// One established QUIC connection, with stream-local cancellation supplied by its adapter.
/// open/accept futures must leave any unreturned stream owned by the transport when cancelled.
/// Dropping a returned half must cancel unfinished I/O; after EOF/FIN it must be harmless.
/// Explicit stop/cancel must be idempotent with that Drop cleanup.
/// close must terminate pending I/O; adapters must preserve stream reset errors where available.
/// The endpoint role must remain fixed for the lifetime of the connection.
#[expect(
    clippy::type_complexity,
    reason = "Keep the agreed stream-ID and raw stream tuple interface, without adapter wrapper types"
)]
pub trait Transport: Send + Sync + 'static {
    /// Report FIN as a successful read of zero bytes and retain RESET metadata in I/O errors.
    type Recv: AsyncRead + StopSending + Unpin + Send + 'static;
    type Send: AsyncWrite + CancelStream + Unpin + Send + 'static;

    fn role(&self) -> Role;

    fn open_bi_stream(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, (Self::Recv, Self::Send))>>> + Send;

    fn accept_bi_stream(
        &self,
    ) -> impl Future<Output = Result<(u64, (Self::Recv, Self::Send))>> + Send;

    fn open_uni_stream(&self) -> impl Future<Output = Result<Option<(u64, Self::Send)>>> + Send;

    fn accept_uni_stream(&self) -> impl Future<Output = Result<(u64, Self::Recv)>> + Send;

    fn close(&self, reason: String, code: u64) -> Result<()>;

    fn terminated(&self) -> impl Future<Output = Error> + Send;
}

/// The local QUIC endpoint role, fixed for the lifetime of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
