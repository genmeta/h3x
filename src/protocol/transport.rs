use std::{future::Future, pin::Pin};

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
    type Recv: AsyncRead + Unpin + Send + 'static;
    type Send: AsyncWrite + Unpin + Send + 'static;

    fn role(&self) -> Role;

    fn stop(recv: &mut Self::Recv, error_code: u64);

    fn cancel(send: &mut Self::Send, error_code: u64);

    /// Optionally observe peer STOP_SENDING while an upload waits for body data.
    /// Return an owned notification future. Without it, write/shutdown errors still
    /// report peer stops, but an idle upload cannot observe them immediately.
    fn send_stopped(
        _send: &Self::Send,
    ) -> Option<Pin<Box<dyn Future<Output = Error> + Send + 'static>>> {
        None
    }

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
