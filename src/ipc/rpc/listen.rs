//! IPC RTC trait for listener capability (accept incoming connections).
//!
//! The server side calls [`quic::Listen::accept`], creates a new
//! [`MuxChannel`](crate::ipc::transport::MuxChannel) pair, queues the remote
//! end's FD via the parent [`FdSender`](crate::ipc::transport::FdSender), and
//! returns the [`VarInt`] registry ID so the client can retrieve the FD.

use crate::{quic::ConnectionError, varint::VarInt};

/// Remote trait for IPC listener capability.
///
/// Each successful [`accept`](IpcListen::accept) returns a [`VarInt`] ID that
/// the caller can pass to
/// [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds) to
/// obtain the [`MuxChannel`](crate::ipc::transport::MuxChannel) FD for the
/// new connection.
#[remoc::rtc::remote]
pub trait IpcListen: Send + Sync {
    /// Accept an incoming connection.
    ///
    /// Returns the FD-registry ID for the new connection's MuxChannel.
    async fn accept(&self) -> Result<VarInt, ConnectionError>;

    /// Gracefully shut down the listener.
    async fn shutdown(&self) -> Result<(), ConnectionError>;
}
