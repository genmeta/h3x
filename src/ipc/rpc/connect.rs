//! IPC RTC trait for connector capability (initiate outgoing connections).
//!
//! The server side calls [`quic::Connect::connect`], creates a new
//! [`MuxChannel`](crate::ipc::transport::MuxChannel) pair, queues the remote
//! end's FD via the parent [`FdSender`](crate::ipc::transport::FdSender), and
//! returns the [`VarInt`] registry ID.

use crate::{quic::ConnectionError, rpc::quic::serde_types::SerdeAuthority, varint::VarInt};

/// Remote trait for IPC connector capability.
///
/// Each successful [`connect`](IpcConnect::connect) returns a [`VarInt`] ID
/// that the caller can pass to
/// [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds) to
/// obtain the [`MuxChannel`](crate::ipc::transport::MuxChannel) FD for the
/// new connection.
#[remoc::rtc::remote]
pub trait IpcConnect: Send + Sync {
    /// Connect to a remote server.
    ///
    /// Returns the FD-registry ID for the new connection's MuxChannel.
    async fn connect(&self, server: SerdeAuthority) -> Result<VarInt, ConnectionError>;
}
