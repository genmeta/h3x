//! Named handle types for IPC stream operations.
//!
//! These types replace the raw `(VarInt, VarInt)` tuples returned by
//! [`IpcConnection`](super::quic::IpcConnection) methods, giving each field
//! a descriptive name.

use serde::{Deserialize, Serialize};

use crate::varint::VarInt;

/// Handle returned by IPC `open_bi` / `accept_bi` operations.
///
/// Contains the FD-registry ID for retrieving 2 socketpair FDs (one per
/// direction) and the underlying QUIC stream ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcBiHandle {
    /// FD-registry ID for [`FdRegistry::wait_fds`](super::transport::FdRegistry::wait_fds).
    pub fd_id: VarInt,
    /// The underlying QUIC stream ID.
    pub stream_id: VarInt,
}

/// Handle returned by IPC `open_uni` / `accept_uni` operations.
///
/// Contains the FD-registry ID for retrieving 1 socketpair FD and the
/// underlying QUIC stream ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcUniHandle {
    /// FD-registry ID for [`FdRegistry::wait_fds`](super::transport::FdRegistry::wait_fds).
    pub fd_id: VarInt,
    /// The underlying QUIC stream ID.
    pub stream_id: VarInt,
}
