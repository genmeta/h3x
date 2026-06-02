//! Named handle types for IPC stream operations.
//!
//! These types replace the raw `VarInt` stream IDs returned by
//! [`IpcConnection`](super::quic::IpcConnection) methods, giving each field
//! a descriptive name.

use serde::{Deserialize, Serialize};

use crate::varint::VarInt;

/// Handle returned by IPC `open_bi` / `accept_bi` operations.
///
/// Contains the underlying QUIC stream ID. The FD transfer ID is chosen by
/// the receiver and passed into the request before this handle is returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcBiHandle {
    /// The underlying QUIC stream ID.
    pub stream_id: VarInt,
}

/// Handle returned by IPC `open_uni` / `accept_uni` operations.
///
/// Contains the underlying QUIC stream ID. The FD transfer ID is chosen by
/// the receiver and passed into the request before this handle is returned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcUniHandle {
    /// The underlying QUIC stream ID.
    pub stream_id: VarInt,
}
