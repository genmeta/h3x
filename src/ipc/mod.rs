//! Inter-process communication for cross-process QUIC forwarding.
//!
//! This module combines the pipe data plane with remoc RPC control plane
//! to provide a complete IPC solution for multi-process QUIC architectures.
//!
//! # Submodules
//!
//! - [`capability`] — Adapters bridging real QUIC connections to IPC.
//! - [`pipe`] — Per-stream Unix socketpair framing (PULL/PUSH/STOP/CANCEL).
//! - [`rpc`] — IPC-specific RPC traits (IpcListen, IpcConnect, IpcConnection).
//! - [`transport`] — FD passing and multiplexed channels (MuxChannel, FdChannel).

pub mod capability;
pub mod pipe;
pub mod rpc;
pub mod transport;
