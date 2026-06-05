//! Shared RPC/IPC stream frame bridge internals.
//!
//! This module is intended to replace the old per-method `rpc::bridge` state
//! machine. It is the single home for typed stream command/event drivers used
//! by RPC, IPC, and WebTransport IPC stream forwarding.

pub(crate) mod error;
pub(crate) mod frame;
pub(crate) mod io;

#[cfg(test)]
pub(crate) mod test_io;
