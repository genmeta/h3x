//! Shared RPC/IPC stream frame bridge internals.
//!
//! This module is the single home for typed stream command/event drivers used
//! by RPC, IPC, and WebTransport IPC stream forwarding.

pub(crate) mod drain;
pub(crate) mod error;
pub(crate) mod frame;
pub(crate) mod hypervisor;
pub(crate) mod io;
pub(crate) mod reader;
pub(crate) mod remoc;
pub(crate) mod writer;

#[cfg(test)]
pub(crate) mod test_io;
