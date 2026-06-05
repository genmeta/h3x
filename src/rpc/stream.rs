//! Shared RPC/IPC stream frame bridge internals.
//!
//! This module replaces the old per-method `rpc::bridge` state machine. It is
//! the single home for typed stream command/event drivers used by RPC, IPC,
//! and WebTransport IPC stream forwarding.

pub(crate) mod frame;
