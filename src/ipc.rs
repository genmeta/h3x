//! Inter-process communication for cross-process QUIC forwarding.
//!
//! This module combines per-stream Unix socketpairs (data plane) with RPC
//! control channels to provide a complete IPC solution for multi-process
//! QUIC architectures.
//!
//! # Submodules
//!
//! - [`quic`] — RTC traits, server-side adapters, client-side wrappers, and
//!   per-stream IPC read/write types.
//! - [`transport`] — Multiplexed channel (MuxChannel) for RPC control and FD passing.

pub mod quic;
pub mod transport;
