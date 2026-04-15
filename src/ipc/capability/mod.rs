//! Capability adapters bridging real QUIC connections to IPC.
//!
//! Server-side adapters wrap a concrete [`quic::Connection`] (or
//! [`quic::Listen`] / [`quic::Connect`]) and implement the IPC RPC traits.
//! Client-side handles wrap an IPC RPC client and implement the corresponding
//! `quic::*` traits, so downstream code sees a transparent QUIC-like interface
//! over Unix sockets.

pub mod connection;
pub mod connector;
pub mod listener;

#[cfg(test)]
mod tests;
