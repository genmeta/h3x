//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module provides remote-capable versions of all traits in [`crate::quic`],
//! allowing QUIC connections, streams, and agent operations to be transparently
//! forwarded over any `remoc`-compatible transport.

mod agent;
mod connect;
mod connection;
mod error;
mod listen;
mod serde_types;
mod stream;
