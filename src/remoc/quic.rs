//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module provides remote-capable versions of all traits in [`crate::quic`],
//! allowing QUIC connections, streams, and agent operations to be transparently
//! forwarded over any `remoc`-compatible transport.
//!
//! # Architecture
//!
//! The bridging is bidirectional:
//!
//! - **Client-side (Remote → Standard)**: `Remote*` wrappers take remoc RTC clients
//!   and implement standard `quic::*` traits, allowing remote services to be used
//!   as if they were local.
//!
//! - **Server-side (Standard → Remote)**: `Local*` wrappers take objects implementing
//!   standard `quic::*` traits and implement remoc RTC traits, allowing local
//!   implementations to be served over remoc.
//!
//! # Public API
//!
//! Only the bridging structs are re-exported. The internal remoc RTC traits
//! are implementation details and not part of the public API.
//!
//! ## Client-side (consuming remote services)
//!
//! - [`RemoteQuicConnection`] — implements `quic::Connection` via RTC
//! - [`RemoteQuicListener`] — implements `quic::Listen` via RTC
//! - [`RemoteQuicConnector`] — implements `quic::Connect` via RTC
//! - [`RemoteReadStream`] — wraps `ReadStreamClient`, convert via [`into_quic`](RemoteReadStream::into_quic)
//! - [`RemoteWriteStream`] — wraps `WriteStreamClient`, convert via [`into_quic`](RemoteWriteStream::into_quic)
//! ## Server-side (serving local implementations)
//!
//! - [`LocalQuicConnection`] — serves a `quic::Connection` over RTC
//! - [`LocalQuicListener`] — serves a `quic::Listen` over RTC
//! - [`LocalQuicConnector`] — serves a `quic::Connect` over RTC
//! - [`LocalReadStream`] — serves a `quic::ReadStream` over RTC
//! - [`LocalWriteStream`] — serves a `quic::WriteStream` over RTC
//! ## Conversion
//!
//! Each `Local*` type provides an `into_remote(self)` method that converts it
//! into the corresponding `Remote*` type plus a `Future` that drives the RTC server.
//! The `Remote*` types implement `Serialize + Deserialize` for sending over the wire.

mod agent;
mod connect;
mod connection;
mod error;
mod listen;
mod serde_types;
mod stream;
mod task_set;

// Client-side: Remote → Standard quic traits
// Server-side: Standard quic traits → Remote
pub use self::{
    connect::{LocalQuicConnector, RemoteQuicConnector},
    connection::{LocalQuicConnection, RemoteQuicConnection},
    listen::{LocalQuicListener, RemoteQuicListener},
    stream::{LocalReadStream, LocalWriteStream, RemoteReadStream, RemoteWriteStream},
};
