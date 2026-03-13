//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module exposes the raw remoc-generated RTC `*Client` and `*ServerShared*`
//! types as the public API for the QUIC bridge.
//!
//! Local QUIC implementations are served by constructing the exported server types
//! and spawning their `serve(true)` futures. Remote stream clients can be turned
//! into poll-based `quic::ReadStream` / `quic::WriteStream` values through the
//! explicit conversion helpers exported here.
//!
//! # Public API
//!
//! ## Raw RTC client handles
//!
//! These are the remoc-generated serializable client types. They are sent over
//! the wire and used to make RPC calls to the remote side. Each is
//! `Serialize + Deserialize`. The stream clients (`ReadStreamClient`,
//! `WriteStreamClient`) are **not** `Clone` because their RTC traits have
//! `&mut self` methods; the connection/connector/listener clients are `Clone`.
//!
//! - [`ConnectionClient`] — RTC client for a remote QUIC connection
//! - [`ReadStreamClient`] — RTC client for a remote readable QUIC stream
//! - [`WriteStreamClient`] — RTC client for a remote writable QUIC stream
//! - [`RemoteConnectClient`] — RTC client for a remote QUIC connector
//! - [`ListenClient`] — RTC client for a remote QUIC listener
//!
//! ## Raw RTC server constructors
//!
//! These are the remoc-generated server types. Call `::new(Arc<...>, buffer)` to
//! obtain a `(Server, Client)` pair, then spawn the server's `serve(true)` future.
//!
//! - [`ConnectionServerShared`] — serves a `Connection` RTC impl
//! - [`ReadStreamServerSharedMut`] — serves a `ReadStream` RTC impl
//! - [`WriteStreamServerSharedMut`] — serves a `WriteStream` RTC impl
//! - [`RemoteConnectServerShared`] — serves a `RemoteConnect` RTC impl
//! - [`ListenServerShared`] — serves a `Listen` RTC impl
//!
//! ## Conversion helpers
//!
//! Low-level async helpers for constructing poll-based `quic::ReadStream` /
//! `quic::WriteStream` implementations directly from raw RTC clients:
//!
//! - [`new_remote_read_stream`] — convert a `ReadStreamClient` into a `quic::ReadStream`
//! - [`new_remote_write_stream`] — convert a `WriteStreamClient` into a `quic::WriteStream`
//! - [`read_stream_client_into_quic`] — convert a `ReadStreamClient` into a boxed
//!   `quic::ReadStream` future adapter
//! - [`write_stream_client_into_quic`] — convert a `WriteStreamClient` into a boxed
//!   `quic::WriteStream` future adapter
//! - [`local_agent_from_client`] — eagerly build the cached local-agent bridge
//! - [`remote_agent_from_client`] — eagerly build the cached remote-agent bridge

mod agent;
mod connect;
mod connection;
mod error;
mod listen;
mod serde_types;
mod stream;
mod task_set;

// Raw remoc-generated RTC client types (serializable, sendable over the wire)
pub use self::{
    agent::{
        LocalAgentClient, LocalAgentServerShared, RemoteAgentClient, RemoteAgentServerShared,
        local_agent_from_client, remote_agent_from_client,
    },
    connect::{ConnectError, RemoteConnectClient},
    connection::ConnectionClient,
    listen::{ListenClient, ListenError},
    stream::{
        ReadStreamClient, WriteStreamClient, new_remote_read_stream, new_remote_write_stream,
        read_stream_client_into_quic, write_stream_client_into_quic,
    },
};
// Raw remoc-generated RTC server constructor types
pub use self::{
    connect::RemoteConnectServerShared,
    connection::ConnectionServerShared,
    listen::ListenServerShared,
    stream::{ReadStreamServerSharedMut, WriteStreamServerSharedMut},
};
