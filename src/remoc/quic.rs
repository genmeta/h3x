//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module exposes raw remoc-generated RTC client and server constructor
//! families as the public API for the QUIC bridge.
//!
//! Local QUIC implementations are served by constructing the exported server types
//! and spawning their `serve(true)` futures. Remote stream clients can be turned
//! into poll-based `quic::ReadStream` / `quic::WriteStream` values through
//! conversion methods on the generated client types.
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
//! Exported server families include the generated `Server`, `ServerRef`,
//! `ServerRefMut`, `ServerShared`, `ServerSharedMut`, and `ReqReceiver`
//! variants when available for the trait receiver shape.
//!
//! ## Conversion methods
//!
//! Raw RTC client handles expose inherent conversion methods for constructing
//! poll-based `quic::ReadStream` / `quic::WriteStream` implementations directly
//! from the generated clients:
//!
//! - [`ReadStreamClient::into_quic`] — convert into a `quic::ReadStream`
//! - [`ReadStreamClient::into_boxed_quic`] — convert into a boxed reader adapter
//! - [`WriteStreamClient::into_quic`] — convert into a `quic::WriteStream`
//! - [`WriteStreamClient::into_boxed_quic`] — convert into a boxed writer adapter
//! - [`CachedLocalAgent::from_client`] — eagerly build the cached local-agent bridge
//! - [`CachedRemoteAgent::from_client`] — eagerly build the cached remote-agent bridge

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
        CachedLocalAgent, CachedRemoteAgent, LocalAgentClient, LocalAgentReqReceiver,
        LocalAgentServer, LocalAgentServerRef, LocalAgentServerRefMut, LocalAgentServerShared,
        LocalAgentServerSharedMut, RemoteAgentClient, RemoteAgentReqReceiver, RemoteAgentServer,
        RemoteAgentServerRef, RemoteAgentServerRefMut, RemoteAgentServerShared,
        RemoteAgentServerSharedMut,
    },
    connect::{
        ConnectError, RemoteConnectClient, RemoteConnectReqReceiver, RemoteConnectServer,
        RemoteConnectServerRef, RemoteConnectServerRefMut, RemoteConnectServerShared,
        RemoteConnectServerSharedMut,
    },
    connection::{
        ConnectionClient, ConnectionReqReceiver, ConnectionServer, ConnectionServerRef,
        ConnectionServerRefMut, ConnectionServerShared, ConnectionServerSharedMut,
    },
    listen::{
        ListenClient, ListenError, ListenReqReceiver, ListenServer, ListenServerRef,
        ListenServerRefMut, ListenServerShared, ListenServerSharedMut,
    },
    stream::{
        ReadStreamClient, ReadStreamReqReceiver, ReadStreamServer, ReadStreamServerRefMut,
        ReadStreamServerSharedMut, WriteStreamClient, WriteStreamReqReceiver, WriteStreamServer,
        WriteStreamServerRefMut, WriteStreamServerSharedMut,
    },
};
