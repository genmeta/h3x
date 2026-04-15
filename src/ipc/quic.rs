//! IPC forwarding of QUIC primitives via RPC + per-stream socketpairs.
//!
//! Parallel to [`crate::rpc::quic`] which bridges QUIC operations via pure
//! RPC, this module bridges them over IPC with dedicated Unix socketpairs
//! for stream-level data, avoiding per-read/write serialization overhead.
//!
//! # Public API
//!
//! ## RTC traits (define the IPC RPC interface)
//!
//! - [`IpcConnection`] — connection-level stream management
//! - [`IpcConnect`] — connector capability (initiate outgoing connections)
//! - [`IpcListen`] — listener capability (accept incoming connections)
//!
//! ## Server-side adapters (wrap real QUIC types, implement RTC traits)
//!
//! - [`ConnectionAdapter`] — wraps `quic::Connection`, implements [`IpcConnection`]
//! - [`ConnectAdapter`] — wraps `quic::Connect`, implements [`IpcConnect`]
//! - [`ListenAdapter`] — wraps `quic::Listen`, implements [`IpcListen`]
//!
//! ## Client-side wrappers (wrap RTC clients, implement `quic::*` traits)
//!
//! - [`IpcConnectionHandle`] — wraps [`IpcConnectionClient`], implements `quic::Connection`
//! - [`IpcConnector`] — wraps [`IpcConnectClient`], implements `quic::Connect`
//! - [`IpcListener`] — wraps [`IpcListenClient`], implements `quic::Listen`
//!
//! ## Stream types (IPC read/write stream backed by Unix socketpairs)
//!
//! - [`IpcReadStream`] — implements `quic::ReadStream`
//! - [`IpcWriteStream`] — implements `quic::WriteStream`
//!
//! ## Bootstrap
//!
//! - [`ConnectionBootstrap`] — one-shot value sent when a connection is established
//!
//! ## Bridge helpers
//!
//! - [`bridge_reader`] — forward QUIC ReadStream → IpcWriteStream
//! - [`bridge_writer`] — forward IpcReadStream → QUIC WriteStream

pub(crate) mod connection;
pub(crate) mod connector;
pub(crate) mod listener;
mod stream;

#[cfg(test)]
mod tests;

pub use self::{
    connection::{
        ConnectionAdapter, ConnectionBootstrap, IpcConnection, IpcConnectionClient,
        IpcConnectionHandle, IpcConnectionReqReceiver, IpcConnectionServer,
        IpcConnectionServerShared, IpcConnectionServerSharedMut, bridge_reader, bridge_writer,
    },
    connector::{
        ConnectAdapter, ConnectorError, IpcConnect, IpcConnectClient, IpcConnectReqReceiver,
        IpcConnectServer, IpcConnectServerShared, IpcConnector,
    },
    listener::{
        IpcListenClient, IpcListenError, IpcListenReqReceiver, IpcListenServer,
        IpcListenServerSharedMut, IpcListener, ListenAdapter,
    },
    stream::{IpcReadStream, IpcWriteStream},
};
