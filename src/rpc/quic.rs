//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module exposes raw remoc-generated RTC client and server constructor
//! families as the public API for the QUIC bridge.
//!
//! Any type implementing [`quic::Connection`] automatically implements the RTC
//! [`Connection`] trait via a blanket impl. On the client side,
//! [`RemoteConnection`] wraps a [`ConnectionClient`] and implements
//! [`quic::Connection`] so that remote connections can be used transparently
//! with the h3x protocol stack.
//!
//! The same blanket-plus-wrapper pattern applies to [`Connect`]/[`RemoteConnector`]
//! and [`Listen`]/[`RemoteListener`].
//!
//! # Public API
//!
//! ## Raw RTC client handles
//!
//! These are the remoc-generated serializable client types. They are sent over
//! the wire and used to make RPC calls to the remote side.
//!
//! - [`ConnectionClient`] — RTC client for a remote QUIC connection
//! - [`ReadStreamClient`] — RTC client for a remote readable QUIC stream
//! - [`WriteStreamClient`] — RTC client for a remote writable QUIC stream
//! - [`ConnectClient`] — RTC client for a remote QUIC connector
//! - [`ListenClient`] — RTC client for a remote QUIC listener
//!
//! ## Client-side wrappers
//!
//! - [`RemoteConnection`] — wraps [`ConnectionClient`], implements [`quic::Connection`]
//! - [`RemoteConnector`] — wraps [`ConnectClient`], implements [`quic::Connect`]
//! - [`RemoteListener`] — wraps [`ListenClient`], implements [`quic::Listen`]
//!
//! ## Conversion methods
//!
//! - [`ConnectionClient::into_quic`] — convert into a [`RemoteConnection`]
//! - [`ConnectClient::into_quic`] — convert into a [`RemoteConnector`]
//! - [`ListenClient::into_quic`] — convert into a [`RemoteListener`]
//! - [`ReadStreamClient::into_quic`] — convert into a `quic::ReadStream`
//! - [`ReadStreamClient::into_boxed_quic`] — convert into a boxed reader adapter
//! - [`WriteStreamClient::into_quic`] — convert into a `quic::WriteStream`
//! - [`WriteStreamClient::into_boxed_quic`] — convert into a boxed writer adapter

mod agent;
mod connect;
mod connection;
mod error;
mod listen;
pub(crate) mod serde_types;
mod stream;

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
        ConnectClient, ConnectError, ConnectReqReceiver, ConnectServer, ConnectServerRef,
        ConnectServerRefMut, ConnectServerShared, ConnectServerSharedMut, RemoteConnector,
    },
    connection::{
        ConnectionClient, ConnectionReqReceiver, ConnectionServer, ConnectionServerRef,
        ConnectionServerRefMut, ConnectionServerShared, ConnectionServerSharedMut,
        RemoteConnection,
    },
    listen::{
        ListenClient, ListenError, ListenReqReceiver, ListenServer, ListenServerRefMut,
        ListenServerSharedMut, RemoteListener,
    },
    stream::{
        ReadStreamClient, ReadStreamReqReceiver, ReadStreamServer, ReadStreamServerRefMut,
        ReadStreamServerSharedMut, WriteStreamClient, WriteStreamReqReceiver, WriteStreamServer,
        WriteStreamServerRefMut, WriteStreamServerSharedMut,
    },
};
