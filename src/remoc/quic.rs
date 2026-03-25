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
//! - [`RemoteConnectClient`] — RTC client for a remote QUIC connector
//! - [`ListenClient`] — RTC client for a remote QUIC listener
//!
//! ## Client-side wrappers
//!
//! - [`RemoteConnection`] — wraps [`ConnectionClient`], implements [`quic::Connection`]
//!
//! ## Conversion methods
//!
//! - [`ReadStreamClient::into_quic`] — convert into a `quic::ReadStream`
//! - [`ReadStreamClient::into_boxed_quic`] — convert into a boxed reader adapter
//! - [`WriteStreamClient::into_quic`] — convert into a `quic::WriteStream`
//! - [`WriteStreamClient::into_boxed_quic`] — convert into a boxed writer adapter

mod agent;
mod connect;
mod connection;
mod error;
mod listen;
mod serde_types;
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
        ConnectError, RemoteConnectClient, RemoteConnectReqReceiver, RemoteConnectServer,
        RemoteConnectServerRef, RemoteConnectServerRefMut, RemoteConnectServerShared,
        RemoteConnectServerSharedMut,
    },
    connection::{
        ConnectionClient, ConnectionReqReceiver, ConnectionServer, ConnectionServerRef,
        ConnectionServerRefMut, ConnectionServerShared, ConnectionServerSharedMut,
        RemoteConnection,
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
