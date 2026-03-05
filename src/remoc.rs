//! Remote forwarding of `quic` traits via `remoc` RTC.
//!
//! This module provides remote-capable versions of all traits in [`crate::quic`],
//! allowing QUIC connections, streams, and agent operations to be transparently
//! forwarded over any `remoc`-compatible transport.

mod error;
mod serde_types;
pub mod agent;
pub mod stream;
pub mod connection;
pub mod connect;
pub mod listen;

pub use error::RemoteError;
pub use serde_types::*;
pub use agent::{
    RemoteLocalAgent, RemoteLocalAgentClient,
    CachedRemoteLocalAgent,
    RemoteRemoteAgent, RemoteRemoteAgentClient,
    CachedRemoteRemoteAgent,
};
pub use stream::{
    RemoteRead, RemoteReadClient,
    RemoteReadStream,
    RemoteWrite, RemoteWriteClient,
    RemoteWriteStream,
};
pub use connection::{
    RemoteConnection, RemoteConnectionClient,
    RemoteConnectionWrapper,
};
pub use connect::{RemoteConnect, RemoteConnectClient, RemoteConnectWrapper};
pub use listen::{RemoteListen, RemoteListenClient, RemoteListenWrapper};
