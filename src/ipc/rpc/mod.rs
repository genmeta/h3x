//! IPC-specific remoc RTC trait definitions.
//!
//! Unlike [`crate::rpc::quic`] traits which return remoc Client objects (bound
//! to the same ChMux), these traits return [`VarInt`] FD-registry IDs.  The
//! caller then retrieves the corresponding FDs via
//! [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds) and
//! establishes a new, independent remoc connection on the received
//! [`MuxChannel`](crate::ipc::transport::MuxChannel).
//!
//! This design enables hierarchical capability passing: each logical level
//! (ControlPlane → Listener/Connector → Connection → Stream) gets its own
//! MuxChannel, preventing all traffic from being funnelled through a single
//! ChMux bottleneck.

pub mod connect;
pub mod connection;
pub mod listen;

pub use connect::{IpcConnectClient, IpcConnectServer, IpcConnectServerShared};
pub use connection::{IpcConnectionClient, IpcConnectionServer, IpcConnectionServerShared};
pub use listen::{IpcListenClient, IpcListenServer, IpcListenServerShared};
