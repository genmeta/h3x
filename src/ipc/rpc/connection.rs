//! IPC RTC trait for connection-level stream management.
//!
//! The server side calls the underlying [`quic::ManageStream`] methods, creates
//! per-stream socketpairs, queues the FDs via the connection-level
//! [`FdSender`](crate::ipc::transport::FdSender), and returns a `(VarInt, VarInt)`
//! pair: `(fd_registry_id, stream_id)`.
//!
//! The `fd_registry_id` is used by the client to retrieve the socketpair FD(s)
//! via [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds).
//! The `stream_id` is the underlying QUIC stream ID, passed eagerly so that
//! [`PipeReader`](crate::ipc::pipe::PipeReader) /
//! [`PipeWriter`](crate::ipc::pipe::PipeWriter) can return it synchronously
//! from [`GetStreamId`](crate::quic::GetStreamId).
//!
//! # FD semantics
//!
//! - **`open_bi` / `accept_bi`**: 2 FDs are queued (2 independent socketpairs).
//!   The first FD carries the reader-side pipe (server's PipeWriter ↔ client's
//!   PipeReader), the second carries the writer-side pipe (server's PipeReader ↔
//!   client's PipeWriter).
//!
//! - **`open_uni` / `accept_uni`**: 1 FD is queued (a single socketpair).

use std::borrow::Cow;

use crate::{
    error::Code,
    quic::ConnectionError,
    rpc::quic::{LocalAgentClient, RemoteAgentClient},
    varint::VarInt,
};

/// Remote trait for IPC connection-level stream management.
///
/// Each stream-opening method returns a `(VarInt, VarInt)` pair:
/// - The first element is the FD-registry ID for
///   [`FdRegistry::wait_fds`](crate::ipc::transport::FdRegistry::wait_fds).
/// - The second element is the underlying QUIC stream ID.
///
/// Agent and lifecycle methods mirror [`crate::rpc::quic::Connection`] and
/// are forwarded over the same remoc channel — only bulk stream data travels
/// through dedicated socketpairs.
#[remoc::rtc::remote]
pub trait IpcConnection: Send + Sync {
    /// Open a bidirectional stream.
    ///
    /// Returns `(fd_registry_id, stream_id)`. The caller retrieves **2 FDs**
    /// from the registry: one for the read pipe and one for the write pipe.
    async fn open_bi(&self) -> Result<(VarInt, VarInt), ConnectionError>;

    /// Accept an incoming bidirectional stream.
    ///
    /// Returns `(fd_registry_id, stream_id)`. The caller retrieves **2 FDs**.
    async fn accept_bi(&self) -> Result<(VarInt, VarInt), ConnectionError>;

    /// Open a unidirectional (send-only) stream.
    ///
    /// Returns `(fd_registry_id, stream_id)`. The caller retrieves **1 FD**.
    async fn open_uni(&self) -> Result<(VarInt, VarInt), ConnectionError>;

    /// Accept an incoming unidirectional (receive-only) stream.
    ///
    /// Returns `(fd_registry_id, stream_id)`. The caller retrieves **1 FD**.
    async fn accept_uni(&self) -> Result<(VarInt, VarInt), ConnectionError>;

    /// Obtain the local agent (signing / identity) handle, if available.
    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, ConnectionError>;

    /// Obtain the remote agent (verification) handle, if available.
    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, ConnectionError>;

    /// Close the connection with an application error code and reason.
    async fn close(&self, code: Code, reason: Cow<'static, str>) -> Result<(), ConnectionError>;

    /// Wait until the connection is closed, returning the terminal error.
    async fn closed(&self) -> Result<ConnectionError, ConnectionError>;
}
