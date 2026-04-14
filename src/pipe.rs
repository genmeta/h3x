//! Per-stream pipe IPC for cross-process QUIC stream forwarding.
//!
//! This module provides high-performance alternatives to the remoc RTC bridge
//! for stream data transfer.  Instead of serializing every `read()`/`write()`
//! through remoc's chmux multiplexer, each QUIC stream is carried over an
//! independent `SOCK_STREAM` Unix socketpair with a minimal inline framing
//! protocol.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Control plane (remoc RTC over stdin/stdout)                │
//! │    • Lifecycle (close / check / closed)                     │
//! │    • Agent (sign / verify)                                  │
//! │    • open_bi / accept_bi → returns stream_id                │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │  FD channel (SOCK_SEQPACKET + SCM_RIGHTS)                  │
//! │    • Passes per-stream socketpair FDs + stream_id metadata  │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Per-stream data pipe (SOCK_STREAM socketpair)              │
//! │    • DATA / STOP / CANCEL / CONN_CLOSED framing             │
//! │    • PipeReader  → impl ReadStream                          │
//! │    • PipeWriter  → impl WriteStream                         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Modules
//!
//! - [`codec`] — Frame types and `tokio_util::codec` implementation.
//! - [`reader`] — [`PipeReader`] implementing [`quic::ReadStream`].
//! - [`writer`] — [`PipeWriter`] implementing [`quic::WriteStream`].
//! - [`fd_channel`] — [`FdChannel`] for passing FDs over SEQPACKET.

pub mod codec;
pub mod fd_channel;
pub mod reader;
pub mod writer;

pub use codec::{Frame, PipeCodec};
pub use fd_channel::{FdChannel, RecvFdsError, SendFdsError};
pub use reader::PipeReader;
pub use writer::PipeWriter;
