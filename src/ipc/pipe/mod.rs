//! Per-stream pipe IPC for cross-process QUIC stream forwarding.
//!
//! This module provides high-performance alternatives to the remoc RTC bridge
//! for stream data transfer.  Instead of serializing every `read()`/`write()`
//! through remoc's chmux multiplexer, each QUIC stream is carried over an
//! independent `SOCK_STREAM` Unix socketpair with a minimal inline framing
//! protocol.
//!
//! # Modules
//!
//! - [`codec`] — Frame types and `tokio_util::codec` implementation.
//! - [`reader`] — [`PipeReader`] implementing [`quic::ReadStream`](crate::quic::ReadStream).
//! - [`writer`] — [`PipeWriter`] implementing [`quic::WriteStream`](crate::quic::WriteStream).

pub mod codec;
pub mod reader;
mod state;
pub mod writer;

pub use codec::{Frame, PipeCodec};
pub use reader::PipeReader;
pub use writer::PipeWriter;
