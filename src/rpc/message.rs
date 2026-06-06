//! Message-level RPC stream facades over typed stream frame channels.
//!
//! The RPC runtime transports stream data/control through the same typed
//! [`ReadFrameChannels`] and [`WriteFrameChannels`] used by QUIC-level RPC
//! stream forwarding. This module adds message-level conversion methods on
//! those channel bundles: data-path QUIC stream errors are mapped to
//! [`MessageStreamError`](crate::dhttp::message::MessageStreamError), while
//! QUIC control operations (`StopStream`, `ResetStream`, `GetStreamId`) keep
//! returning [`quic::StreamError`](crate::quic::StreamError).
//!
//! # Conversion methods
//!
//! - `ReadFrameChannels::into_message_stream`
//! - `ReadFrameChannels::into_boxed_message_stream`
//! - `ReadFrameChannels::into_box_reader`
//! - `WriteFrameChannels::into_message_stream`
//! - `WriteFrameChannels::into_boxed_message_stream`
//! - `WriteFrameChannels::into_box_writer`

mod stream;

pub use super::quic::{ReadFrameChannels, WriteFrameChannels};
