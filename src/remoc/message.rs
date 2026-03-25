//! Remote forwarding of message-level streams via `remoc` RTC.
//!
//! Parallel to [`super::quic`] which bridges raw QUIC streams, this module
//! bridges **message-level** streams ([`ReadMessageStream`] / [`WriteMessageStream`])
//! that carry HTTP/3 DATA frame semantics and use [`MessageStreamError`] for their
//! data path. The QUIC-level control operations (`StopStream`, `CancelStream`,
//! `GetStreamId`) still use [`quic::StreamError`].
//!
//! # Public API
//!
//! ## RTC client handles (serializable, sendable over the wire)
//!
//! - [`MessageReadStreamClient`]
//! - [`MessageWriteStreamClient`]
//!
//! ## Serve functions (create server+client pair from a real stream)
//!
//! - [`serve_message_read_stream`]
//! - [`serve_message_write_stream`]
//!
//! ## Conversion methods (reconstruct poll-based streams from clients)
//!
//! - [`MessageReadStreamClient::into_message_stream`]
//! - [`MessageReadStreamClient::into_boxed_message_stream`]
//! - [`MessageReadStreamClient::into_box_reader`]
//! - [`MessageWriteStreamClient::into_message_stream`]
//! - [`MessageWriteStreamClient::into_boxed_message_stream`]
//! - [`MessageWriteStreamClient::into_box_writer`]

mod stream;

pub use self::stream::{
    MessageReadStreamClient, MessageReadStreamReqReceiver, MessageReadStreamServer,
    MessageReadStreamServerRefMut, MessageReadStreamServerSharedMut, MessageWriteStreamClient,
    MessageWriteStreamReqReceiver, MessageWriteStreamServer, MessageWriteStreamServerRefMut,
    MessageWriteStreamServerSharedMut, serve_message_read_stream, serve_message_write_stream,
};
