//! Remote forwarding of message-level streams via `remoc` RTC.
//!
//! Parallel to [`super::quic`] which bridges raw QUIC streams, this module
//! bridges **message-level** streams ([`ReadMessageStream`] / [`WriteMessageStream`])
//! that carry HTTP/3 DATA frame semantics and use [`MessageStreamError`] for their
//! data path. The QUIC-level control operations (`StopStream`, `CancelStream`,
//! `GetStreamId`) still use [`quic::StreamError`].
//!
//! Any type implementing the original [`ReadMessageStream`] / [`WriteMessageStream`]
//! traits automatically implements the RTC traits via blanket impls.
//!
//! # Public API
//!
//! ## RTC client handles (serializable, sendable over the wire)
//!
//! - [`ReadMessageStreamClient`]
//! - [`WriteMessageStreamClient`]
//!
//! ## Conversion methods (reconstruct poll-based streams from clients)
//!
//! - [`ReadMessageStreamClient::into_message_stream`]
//! - [`ReadMessageStreamClient::into_boxed_message_stream`]
//! - [`ReadMessageStreamClient::into_box_reader`]
//! - [`WriteMessageStreamClient::into_message_stream`]
//! - [`WriteMessageStreamClient::into_boxed_message_stream`]
//! - [`WriteMessageStreamClient::into_box_writer`]

mod stream;

pub use self::stream::{
    ReadMessageStreamClient, ReadMessageStreamReqReceiver, ReadMessageStreamServer,
    ReadMessageStreamServerRefMut, ReadMessageStreamServerSharedMut, WriteMessageStreamClient,
    WriteMessageStreamReqReceiver, WriteMessageStreamServer, WriteMessageStreamServerRefMut,
    WriteMessageStreamServerSharedMut,
};
