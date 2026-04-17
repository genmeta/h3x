//! WebTransport session handle.
//!
//! A [`WebTransportSession`] is returned by
//! [`WebTransportProtocol::register`](super::WebTransportProtocol::register) and
//! provides the application-facing API for opening and accepting streams within a
//! WebTransport session.
//!
//! Dropping the session automatically unregisters it from the protocol registry.

use std::{fmt, sync::Arc};

use snafu::ResultExt;
use tokio::{io::AsyncWriteExt, sync::mpsc};

use super::{
    error::{
        Closed, DatagramError, OpenSnafu, OpenStreamError, UnsupportedSnafu, WriteHeaderSnafu,
    },
    protocol::Registry,
};
use crate::{
    codec::{BoxReadStream, BoxWriteStream, EncodeExt, SinkWriter},
    quic::{self},
    varint::VarInt,
};

// ============================================================================
// Stream type aliases
// ============================================================================

/// A routed bidirectional stream (reader + writer) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedBiStream = (BoxReadStream, BoxWriteStream);

/// A routed unidirectional stream (reader only) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedUniStream = BoxReadStream;

// ============================================================================
// WebTransportSession
// ============================================================================

/// Handle for a registered WebTransport session.
///
/// Provides stream management for a single session: accepting streams routed
/// by the protocol layer and opening new streams to the remote peer.
///
/// Dropping the handle automatically unregisters the session from the protocol
/// registry.
pub struct WebTransportSession {
    session_id: VarInt,
    bidi_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedBiStream>>,
    uni_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedUniStream>>,
    conn: Arc<dyn quic::DynManageStream>,
    registry: Registry,
}

impl WebTransportSession {
    pub(super) fn new(
        session_id: VarInt,
        bidi_rx: mpsc::Receiver<RoutedBiStream>,
        uni_rx: mpsc::Receiver<RoutedUniStream>,
        conn: Arc<dyn quic::DynManageStream>,
        registry: Registry,
    ) -> Self {
        Self {
            session_id,
            bidi_rx: tokio::sync::Mutex::new(bidi_rx),
            uni_rx: tokio::sync::Mutex::new(uni_rx),
            conn,
            registry,
        }
    }

    /// The session ID (QUIC stream ID of the CONNECT stream that established
    /// this session).
    pub fn session_id(&self) -> VarInt {
        self.session_id
    }

    /// Open a new bidirectional stream within this session.
    ///
    /// Writes the WT bidi signal value (`0x41`) and the session ID as a
    /// routing header, then returns the raw stream pair positioned after the
    /// header.
    pub async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
        let (reader, writer) = self.conn.open_bi().await.context(OpenSnafu)?;
        let writer = write_header(writer, super::WT_BIDI_SIGNAL, self.session_id).await?;
        Ok((reader, writer))
    }

    /// Open a new unidirectional stream within this session.
    ///
    /// Writes the WT uni signal value (`0x54`) and the session ID as a
    /// routing header, then returns the write half positioned after the header.
    pub async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
        let writer = self.conn.open_uni().await.context(OpenSnafu)?;
        let writer = write_header(writer, super::WT_UNI_SIGNAL, self.session_id).await?;
        Ok(writer)
    }

    /// Accept a bidirectional stream routed to this session by the protocol layer.
    ///
    /// Returns [`Closed`] when the session is closed and no more streams will arrive.
    pub async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), Closed> {
        self.bidi_rx.lock().await.recv().await.ok_or(Closed)
    }

    /// Accept a unidirectional stream routed to this session by the protocol layer.
    ///
    /// Returns [`Closed`] when the session is closed and no more streams will arrive.
    pub async fn accept_uni(&self) -> Result<BoxReadStream, Closed> {
        self.uni_rx.lock().await.recv().await.ok_or(Closed)
    }

    /// Send a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn send_datagram(&self, _data: &[u8]) -> Result<(), DatagramError> {
        UnsupportedSnafu.fail()
    }

    /// Receive a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, DatagramError> {
        UnsupportedSnafu.fail()
    }
}

// ============================================================================
// Header writing helper
// ============================================================================

/// Write the WebTransport stream routing header (signal + session_id) and flush.
async fn write_header(
    writer: BoxWriteStream,
    signal: VarInt,
    session_id: VarInt,
) -> Result<BoxWriteStream, OpenStreamError> {
    let mut codec_writer = SinkWriter::new(writer);
    codec_writer
        .encode_one(signal)
        .await
        .map_err(quic::StreamError::from)
        .context(WriteHeaderSnafu)?;
    codec_writer
        .encode_one(session_id)
        .await
        .map_err(quic::StreamError::from)
        .context(WriteHeaderSnafu)?;
    AsyncWriteExt::flush(&mut codec_writer)
        .await
        .map_err(quic::StreamError::from)
        .context(WriteHeaderSnafu)?;
    Ok(codec_writer.into_inner())
}

// ============================================================================
// Trait impls
// ============================================================================

impl fmt::Debug for WebTransportSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportSession")
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl Drop for WebTransportSession {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.registry.lock() {
            registry.remove(&self.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const _: () = {
        fn assert_send_sync<T: Send + Sync>() {}
        fn check() {
            assert_send_sync::<WebTransportSession>();
        }
    };
}
