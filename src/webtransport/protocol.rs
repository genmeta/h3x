//! WebTransport protocol layer for h3x stream dispatch.
//!
//! Integrates WebTransport into the h3x layered protocol architecture. The
//! protocol layer identifies incoming WebTransport streams by peeking for the
//! signal values (`0x41` for bidi, `0x54` for uni), then routes them to the
//! appropriate session based on session ID.
//!
//! # Stream identification
//!
//! The protocol layer consumes exactly two fields from each incoming stream:
//!
//! 1. The stream signal value ([`VarInt`])
//! 2. The session ID ([`StreamId`](crate::stream_id::StreamId))
//!
//! The session receives the stream positioned after these two fields.

use std::{fmt, sync::Arc};

use futures::future::BoxFuture;

use super::{
    error::RegisterSessionError,
    registry::{RegisteredSession, Registry},
};
use crate::{
    codec::{
        BoxReadStream, BoxWriteStream, DecodeExt, ErasedPeekableBiStream, ErasedPeekableUniStream,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    stream_id::StreamId,
    varint::VarInt,
};

// ============================================================================
// Constants
// ============================================================================

/// Extended CONNECT protocol token for WebTransport over HTTP/3.
pub const WEBTRANSPORT_H3: &str = "webtransport-h3";

/// Signal value for WebTransport bidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WEBTRANSPORT_BIDI_SIGNAL: VarInt = VarInt::from_u32(0x41);

/// Signal value for WebTransport unidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WEBTRANSPORT_UNI_SIGNAL: VarInt = VarInt::from_u32(0x54);

// ============================================================================
// WebTransportProtocol
// ============================================================================

/// WebTransport protocol layer for h3x.
///
/// Routes incoming QUIC streams to registered sessions by peeking the signal
/// value and session ID.
///
/// Created once per QUIC connection by [`WebTransportProtocolFactory`] and
/// shared (via `Arc<Protocols>`) across all concurrent streams.
pub struct WebTransportProtocol {
    registry: Registry,
    conn: Arc<dyn quic::DynConnection>,
}

impl fmt::Debug for WebTransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportProtocol")
            .field("sessions", &self.registry.len())
            .finish()
    }
}

impl WebTransportProtocol {
    pub(super) fn register(
        &self,
        session_id: StreamId,
    ) -> Result<RegisteredSession, RegisterSessionError> {
        self.registry.register(session_id)
    }

    pub(super) fn connection(&self) -> Arc<dyn quic::DynConnection> {
        Arc::clone(&self.conn)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(conn: Arc<dyn quic::DynConnection>) -> Self {
        Self {
            registry: Registry::default(),
            conn,
        }
    }
}

// ============================================================================
// Stream routing
// ============================================================================

impl WebTransportProtocol {
    async fn accept_bi_inner(
        &self,
        (mut reader, writer): ErasedPeekableBiStream,
    ) -> Result<StreamVerdict<ErasedPeekableBiStream>, StreamError> {
        let Ok(signal_value) = reader.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed((reader, writer)));
        };

        if signal_value != WEBTRANSPORT_BIDI_SIGNAL {
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // WebTransport bidi stream confirmed. Decode session ID for routing.
        let Ok(session_id) = reader.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session ID from webtransport bidi stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(?session_id, "routing webtransport bidi stream to session");

        let reader: BoxReadStream = Box::pin(reader.into_stream_reader());
        let writer: BoxWriteStream = writer.into_inner();

        self.registry.route_bi(session_id, (reader, writer));

        Ok(StreamVerdict::Accepted)
    }

    async fn accept_uni_inner(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        let Ok(signal_value) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if signal_value != WEBTRANSPORT_UNI_SIGNAL {
            return Ok(StreamVerdict::Passed(stream));
        }

        // WebTransport uni stream confirmed. Decode session ID for routing.
        let Ok(session_id) = stream.decode_one::<StreamId>().await else {
            tracing::debug!("failed to decode session ID from webtransport uni stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(?session_id, "routing webtransport uni stream to session");

        let reader: BoxReadStream = Box::pin(stream.into_stream_reader());

        self.registry.route_uni(session_id, reader);

        Ok(StreamVerdict::Accepted)
    }
}

impl Protocol for WebTransportProtocol {
    fn accept_uni<'a>(
        &'a self,
        stream: ErasedPeekableUniStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableUniStream>, StreamError>> {
        Box::pin(self.accept_uni_inner(stream))
    }

    fn accept_bi<'a>(
        &'a self,
        stream: ErasedPeekableBiStream,
    ) -> BoxFuture<'a, Result<StreamVerdict<ErasedPeekableBiStream>, StreamError>> {
        Box::pin(self.accept_bi_inner(stream))
    }
}

// ============================================================================
// WebTransportProtocolFactory
// ============================================================================

/// Factory for creating [`WebTransportProtocol`] instances during connection setup.
///
/// Register this as a protocol layer to enable WebTransport stream routing:
///
/// ```ignore
/// let builder = ConnectionBuilder::new(settings)
///     .protocol(WebTransportProtocolFactory);
/// ```
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct WebTransportProtocolFactory;

impl fmt::Display for WebTransportProtocolFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WebTransport")
    }
}

impl<C: quic::Connection> ProductProtocol<C> for WebTransportProtocolFactory {
    type Protocol = WebTransportProtocol;

    fn init<'a>(
        &'a self,
        conn: &'a Arc<C>,
        _layers: &'a Protocols,
    ) -> BoxFuture<'a, Result<Self::Protocol, ConnectionError>> {
        let conn: Arc<dyn quic::DynConnection> = conn.clone();
        Box::pin(async move {
            Ok(WebTransportProtocol {
                registry: Registry::default(),
                conn,
            })
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const fn assert_send_sync<T: Send + Sync>() {}
    // WebTransportProtocol is Send + Sync (required for Protocol trait).
    const _: () = assert_send_sync::<WebTransportProtocol>();

    #[test]
    fn signal_values_are_correct() {
        assert_eq!(WEBTRANSPORT_BIDI_SIGNAL.into_inner(), 0x41);
        assert_eq!(WEBTRANSPORT_UNI_SIGNAL.into_inner(), 0x54);
    }
}
