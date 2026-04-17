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
//! 2. The session ID ([`VarInt`])
//!
//! The session receives the stream positioned after these two fields.

use std::{collections::HashMap, fmt, sync::Arc};

use futures::future::BoxFuture;
use snafu::ensure;
use tokio::sync::mpsc;

use super::{
    error::{AlreadyRegisteredSnafu, RegisterError},
    session::{RoutedBiStream, RoutedUniStream, WebTransportSession},
};
use crate::{
    codec::{
        BoxReadStream, BoxWriteStream, DecodeExt, ErasedPeekableBiStream, ErasedPeekableUniStream,
    },
    connection::StreamError,
    protocol::{ProductProtocol, Protocol, Protocols, StreamVerdict},
    quic::{self, ConnectionError},
    varint::VarInt,
};

// ============================================================================
// Constants
// ============================================================================

/// Signal value for WebTransport bidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WT_BIDI_SIGNAL: VarInt = VarInt::from_u32(0x41);

/// Signal value for WebTransport unidirectional streams
/// (draft-ietf-webtrans-http3, §2).
pub const WT_UNI_SIGNAL: VarInt = VarInt::from_u32(0x54);

// ============================================================================
// Session stream router
// ============================================================================

/// Session registry: maps session ID to stream routers.
pub(super) type Registry = Arc<std::sync::Mutex<HashMap<VarInt, SessionStreamRouter>>>;

/// Routes incoming streams to a single WebTransport session via bounded channels.
pub(super) struct SessionStreamRouter {
    bidi_tx: mpsc::Sender<RoutedBiStream>,
    uni_tx: mpsc::Sender<RoutedUniStream>,
}

impl SessionStreamRouter {
    fn new(bidi_tx: mpsc::Sender<RoutedBiStream>, uni_tx: mpsc::Sender<RoutedUniStream>) -> Self {
        Self { bidi_tx, uni_tx }
    }

    fn route_bi(&self, session_id: VarInt, stream: RoutedBiStream) {
        if self.bidi_tx.try_send(stream).is_err() {
            tracing::debug!(
                ?session_id,
                "session bidi channel full or closed, dropping stream"
            );
        }
    }

    fn route_uni(&self, session_id: VarInt, stream: RoutedUniStream) {
        if self.uni_tx.try_send(stream).is_err() {
            tracing::debug!(
                ?session_id,
                "session uni channel full or closed, dropping stream"
            );
        }
    }
}

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
    conn: Arc<dyn quic::DynManageStream>,
}

impl fmt::Debug for WebTransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportProtocol")
            .field(
                "sessions",
                &self.registry.lock().map(|r| r.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl WebTransportProtocol {
    /// Register a new session for the given session ID.
    ///
    /// Returns a [`WebTransportSession`] that receives routed streams and can
    /// open new streams. The session unregisters itself when dropped.
    pub fn register(&self, session_id: VarInt) -> Result<WebTransportSession, RegisterError> {
        let (bidi_tx, bidi_rx) = mpsc::channel(16);
        let (uni_tx, uni_rx) = mpsc::channel(16);

        let mut registry = self
            .registry
            .lock()
            .map_err(|_| RegisterError::RegistryPoisoned)?;

        ensure!(
            !registry.contains_key(&session_id),
            AlreadyRegisteredSnafu {
                session_id: crate::stream_id::StreamId::from(session_id),
            }
        );

        registry.insert(session_id, SessionStreamRouter::new(bidi_tx, uni_tx));

        Ok(WebTransportSession::new(
            session_id,
            bidi_rx,
            uni_rx,
            Arc::clone(&self.conn),
            Arc::clone(&self.registry),
        ))
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

        if signal_value != WT_BIDI_SIGNAL {
            return Ok(StreamVerdict::Passed((reader, writer)));
        }

        // WebTransport bidi stream confirmed. Decode session ID for routing.
        let Ok(session_id) = reader.decode_one::<VarInt>().await else {
            tracing::debug!("failed to decode session ID from webtransport bidi stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(?session_id, "routing webtransport bidi stream to session");

        let reader: BoxReadStream = Box::pin(reader.into_stream_reader());
        let writer: BoxWriteStream = writer.into_inner();

        let Ok(registry) = self.registry.lock() else {
            tracing::debug!("webtransport session registry lock poisoned");
            return Ok(StreamVerdict::Accepted);
        };
        if let Some(router) = registry.get(&session_id) {
            router.route_bi(session_id, (reader, writer));
        } else {
            tracing::debug!(
                ?session_id,
                "no registered session for webtransport bidi stream"
            );
        }

        Ok(StreamVerdict::Accepted)
    }

    async fn accept_uni_inner(
        &self,
        mut stream: ErasedPeekableUniStream,
    ) -> Result<StreamVerdict<ErasedPeekableUniStream>, StreamError> {
        let Ok(signal_value) = stream.decode_one::<VarInt>().await else {
            return Ok(StreamVerdict::Passed(stream));
        };

        if signal_value != WT_UNI_SIGNAL {
            return Ok(StreamVerdict::Passed(stream));
        }

        // WebTransport uni stream confirmed. Decode session ID for routing.
        let Ok(session_id) = stream.decode_one::<VarInt>().await else {
            tracing::debug!("failed to decode session ID from webtransport uni stream");
            return Ok(StreamVerdict::Accepted);
        };

        tracing::debug!(?session_id, "routing webtransport uni stream to session");

        let reader: BoxReadStream = Box::pin(stream.into_stream_reader());

        let Ok(registry) = self.registry.lock() else {
            tracing::debug!("webtransport session registry lock poisoned");
            return Ok(StreamVerdict::Accepted);
        };
        if let Some(router) = registry.get(&session_id) {
            router.route_uni(session_id, reader);
        } else {
            tracing::debug!(
                ?session_id,
                "no registered session for webtransport uni stream"
            );
        }

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
        let conn: Arc<dyn quic::DynManageStream> = conn.clone();
        Box::pin(async move {
            Ok(WebTransportProtocol {
                registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
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

    // WebTransportProtocol is Send + Sync (required for Protocol trait).
    const _: () = {
        fn assert_send_sync<T: Send + Sync>() {}
        fn check() {
            assert_send_sync::<WebTransportProtocol>();
        }
    };

    #[test]
    fn signal_values_are_correct() {
        assert_eq!(WT_BIDI_SIGNAL.into_inner(), 0x41);
        assert_eq!(WT_UNI_SIGNAL.into_inner(), 0x54);
    }
}
