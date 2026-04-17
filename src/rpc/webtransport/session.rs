//! RPC-forwarded WebTransport session.
//!
//! Follows the same pattern as [`super::super::quic::connection`]: a
//! `#[remoc::rtc::remote]` trait provides the wire protocol, a blanket-free
//! server impl delegates to [`WebTransportSession`], and [`RemoteWtSession`]
//! wraps the generated client to present a convenient async API.

use std::sync::Arc;

use remoc::rtc::Client as RemocClient;
use tracing::Instrument;

use super::super::{
    lifecycle::ConnectionErrorLatch,
    quic::{ReadStreamClient, ReadStreamServer, WriteStreamClient, WriteStreamServer},
};
use crate::{
    codec::{BoxReadStream, BoxWriteStream},
    quic::{self, ConnectionError, DynLifecycle},
    varint::VarInt,
    webtransport::{self, Closed, OpenStreamError},
};

// ---------------------------------------------------------------------------
// RPC trait
// ---------------------------------------------------------------------------

/// Remoc RPC counterpart of [`WebTransportSession`].
///
/// Uses the native [`OpenStreamError`] and [`Closed`] error types directly —
/// both are serializable. The `session_id` is not included because it is
/// immutable and can be passed out-of-band at construction time.
#[remoc::rtc::remote]
pub trait WtSession: Send + Sync {
    async fn open_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), OpenStreamError>;
    async fn open_uni(&self) -> Result<WriteStreamClient, OpenStreamError>;
    async fn accept_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), Closed>;
    async fn accept_uni(&self) -> Result<ReadStreamClient, Closed>;
}

// ---------------------------------------------------------------------------
// Server: impl WtSession for WebTransportSession
// ---------------------------------------------------------------------------

impl WtSession for webtransport::WebTransportSession {
    async fn open_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), OpenStreamError> {
        let (reader, writer) = webtransport::WebTransportSession::open_bi(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn open_uni(&self) -> Result<WriteStreamClient, OpenStreamError> {
        let writer = webtransport::WebTransportSession::open_uni(self).await?;
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok(wc)
    }

    async fn accept_bi(&self) -> Result<(ReadStreamClient, WriteStreamClient), Closed> {
        let (reader, writer) = webtransport::WebTransportSession::accept_bi(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = WriteStreamServer::new(writer, 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn accept_uni(&self) -> Result<ReadStreamClient, Closed> {
        let reader = webtransport::WebTransportSession::accept_uni(self).await?;
        let (rs, rc) = ReadStreamServer::new(reader, 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        Ok(rc)
    }
}

// ---------------------------------------------------------------------------
// Client: RemoteWtSession wraps WtSessionClient
// ---------------------------------------------------------------------------

/// A wrapper around [`WtSessionClient`] that converts RPC stream clients back
/// into boxed async streams.
///
/// This is the client-side handle for a remote WebTransport session. It mirrors
/// the [`WebTransportSession`] API but works across process/RPC boundaries.
///
/// The `session_id` is stored locally (passed at construction time) and does
/// not require an RPC call.
///
/// Error handling uses a parent [`DynLifecycle`] plus a local
/// [`ConnectionErrorLatch`] to inherit the parent connection's lifecycle.
/// The first connection error — whether from the parent or from the session's
/// own remoc channel — is latched and returned on every subsequent operation,
/// satisfying the QUIC connection-error consistency requirement.
#[derive(Debug, Clone)]
pub struct RemoteWtSession {
    client: WtSessionClient,
    session_id: VarInt,
    parent: Arc<dyn DynLifecycle>,
    latch: ConnectionErrorLatch,
}

impl RemoteWtSession {
    pub fn new(
        client: WtSessionClient,
        session_id: VarInt,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> Self {
        Self {
            client,
            session_id,
            parent: conn_lifecycle,
            latch: ConnectionErrorLatch::new(),
        }
    }

    pub fn into_inner(self) -> WtSessionClient {
        self.client
    }

    /// Synthesize a transport error for remoc channel failures.
    fn remoc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: "remoc wt session channel closed".into(),
            },
        }
    }

    /// Check if the connection is dead.  Checks the local latch first,
    /// then the parent lifecycle (syncing errors into the latch), then
    /// the remoc channel.
    fn check(&self) -> Result<(), ConnectionError> {
        self.latch.check()?;
        self.parent.check().map_err(|e| self.latch.latch(e))?;
        if RemocClient::is_closed(&self.client) {
            return Err(self.latch.latch_with(Self::remoc_channel_error));
        }
        Ok(())
    }

    /// Latch a [`Closed`] from an accept operation.  If the remoc channel
    /// is actually dead, latch the channel error so future operations
    /// return a consistent connection error.
    fn latch_accept_error(&self, error: Closed) -> Closed {
        if RemocClient::is_closed(&self.client) {
            self.latch.latch_with(Self::remoc_channel_error);
        }
        error
    }

    /// Guard an async open operation: check lifecycle + remoc channel,
    /// execute, latch errors.
    async fn guard_open<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, OpenStreamError>>,
    ) -> Result<T, OpenStreamError> {
        self.latch.check_open()?;
        self.parent.check().map_err(|e| OpenStreamError::Open {
            source: self.latch.latch(e),
        })?;
        if RemocClient::is_closed(&self.client) {
            return Err(OpenStreamError::Open {
                source: self.latch.latch_with(Self::remoc_channel_error),
            });
        }
        fut.await.map_err(|e| self.latch.latch_open(e))
    }

    /// Guard an async accept operation: check lifecycle + remoc channel,
    /// execute, latch errors.
    async fn guard_accept<T>(
        &self,
        fut: impl std::future::Future<Output = Result<T, Closed>>,
    ) -> Result<T, Closed> {
        self.check().map_err(|_| Closed)?;
        fut.await.map_err(|e| self.latch_accept_error(e))
    }
}

impl webtransport::Session for RemoteWtSession {
    type StreamReader = BoxReadStream;
    type StreamWriter = BoxWriteStream;

    fn session_id(&self) -> VarInt {
        self.session_id
    }

    async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
        let (reader, writer) = self.guard_open(WtSession::open_bi(&self.client)).await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
        let writer = self.guard_open(WtSession::open_uni(&self.client)).await?;
        Ok(writer.into_boxed_quic())
    }

    async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), Closed> {
        let (reader, writer) = self
            .guard_accept(WtSession::accept_bi(&self.client))
            .await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn accept_uni(&self) -> Result<BoxReadStream, Closed> {
        let reader = self
            .guard_accept(WtSession::accept_uni(&self.client))
            .await?;
        Ok(reader.into_boxed_quic())
    }
}

impl WtSessionClient {
    /// Convert into a [`RemoteWtSession`].
    pub fn into_wt(
        self,
        session_id: VarInt,
        conn_lifecycle: Arc<dyn DynLifecycle>,
    ) -> RemoteWtSession {
        RemoteWtSession::new(self, session_id, conn_lifecycle)
    }
}

impl From<RemoteWtSession> for WtSessionClient {
    fn from(remote: RemoteWtSession) -> Self {
        remote.client
    }
}
