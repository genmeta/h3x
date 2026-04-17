//! RPC-forwarded WebTransport session.
//!
//! Follows the same pattern as [`super::super::quic::connection`]: a
//! `#[remoc::rtc::remote]` trait provides the wire protocol, a blanket-free
//! server impl delegates to [`WebTransportSession`], and [`RemoteWtSession`]
//! wraps the generated client to present a convenient async API.

use std::sync::Arc;

use remoc::{prelude::Server, rtc::Client as RemocClient};
use tracing::Instrument;

use super::super::{
    lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
    quic::{ReadStreamClient, ReadStreamServer, WriteStreamClient, WriteStreamServer},
};
use crate::{
    message::stream::guard,
    quic::{self, ConnectionError, DynLifecycle},
    varint::VarInt,
    webtransport::{self, Closed, OpenStreamError, WtLifecycleExt},
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
#[derive(Clone)]
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

    /// Liveness probe combining parent lifecycle and remoc channel state.
    fn probe(&self) -> Option<ConnectionError> {
        if let Err(e) = DynLifecycle::check(self.parent.as_ref()) {
            return Some(e);
        }
        if RemocClient::is_closed(&self.client) {
            return Some(Self::remoc_channel_error());
        }
        None
    }
}

impl HasLatch for RemoteWtSession {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for RemoteWtSession {
    fn close(&self, code: crate::error::Code, reason: std::borrow::Cow<'static, str>) {
        DynLifecycle::close(self.parent.as_ref(), code, reason);
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| self.probe())
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(DynLifecycle::closed(self.parent.as_ref()))
            .await
    }
}

impl webtransport::Session for RemoteWtSession {
    type StreamReader = guard::GuardedQuicReader;
    type StreamWriter = guard::GuardedQuicWriter;

    fn session_id(&self) -> VarInt {
        self.session_id
    }

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError> {
        let (reader, writer) = self.guard_open(WtSession::open_bi(&self.client)).await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, OpenStreamError> {
        let writer = self.guard_open(WtSession::open_uni(&self.client)).await?;
        Ok(writer.into_boxed_quic())
    }

    async fn accept_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Closed> {
        let (reader, writer) = self
            .guard_accept_err(WtSession::accept_bi(&self.client), |Closed| {
                RemocClient::is_closed(&self.client).then(Self::remoc_channel_error)
            })
            .await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, Closed> {
        let reader = self
            .guard_accept_err(WtSession::accept_uni(&self.client), |Closed| {
                RemocClient::is_closed(&self.client).then(Self::remoc_channel_error)
            })
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
