use std::{borrow::Cow, sync::Arc};

use remoc::{
    prelude::{Server, ServerShared},
    rtc::Client as RemocClient,
};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::{
    agent::{CachedLocalAgent, CachedRemoteAgent, LocalAgentClient, RemoteAgentClient},
    stream::{self, ReadStreamClient, WriteStreamClient},
};
use crate::{
    error::Code,
    quic::{self, ConnectionError},
    rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
    varint::VarInt,
};

#[remoc::rtc::remote]
pub trait Connection: Send + Sync {
    async fn open_bi(&self)
    -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;
    async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError>;
    async fn accept_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;
    async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError>;
    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError>;
    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError>;
    async fn close(
        &self,
        code: Code,
        reason: Cow<'static, str>,
    ) -> Result<(), quic::ConnectionError>;
    async fn closed(&self) -> Result<quic::ConnectionError, quic::ConnectionError>;
}

// ---------------------------------------------------------------------------
// Server side: blanket — any quic::Connection implements the RTC trait
// ---------------------------------------------------------------------------

impl<C> Connection for C
where
    C: quic::Connection + 'static,
    C::LocalAgent: Send + Sync,
    C::RemoteAgent: Send + Sync,
{
    async fn open_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = quic::ManageStream::open_bi(self).await?;
        let (rs, rc) = stream::ReadStreamServer::new(Box::pin(reader), 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = stream::WriteStreamServer::new(Box::pin(writer), 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError> {
        let writer = quic::ManageStream::open_uni(self).await?;
        let (ws, wc) = stream::WriteStreamServer::new(Box::pin(writer), 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok(wc)
    }

    async fn accept_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = quic::ManageStream::accept_bi(self).await?;
        let (rs, rc) = stream::ReadStreamServer::new(Box::pin(reader), 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        let (ws, wc) = stream::WriteStreamServer::new(Box::pin(writer), 1);
        tokio::spawn(
            (async move {
                let _ = ws.serve().await;
            })
            .in_current_span(),
        );
        Ok((rc, wc))
    }

    async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError> {
        let reader = quic::ManageStream::accept_uni(self).await?;
        let (rs, rc) = stream::ReadStreamServer::new(Box::pin(reader), 1);
        tokio::spawn(
            (async move {
                let _ = rs.serve().await;
            })
            .in_current_span(),
        );
        Ok(rc)
    }

    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError> {
        match quic::WithLocalAgent::local_agent(self).await? {
            Some(agent) => {
                let (server, client) =
                    super::agent::LocalAgentServerShared::new(Arc::new(agent), 1);
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError> {
        match quic::WithRemoteAgent::remote_agent(self).await? {
            Some(agent) => {
                let (server, client) =
                    super::agent::RemoteAgentServerShared::new(Arc::new(agent), 1);
                tokio::spawn(
                    (async move {
                        let _ = server.serve(true).await;
                    })
                    .in_current_span(),
                );
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn close(
        &self,
        code: Code,
        reason: Cow<'static, str>,
    ) -> Result<(), quic::ConnectionError> {
        quic::Lifecycle::close(self, code, reason);
        Ok(())
    }

    async fn closed(&self) -> Result<quic::ConnectionError, quic::ConnectionError> {
        Ok(quic::Lifecycle::closed(self).await)
    }
}

// ---------------------------------------------------------------------------
// Client side: RemoteConnection wraps ConnectionClient → quic::Connection
// ---------------------------------------------------------------------------

/// A wrapper around [`ConnectionClient`] that implements [`quic::Connection`].
///
/// On the client side, use this to treat a received RTC connection handle as a
/// local [`quic::Connection`] for the h3x protocol stack.
///
/// Transparent serialization allows sending a `RemoteConnection` directly
/// across process boundaries without unwrapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RemoteConnection {
    client: ConnectionClient,
    #[serde(skip)]
    latch: ConnectionErrorLatch,
}

impl RemoteConnection {
    pub fn new(client: ConnectionClient) -> Self {
        Self {
            client,
            latch: ConnectionErrorLatch::new(),
        }
    }

    pub fn into_inner(self) -> ConnectionClient {
        self.client
    }

    /// Synthesize a transport error for remoc channel failures.
    fn remoc_channel_error() -> ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: "remoc connection channel closed".into(),
            },
        }
    }
}

impl HasLatch for RemoteConnection {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl ConnectionClient {
    /// Convert into a [`RemoteConnection`] that implements [`quic::Connection`].
    pub fn into_quic(self) -> RemoteConnection {
        RemoteConnection::new(self)
    }
}

impl From<ConnectionClient> for RemoteConnection {
    fn from(client: ConnectionClient) -> Self {
        Self::new(client)
    }
}

impl From<RemoteConnection> for ConnectionClient {
    fn from(remote: RemoteConnection) -> Self {
        remote.client
    }
}

impl quic::ManageStream for RemoteConnection {
    type StreamWriter = crate::dhttp::protocol::BoxDynQuicStreamWriter;
    type StreamReader = crate::dhttp::protocol::BoxDynQuicStreamReader;

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let (reader, writer) = self.guard(Connection::open_bi(&self.client)).await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, ConnectionError> {
        let writer = self.guard(Connection::open_uni(&self.client)).await?;
        Ok(writer.into_boxed_quic())
    }

    async fn accept_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), ConnectionError> {
        let (reader, writer) = self.guard(Connection::accept_bi(&self.client)).await?;
        Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, ConnectionError> {
        let reader = self.guard(Connection::accept_uni(&self.client)).await?;
        Ok(reader.into_boxed_quic())
    }
}

impl quic::WithLocalAgent for RemoteConnection {
    type LocalAgent = CachedLocalAgent;

    async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, ConnectionError> {
        match self.guard(Connection::local_agent(&self.client)).await? {
            Some(agent) => Ok(Some(
                self.guard(CachedLocalAgent::from_client(agent)).await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::WithRemoteAgent for RemoteConnection {
    type RemoteAgent = CachedRemoteAgent;

    async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, ConnectionError> {
        match self.guard(Connection::remote_agent(&self.client)).await? {
            Some(agent) => Ok(Some(
                self.guard(CachedRemoteAgent::from_client(agent)).await?,
            )),
            None => Ok(None),
        }
    }
}

impl quic::Lifecycle for RemoteConnection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let client = self.client.clone();
        tokio::spawn(
            async move {
                let _ = Connection::close(&client, code, reason).await;
            }
            .in_current_span(),
        );
    }

    fn check(&self) -> Result<(), ConnectionError> {
        self.check_with_probe(|| {
            RemocClient::is_closed(&self.client).then(Self::remoc_channel_error)
        })
    }

    async fn closed(&self) -> ConnectionError {
        self.resolve_closed(async {
            Connection::closed(&self.client)
                .await
                .unwrap_or_else(|_| Self::remoc_channel_error())
        })
        .await
    }
}
