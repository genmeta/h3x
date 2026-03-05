use std::borrow::Cow;

use futures::future::BoxFuture;

use crate::{
    error::Code,
    quic::{self, ConnectionError},
    varint::VarInt,
};

use super::{
    RemoteError,
    agent::{
        CachedRemoteLocalAgent, CachedRemoteRemoteAgent, RemoteLocalAgentClient,
        RemoteRemoteAgentClient,
    },
    stream::{RemoteReadClient, RemoteReadStream, RemoteWriteClient, RemoteWriteStream},
};

/// Remote trait for a QUIC connection, combining stream management, agent access,
/// and close operations over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait RemoteConnection: Send + Sync {
    /// Open a bidirectional stream, returning RTC clients for both sides.
    async fn open_bi(&self) -> Result<(RemoteReadClient, RemoteWriteClient), RemoteError>;

    /// Open a unidirectional (send-only) stream.
    async fn open_uni(&self) -> Result<RemoteWriteClient, RemoteError>;

    /// Accept a bidirectional stream initiated by the remote peer.
    async fn accept_bi(&self) -> Result<(RemoteReadClient, RemoteWriteClient), RemoteError>;

    /// Accept a unidirectional stream initiated by the remote peer.
    async fn accept_uni(&self) -> Result<RemoteReadClient, RemoteError>;

    /// Retrieve the local agent's RTC client, if available.
    async fn local_agent(&self) -> Result<Option<RemoteLocalAgentClient>, RemoteError>;

    /// Retrieve the remote agent's RTC client, if available.
    async fn remote_agent(&self) -> Result<Option<RemoteRemoteAgentClient>, RemoteError>;

    /// Close the connection with the given error code and reason.
    ///
    /// Uses `String` instead of `Cow<'static, str>` for serde compatibility.
    /// Uses `VarInt` instead of `Code` to keep the RTC trait simple.
    async fn close(&self, code: VarInt, reason: String) -> Result<(), RemoteError>;
}

/// Wrapper around [`RemoteConnectionClient`] that implements the four quic
/// connection traits ([`ManageStream`], [`WithLocalAgent`], [`WithRemoteAgent`],
/// [`Close`]), satisfying the blanket [`Connection`](quic::Connection) impl.
pub struct RemoteConnectionWrapper {
    client: RemoteConnectionClient,
}

impl RemoteConnectionWrapper {
    /// Create a new wrapper from a remoc-generated connection client.
    pub fn new(client: RemoteConnectionClient) -> Self {
        Self { client }
    }
}

impl quic::ManageStream for RemoteConnectionWrapper {
    type StreamWriter = RemoteWriteStream;
    type StreamReader = RemoteReadStream;

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (read_client, write_client) = client
                .open_bi()
                .await
                .map_err(|e| e.into_connection_error())?;
            Ok((
                RemoteReadStream::new(read_client),
                RemoteWriteStream::new(write_client),
            ))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Self::StreamWriter, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let write_client = client
                .open_uni()
                .await
                .map_err(|e| e.into_connection_error())?;
            Ok(RemoteWriteStream::new(write_client))
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (read_client, write_client) = client
                .accept_bi()
                .await
                .map_err(|e| e.into_connection_error())?;
            Ok((
                RemoteReadStream::new(read_client),
                RemoteWriteStream::new(write_client),
            ))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Self::StreamReader, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let read_client = client
                .accept_uni()
                .await
                .map_err(|e| e.into_connection_error())?;
            Ok(RemoteReadStream::new(read_client))
        })
    }
}

impl quic::WithLocalAgent for RemoteConnectionWrapper {
    type LocalAgent = CachedRemoteLocalAgent;

    fn local_agent(&self) -> BoxFuture<'_, Result<Option<Self::LocalAgent>, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let agent_client = client
                .local_agent()
                .await
                .map_err(|e| e.into_connection_error())?;
            match agent_client {
                Some(c) => {
                    let cached = CachedRemoteLocalAgent::new(c)
                        .await
                        .map_err(|e| e.into_connection_error())?;
                    Ok(Some(cached))
                }
                None => Ok(None),
            }
        })
    }
}

impl quic::WithRemoteAgent for RemoteConnectionWrapper {
    type RemoteAgent = CachedRemoteRemoteAgent;

    fn remote_agent(&self) -> BoxFuture<'_, Result<Option<Self::RemoteAgent>, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let agent_client = client
                .remote_agent()
                .await
                .map_err(|e| e.into_connection_error())?;
            match agent_client {
                Some(c) => {
                    let cached = CachedRemoteRemoteAgent::new(c)
                        .await
                        .map_err(|e| e.into_connection_error())?;
                    Ok(Some(cached))
                }
                None => Ok(None),
            }
        })
    }
}

impl quic::Close for RemoteConnectionWrapper {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let client = self.client.clone();
        let reason_owned = reason.into_owned();
        let code_varint = code.into_inner();
        // Fire-and-forget: spawn a task to handle the async RPC.
        // The result is intentionally discarded since close is fire-and-forget.
        tokio::spawn(async move {
            let _ = client.close(code_varint, reason_owned).await;
        });
    }
}
