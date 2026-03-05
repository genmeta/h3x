use std::borrow::Cow;

use futures::future::BoxFuture;

use super::{
    agent::{LocalAgentClient, RemoteAgentClient, RemoteLocalAgent, RemoteRemoteAgent},
    stream::{self, ReadStreamClient, WriteStreamClient},
};
use crate::{
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    error::Code,
    quic::{self, ConnectionError},
    util::try_future::TryFuture,
};

/// Remote trait for a QUIC connection, combining stream management, agent access,
/// and close operations over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone`.
#[remoc::rtc::remote]
pub trait Connection: Send + Sync {
    /// Open a bidirectional stream, returning RTC clients for both sides.
    async fn open_bi(&self)
    -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;

    /// Open a unidirectional (send-only) stream.
    async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError>;

    /// Accept a bidirectional stream initiated by the remote peer.
    async fn accept_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;

    /// Accept a unidirectional stream initiated by the remote peer.
    async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError>;

    /// Retrieve the local agent's RTC client, if available.
    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError>;

    /// Retrieve the remote agent's RTC client, if available.
    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError>;

    /// Close the connection with the given error code and reason.
    ///
    /// Uses `String` instead of `Cow<'static, str>` for serde compatibility.
    /// Uses `VarInt` instead of `Code` to keep the RTC trait simple.
    async fn close(
        &self,
        code: Code,
        reason: Cow<'static, str>,
    ) -> Result<(), quic::ConnectionError>;
}

/// Wrapper around [`RemoteConnectionClient`] that implements the four quic
/// connection traits ([`ManageStream`], [`WithLocalAgent`], [`WithRemoteAgent`],
/// [`Close`]), satisfying the blanket [`Connection`](quic::Connection) impl.
pub struct RemoteQuicConnection {
    client: ConnectionClient,
}

impl RemoteQuicConnection {
    /// Create a new wrapper from a remoc-generated connection client.
    pub fn new(client: ConnectionClient) -> Self {
        Self { client }
    }
}

impl quic::ManageStream for RemoteQuicConnection {
    type StreamWriter = BoxDynQuicStreamWriter;
    type StreamReader = BoxDynQuicStreamReader;

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (read_client, write_client) = client.open_bi().await?;
            Ok((
                Box::pin(TryFuture::from(stream::new_remote_read_stream(read_client)))
                    as BoxDynQuicStreamReader,
                Box::pin(TryFuture::from(stream::new_remote_write_stream(
                    write_client,
                ))) as BoxDynQuicStreamWriter,
            ))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Self::StreamWriter, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let write_client = client.open_uni().await?;
            Ok(Box::pin(TryFuture::from(stream::new_remote_write_stream(
                write_client,
            ))) as BoxDynQuicStreamWriter)
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (read_client, write_client) = client.accept_bi().await?;
            Ok((
                Box::pin(TryFuture::from(stream::new_remote_read_stream(read_client)))
                    as BoxDynQuicStreamReader,
                Box::pin(TryFuture::from(stream::new_remote_write_stream(
                    write_client,
                ))) as BoxDynQuicStreamWriter,
            ))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Self::StreamReader, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let read_client = client.accept_uni().await?;
            Ok(
                Box::pin(TryFuture::from(stream::new_remote_read_stream(read_client)))
                    as BoxDynQuicStreamReader,
            )
        })
    }
}

impl quic::WithLocalAgent for RemoteQuicConnection {
    type LocalAgent = RemoteLocalAgent;

    fn local_agent(&self) -> BoxFuture<'_, Result<Option<Self::LocalAgent>, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let agent_client = client.local_agent().await?;
            match agent_client {
                Some(c) => {
                    let cached = RemoteLocalAgent::new(c).await?;
                    Ok(Some(cached))
                }
                None => Ok(None),
            }
        })
    }
}

impl quic::WithRemoteAgent for RemoteQuicConnection {
    type RemoteAgent = RemoteRemoteAgent;

    fn remote_agent(&self) -> BoxFuture<'_, Result<Option<Self::RemoteAgent>, ConnectionError>> {
        let client = self.client.clone();
        Box::pin(async move {
            let agent_client = client.remote_agent().await?;
            match agent_client {
                Some(c) => {
                    let cached = RemoteRemoteAgent::new(c).await?;
                    Ok(Some(cached))
                }
                None => Ok(None),
            }
        })
    }
}

impl quic::Close for RemoteQuicConnection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let client = self.client.clone();
        // Fire-and-forget: spawn a task to handle the async RPC.
        // The result is intentionally discarded since close is fire-and-forget.
        tokio::spawn(async move {
            let _ = client.close(code, reason).await;
        });
    }
}
