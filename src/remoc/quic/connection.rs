use std::{borrow::Cow, sync::Arc};

use futures::future::BoxFuture;
use remoc::prelude::{ServerShared, ServerSharedMut};
use tracing::Instrument;

use super::{
    agent::{
        LocalAgentClient, LocalLocalAgent, LocalRemoteAgent, RemoteAgentClient, RemoteLocalAgent,
        RemoteRemoteAgent,
    },
    stream::{self, LocalReadStream, LocalWriteStream, ReadStreamClient, WriteStreamClient},
    task_set::TaskSet,
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
#[derive(serde::Serialize, serde::Deserialize)]
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
        tokio::spawn(
            async move {
                let _ = client.close(code, reason).await;
            }
            .in_current_span(),
        );
    }
}

/// Server-side wrapper that implements the remoc [`Connection`] RTC trait
/// for any local [`quic::Connection`] implementation.
///
/// This allows a real QUIC connection to be served over remoc RTC,
/// converting standard trait calls into RTC-compatible async methods.
/// Each opened/accepted stream is wrapped and served as an individual RTC server.
pub struct LocalQuicConnection<C> {
    conn: C,
    tasks: TaskSet,
}

impl<C> LocalQuicConnection<C> {
    /// Wrap a local QUIC connection so it can be served over remoc RTC.
    pub fn new(conn: C) -> Self {
        Self {
            conn,
            tasks: TaskSet::new(),
        }
    }
}

impl<C> LocalQuicConnection<C>
where
    C: quic::Connection + 'static,
{
    /// Convert this local connection into a remote-accessible connection.
    ///
    /// Consumes `self` and returns:
    /// - A [`RemoteQuicConnection`] that can be serialized and sent to a remote peer.
    /// - A `Future` that must be polled to drive the RTC server and all spawned tasks.
    ///   When this future is dropped, all associated tasks are cancelled.
    pub fn into_remote(
        self,
    ) -> (
        RemoteQuicConnection,
        impl Future<Output = ()> + Send + 'static,
    ) {
        let (server, client) = ConnectionServerShared::new(Arc::new(self), 1);
        let remote = RemoteQuicConnection::new(client);
        let fut = async move {
            let _ = server.serve(true).await;
        };
        (remote, fut)
    }
}

/// Create a [`ReadStreamServerSharedMut`] for a local read stream
/// and return the corresponding [`ReadStreamClient`] and a future to serve it.
fn serve_read_stream(
    reader: impl quic::ReadStream + 'static,
) -> (ReadStreamClient, impl Future<Output = ()> + Send + 'static) {
    let local = LocalReadStream::new(reader);
    let (server, client) =
        stream::ReadStreamServerSharedMut::new(Arc::new(tokio::sync::RwLock::new(local)), 1);
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

/// Create a [`WriteStreamServerSharedMut`] for a local write stream
/// and return the corresponding [`WriteStreamClient`] and a future to serve it.
fn serve_write_stream(
    writer: impl quic::WriteStream + 'static,
) -> (WriteStreamClient, impl Future<Output = ()> + Send + 'static) {
    let local = LocalWriteStream::new(writer);
    let (server, client) =
        stream::WriteStreamServerSharedMut::new(Arc::new(tokio::sync::RwLock::new(local)), 1);
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

impl<C> Connection for LocalQuicConnection<C>
where
    C: quic::Connection + 'static,
{
    async fn open_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = self.conn.open_bi().await?;
        let (read_client, read_fut) = serve_read_stream(reader);
        let (write_client, write_fut) = serve_write_stream(writer);
        self.tasks.spawn(read_fut);
        self.tasks.spawn(write_fut);
        Ok((read_client, write_client))
    }

    async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError> {
        let writer = self.conn.open_uni().await?;
        let (client, fut) = serve_write_stream(writer);
        self.tasks.spawn(fut);
        Ok(client)
    }

    async fn accept_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = self.conn.accept_bi().await?;
        let (read_client, read_fut) = serve_read_stream(reader);
        let (write_client, write_fut) = serve_write_stream(writer);
        self.tasks.spawn(read_fut);
        self.tasks.spawn(write_fut);
        Ok((read_client, write_client))
    }

    async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError> {
        let reader = self.conn.accept_uni().await?;
        let (client, fut) = serve_read_stream(reader);
        self.tasks.spawn(fut);
        Ok(client)
    }

    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError> {
        let agent = self.conn.local_agent().await?;
        match agent {
            Some(a) => {
                let local = LocalLocalAgent::new(a);
                let (server, client) =
                    super::agent::LocalAgentServerShared::new(Arc::new(local), 1);
                self.tasks.spawn(async move {
                    let _ = server.serve(true).await;
                });
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError> {
        let agent = self.conn.remote_agent().await?;
        match agent {
            Some(a) => {
                let local = LocalRemoteAgent::new(a);
                let (server, client) =
                    super::agent::RemoteAgentServerShared::new(Arc::new(local), 1);
                self.tasks.spawn(async move {
                    let _ = server.serve(true).await;
                });
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
        self.conn.close(code, reason);
        Ok(())
    }
}
