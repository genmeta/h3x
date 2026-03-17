use std::{borrow::Cow, future::Future, sync::Arc};

use futures::{SinkExt, StreamExt, future::BoxFuture};
use remoc::{
    prelude::{ServerShared, ServerSharedMut},
    rtc::Client as RemocClient,
};
use tracing::Instrument;

use super::{
    agent::{CachedLocalAgent, CachedRemoteAgent, LocalAgentClient, RemoteAgentClient},
    stream::{self, ReadStreamClient, WriteStreamClient},
    task_set::TaskSet,
};
use crate::{
    error::Code,
    quic::{self, CancelStreamExt, ConnectionError, GetStreamIdExt, StopStreamExt},
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

pub fn serve_quic_connection<C>(
    connection: C,
) -> (ConnectionClient, impl Future<Output = ()> + Send + 'static)
where
    C: quic::Connection + 'static,
    C::LocalAgent: Send + Sync,
    C::RemoteAgent: Send + Sync,
{
    let (server, client) =
        ConnectionServerShared::new(Arc::new(ServedConnection::new(connection)), 1);
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

impl quic::ManageStream for ConnectionClient {
    type StreamWriter = crate::dhttp::protocol::BoxDynQuicStreamWriter;
    type StreamReader = crate::dhttp::protocol::BoxDynQuicStreamReader;

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            let (reader, writer) = Connection::open_bi(&client).await?;
            Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Self::StreamWriter, ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            let writer = Connection::open_uni(&client).await?;
            Ok(writer.into_boxed_quic())
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            let (reader, writer) = Connection::accept_bi(&client).await?;
            Ok((reader.into_boxed_quic(), writer.into_boxed_quic()))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Self::StreamReader, ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            let reader = Connection::accept_uni(&client).await?;
            Ok(reader.into_boxed_quic())
        })
    }
}

impl quic::WithLocalAgent for ConnectionClient {
    type LocalAgent = CachedLocalAgent;

    fn local_agent(&self) -> BoxFuture<'_, Result<Option<Self::LocalAgent>, ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            match Connection::local_agent(&client).await? {
                Some(agent) => Ok(Some(CachedLocalAgent::from_client(agent).await?)),
                None => Ok(None),
            }
        })
    }
}

impl quic::WithRemoteAgent for ConnectionClient {
    type RemoteAgent = CachedRemoteAgent;

    fn remote_agent(&self) -> BoxFuture<'_, Result<Option<Self::RemoteAgent>, ConnectionError>> {
        let client = self.clone();
        Box::pin(async move {
            match Connection::remote_agent(&client).await? {
                Some(agent) => Ok(Some(CachedRemoteAgent::from_client(agent).await?)),
                None => Ok(None),
            }
        })
    }
}

impl quic::Lifecycle for ConnectionClient {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        let client = self.clone();
        tokio::spawn(
            async move {
                let _ = Connection::close(&client, code, reason).await;
            }
            .in_current_span(),
        );
    }

    fn check(&self) -> Result<(), ConnectionError> {
        if RemocClient::is_closed(self) {
            Err(quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: VarInt::from_u32(0x01),
                    frame_type: VarInt::from_u32(0x00),
                    reason: "remoc connection channel closed".into(),
                },
            })
        } else {
            Ok(())
        }
    }

    fn closed(&self) -> BoxFuture<'_, ConnectionError> {
        let client = self.clone();
        Box::pin(async move {
            match Connection::closed(&client).await {
                Ok(error) | Err(error) => error,
            }
        })
    }
}

struct ServedConnection<C> {
    connection: C,
    tasks: TaskSet,
}

struct ServedReadStream<R> {
    inner: tokio::sync::Mutex<std::pin::Pin<Box<R>>>,
}

impl<R> ServedReadStream<R> {
    fn new(stream: R) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Box::pin(stream)),
        }
    }
}

impl<R> stream::ReadStream for ServedReadStream<R>
where
    R: quic::ReadStream + 'static,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.as_mut().stream_id().await
    }

    async fn read(&mut self) -> Result<Option<bytes::Bytes>, quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.next().await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.as_mut().stop(code).await
    }
}

struct ServedWriteStream<W> {
    inner: tokio::sync::Mutex<std::pin::Pin<Box<W>>>,
}

impl<W> ServedWriteStream<W> {
    fn new(stream: W) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Box::pin(stream)),
        }
    }
}

impl<W> stream::WriteStream for ServedWriteStream<W>
where
    W: quic::WriteStream + 'static,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.as_mut().stream_id().await
    }

    async fn write(&mut self, data: bytes::Bytes) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.send(data).await
    }

    async fn flush(&mut self) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        SinkExt::flush(&mut *stream).await
    }

    async fn shutdown(&mut self) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.close().await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        stream.as_mut().cancel(code).await
    }
}

impl<C> ServedConnection<C> {
    fn new(connection: C) -> Self {
        Self {
            connection,
            tasks: TaskSet::new(),
        }
    }
}

fn serve_read_stream(
    reader: impl quic::ReadStream + 'static,
) -> (ReadStreamClient, impl Future<Output = ()> + Send + 'static) {
    let (server, client) = stream::ReadStreamServerSharedMut::new(
        Arc::new(tokio::sync::RwLock::new(ServedReadStream::new(reader))),
        1,
    );
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

fn serve_write_stream(
    writer: impl quic::WriteStream + 'static,
) -> (WriteStreamClient, impl Future<Output = ()> + Send + 'static) {
    let (server, client) = stream::WriteStreamServerSharedMut::new(
        Arc::new(tokio::sync::RwLock::new(ServedWriteStream::new(writer))),
        1,
    );
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

impl<C> Connection for ServedConnection<C>
where
    C: quic::Connection + 'static,
    C::LocalAgent: Send + Sync,
    C::RemoteAgent: Send + Sync,
{
    async fn open_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = self.connection.open_bi().await?;
        let (read_client, read_fut) = serve_read_stream(reader);
        let (write_client, write_fut) = serve_write_stream(writer);
        self.tasks.spawn(read_fut);
        self.tasks.spawn(write_fut);
        Ok((read_client, write_client))
    }

    async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError> {
        let writer = self.connection.open_uni().await?;
        let (client, fut) = serve_write_stream(writer);
        self.tasks.spawn(fut);
        Ok(client)
    }

    async fn accept_bi(
        &self,
    ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
        let (reader, writer) = self.connection.accept_bi().await?;
        let (read_client, read_fut) = serve_read_stream(reader);
        let (write_client, write_fut) = serve_write_stream(writer);
        self.tasks.spawn(read_fut);
        self.tasks.spawn(write_fut);
        Ok((read_client, write_client))
    }

    async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError> {
        let reader = self.connection.accept_uni().await?;
        let (client, fut) = serve_read_stream(reader);
        self.tasks.spawn(fut);
        Ok(client)
    }

    async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError> {
        match self.connection.local_agent().await? {
            Some(agent) => {
                let (server, client) =
                    super::agent::LocalAgentServerShared::new(Arc::new(agent), 1);
                self.tasks.spawn(async move {
                    let _ = server.serve(true).await;
                });
                Ok(Some(client))
            }
            None => Ok(None),
        }
    }

    async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError> {
        match self.connection.remote_agent().await? {
            Some(agent) => {
                let (server, client) =
                    super::agent::RemoteAgentServerShared::new(Arc::new(agent), 1);
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
        self.connection.close(code, reason);
        Ok(())
    }

    async fn closed(&self) -> Result<quic::ConnectionError, quic::ConnectionError> {
        Ok(self.connection.closed().await)
    }
}
