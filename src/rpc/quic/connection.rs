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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt};
    use remoc::prelude::ServerShared;
    use tokio_util::task::AbortOnDropHandle;

    use super::*;
    use crate::{
        codec::{BoxReadStream, BoxWriteStream},
        quic::{GetStreamIdExt, StopStreamExt},
    };

    struct TestRpcConnection {
        fail_open: bool,
        terminal: Mutex<Option<quic::ConnectionError>>,
        closes: Mutex<Vec<(Code, Cow<'static, str>)>>,
        tasks: Mutex<Vec<AbortOnDropHandle<()>>>,
    }

    impl TestRpcConnection {
        fn new() -> Self {
            Self {
                fail_open: false,
                terminal: Mutex::new(None),
                closes: Mutex::new(Vec::new()),
                tasks: Mutex::new(Vec::new()),
            }
        }

        fn fail_open() -> Self {
            Self {
                fail_open: true,
                ..Self::new()
            }
        }

        fn set_terminal(&self, error: quic::ConnectionError) {
            *self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned") = Some(error);
        }

        fn closes(&self) -> Vec<(Code, Cow<'static, str>)> {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .clone()
        }

        fn stream_pair(&self, stream_id: u32) -> (ReadStreamClient, WriteStreamClient) {
            let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (reader_server, reader_client) =
                stream::ReadStreamServer::new(Box::pin(reader) as BoxReadStream, 1);
            let (writer_server, writer_client) =
                stream::WriteStreamServer::new(Box::pin(writer) as BoxWriteStream, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = reader_server.serve().await;
                }
                .in_current_span(),
            ));
            self.push_task(tokio::spawn(
                async move {
                    let _ = writer_server.serve().await;
                }
                .in_current_span(),
            ));
            (reader_client, writer_client)
        }

        fn read_stream(&self, stream_id: u32) -> ReadStreamClient {
            let (reader, _writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (reader_server, reader_client) =
                stream::ReadStreamServer::new(Box::pin(reader) as BoxReadStream, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = reader_server.serve().await;
                }
                .in_current_span(),
            ));
            reader_client
        }

        fn write_stream(&self, stream_id: u32) -> WriteStreamClient {
            let (_reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
            let (writer_server, writer_client) =
                stream::WriteStreamServer::new(Box::pin(writer) as BoxWriteStream, 1);
            self.push_task(tokio::spawn(
                async move {
                    let _ = writer_server.serve().await;
                }
                .in_current_span(),
            ));
            writer_client
        }

        fn push_task(&self, task: tokio::task::JoinHandle<()>) {
            self.tasks
                .lock()
                .expect("tasks mutex should not be poisoned")
                .push(AbortOnDropHandle::new(task));
        }
    }

    impl super::Connection for TestRpcConnection {
        async fn open_bi(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
            if self.fail_open {
                return Err(connection_error("rpc open failed"));
            }
            Ok(self.stream_pair(1))
        }

        async fn open_uni(&self) -> Result<WriteStreamClient, quic::ConnectionError> {
            if self.fail_open {
                return Err(connection_error("rpc open failed"));
            }
            Ok(self.write_stream(2))
        }

        async fn accept_bi(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError> {
            Ok(self.stream_pair(3))
        }

        async fn accept_uni(&self) -> Result<ReadStreamClient, quic::ConnectionError> {
            Ok(self.read_stream(4))
        }

        async fn local_agent(&self) -> Result<Option<LocalAgentClient>, quic::ConnectionError> {
            Ok(None)
        }

        async fn remote_agent(&self) -> Result<Option<RemoteAgentClient>, quic::ConnectionError> {
            Ok(None)
        }

        async fn close(
            &self,
            code: Code,
            reason: Cow<'static, str>,
        ) -> Result<(), quic::ConnectionError> {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .push((code, reason));
            Ok(())
        }

        async fn closed(&self) -> Result<quic::ConnectionError, quic::ConnectionError> {
            Ok(self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
                .unwrap_or_else(|| connection_error("rpc closed")))
        }
    }

    fn spawn_rpc_connection(
        connection: Arc<TestRpcConnection>,
    ) -> (AbortOnDropHandle<()>, ConnectionClient) {
        let (server, client) = ConnectionServerShared::new(connection, 1);
        let task = AbortOnDropHandle::new(tokio::spawn(
            async move {
                let _ = server.serve(true).await;
            }
            .in_current_span(),
        ));
        (task, client)
    }

    fn connection_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_reason(error: &quic::ConnectionError, expected: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    async fn assert_roundtrip(
        reader: &mut (impl Stream<Item = Result<Bytes, quic::StreamError>> + Unpin),
        writer: &mut (impl Sink<Bytes, Error = quic::StreamError> + Unpin),
        payload: &'static [u8],
    ) {
        let bytes = Bytes::from_static(payload);
        writer.send(bytes.clone()).await.expect("write");
        let received = reader
            .next()
            .await
            .expect("reader should produce one chunk")
            .expect("read");
        assert_eq!(received, bytes);
    }

    #[tokio::test]
    async fn remote_connection_conversions_preserve_client() {
        let connection = Arc::new(TestRpcConnection::new());
        let (_task, client) = spawn_rpc_connection(connection);

        let remote = ConnectionClient::into_quic(client);
        let client = remote.clone().into_inner();
        let remote = RemoteConnection::from(client);
        let client = ConnectionClient::from(remote);
        let remote = client.into_quic();

        let mut writer = quic::ManageStream::open_uni(&remote)
            .await
            .expect("open uni");
        assert_eq!(
            writer.stream_id().await.expect("stream id"),
            VarInt::from_u32(2)
        );
    }

    #[tokio::test]
    async fn remote_connection_delegates_stream_operations_and_agents() {
        let connection = Arc::new(TestRpcConnection::new());
        let (_task, client) = spawn_rpc_connection(connection.clone());
        let remote = client.into_quic();

        quic::Lifecycle::check(&remote).expect("fresh connection should be live");

        let (mut reader, mut writer) = quic::ManageStream::open_bi(&remote)
            .await
            .expect("open bidi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(1)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(1)
        );
        assert_roundtrip(&mut reader, &mut writer, b"open-bidi").await;

        let mut writer = quic::ManageStream::open_uni(&remote)
            .await
            .expect("open uni");
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(2)
        );

        let (mut reader, mut writer) = quic::ManageStream::accept_bi(&remote)
            .await
            .expect("accept bidi");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(3)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(3)
        );
        assert_roundtrip(&mut reader, &mut writer, b"accept-bidi").await;

        let mut reader = quic::ManageStream::accept_uni(&remote)
            .await
            .expect("accept uni");
        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(4)
        );
        reader
            .stop(VarInt::from_u32(10))
            .await
            .expect("stop accepted reader");

        assert!(
            quic::WithLocalAgent::local_agent(&remote)
                .await
                .expect("local agent")
                .is_none()
        );
        assert!(
            quic::WithRemoteAgent::remote_agent(&remote)
                .await
                .expect("remote agent")
                .is_none()
        );

        quic::Lifecycle::close(&remote, Code::H3_NO_ERROR, "bye".into());
        for _ in 0..20 {
            if !connection.closes().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            connection.closes(),
            vec![(Code::H3_NO_ERROR, Cow::Borrowed("bye"))],
        );

        connection.set_terminal(connection_error("terminal"));
        let closed = quic::Lifecycle::closed(&remote).await;
        assert_reason(&closed, "terminal");
        let latched = quic::Lifecycle::check(&remote).expect_err("closed should latch");
        assert_reason(&latched, "terminal");
    }

    #[tokio::test]
    async fn remote_connection_latches_remote_errors() {
        let connection = Arc::new(TestRpcConnection::fail_open());
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let Err(error) = quic::ManageStream::open_bi(&remote).await else {
            panic!("open error should surface");
        };
        assert_reason(&error, "rpc open failed");

        let latched = quic::Lifecycle::check(&remote).expect_err("open error should latch");
        assert_reason(&latched, "rpc open failed");

        let closed = quic::Lifecycle::closed(&remote).await;
        assert_reason(&closed, "rpc open failed");
    }
}
