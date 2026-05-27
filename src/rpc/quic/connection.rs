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
    use std::{
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::Bytes;
    use dhttp_identity::identity::{self as agent, SignError};
    use futures::{Sink, SinkExt, Stream, StreamExt, future::BoxFuture};
    use remoc::prelude::ServerShared;
    use rustls::{SignatureScheme, pki_types::CertificateDer};
    use tokio_util::task::AbortOnDropHandle;

    use super::*;
    use crate::{
        codec::{BoxReadStream, BoxWriteStream},
        dquic::cert::handy::ToCertificate,
        quic::{CancelStream, GetStreamId, GetStreamIdExt, StopStream, StopStreamExt},
    };

    const SERVER_CERT: &[u8] = include_bytes!("../../../tests/keychain/localhost/server.cert");

    #[derive(Clone, Debug)]
    struct TestLocalAgent {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl TestLocalAgent {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: SERVER_CERT.to_certificate(),
            }
        }
    }

    impl agent::LocalAgent for TestLocalAgent {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
            rustls::SignatureAlgorithm::ECDSA
        }

        fn sign(
            &self,
            scheme: SignatureScheme,
            data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
            let signature = expected_signature(scheme, data);
            Box::pin(std::future::ready(Ok(signature)))
        }
    }

    #[derive(Clone, Debug)]
    struct TestRemoteAgent {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl TestRemoteAgent {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                cert_chain: SERVER_CERT.to_certificate(),
            }
        }
    }

    impl agent::RemoteAgent for TestRemoteAgent {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }
    }

    struct TestQuicConnection {
        open_bi_error: Option<quic::ConnectionError>,
        open_uni_error: Option<quic::ConnectionError>,
        accept_bi_error: Option<quic::ConnectionError>,
        accept_uni_error: Option<quic::ConnectionError>,
        local_agent: Option<TestLocalAgent>,
        local_agent_error: Option<quic::ConnectionError>,
        remote_agent: Option<TestRemoteAgent>,
        remote_agent_error: Option<quic::ConnectionError>,
        terminal: Mutex<Option<quic::ConnectionError>>,
        closes: Mutex<Vec<(Code, Cow<'static, str>)>>,
    }

    impl TestQuicConnection {
        fn new() -> Self {
            Self {
                open_bi_error: None,
                open_uni_error: None,
                accept_bi_error: None,
                accept_uni_error: None,
                local_agent: None,
                local_agent_error: None,
                remote_agent: None,
                remote_agent_error: None,
                terminal: Mutex::new(None),
                closes: Mutex::new(Vec::new()),
            }
        }

        fn with_agents() -> Self {
            Self {
                local_agent: Some(TestLocalAgent::new("local.example")),
                remote_agent: Some(TestRemoteAgent::new("remote.example")),
                ..Self::new()
            }
        }

        fn fail_open_bi(reason: &'static str) -> Self {
            Self {
                open_bi_error: Some(connection_error(reason)),
                ..Self::new()
            }
        }

        fn fail_open_uni(reason: &'static str) -> Self {
            Self {
                open_uni_error: Some(connection_error(reason)),
                ..Self::new()
            }
        }

        fn fail_accept_bi(reason: &'static str) -> Self {
            Self {
                accept_bi_error: Some(connection_error(reason)),
                ..Self::new()
            }
        }

        fn fail_accept_uni(reason: &'static str) -> Self {
            Self {
                accept_uni_error: Some(connection_error(reason)),
                ..Self::new()
            }
        }

        fn fail_local_agent(reason: &'static str) -> Self {
            Self {
                local_agent_error: Some(connection_error(reason)),
                ..Self::new()
            }
        }

        fn fail_remote_agent(reason: &'static str) -> Self {
            Self {
                remote_agent_error: Some(connection_error(reason)),
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
    }

    impl quic::ManageStream for TestQuicConnection {
        type StreamReader = BoxReadStream;
        type StreamWriter = BoxWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            if let Some(error) = &self.open_bi_error {
                return Err(error.clone());
            }
            let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(1));
            Ok((
                Box::pin(reader) as BoxReadStream,
                Box::pin(writer) as BoxWriteStream,
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            if let Some(error) = &self.open_uni_error {
                return Err(error.clone());
            }
            let (_reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(2));
            Ok(Box::pin(writer) as BoxWriteStream)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            if let Some(error) = &self.accept_bi_error {
                return Err(error.clone());
            }
            let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(3));
            Ok((
                Box::pin(reader) as BoxReadStream,
                Box::pin(writer) as BoxWriteStream,
            ))
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            if let Some(error) = &self.accept_uni_error {
                return Err(error.clone());
            }
            let (reader, _writer) = quic::test::mock_stream_pair(VarInt::from_u32(4));
            Ok(Box::pin(reader) as BoxReadStream)
        }
    }

    impl quic::WithLocalAgent for TestQuicConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, quic::ConnectionError> {
            if let Some(error) = &self.local_agent_error {
                return Err(error.clone());
            }
            Ok(self.local_agent.clone())
        }
    }

    impl quic::WithRemoteAgent for TestQuicConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, quic::ConnectionError> {
            if let Some(error) = &self.remote_agent_error {
                return Err(error.clone());
            }
            Ok(self.remote_agent.clone())
        }
    }

    impl quic::Lifecycle for TestQuicConnection {
        fn close(&self, code: Code, reason: Cow<'static, str>) {
            self.closes
                .lock()
                .expect("closes mutex should not be poisoned")
                .push((code, reason));
        }

        fn check(&self) -> Result<(), quic::ConnectionError> {
            match self
                .terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
            {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn closed(&self) -> quic::ConnectionError {
            self.terminal
                .lock()
                .expect("terminal mutex should not be poisoned")
                .clone()
                .unwrap_or_else(|| connection_error("quic closed"))
        }
    }

    #[derive(Clone)]
    struct BrokenIdReadStream {
        error: quic::StreamError,
    }

    impl GetStreamId for BrokenIdReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Err(self.get_mut().error.clone()))
        }
    }

    impl StopStream for BrokenIdReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for BrokenIdReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(None)
        }
    }

    #[derive(Clone)]
    struct BrokenIdWriteStream {
        error: quic::StreamError,
    }

    impl GetStreamId for BrokenIdWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Err(self.get_mut().error.clone()))
        }
    }

    impl CancelStream for BrokenIdWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for BrokenIdWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct BrokenIdQuicConnection;

    impl quic::ManageStream for BrokenIdQuicConnection {
        type StreamReader = BoxReadStream;
        type StreamWriter = BoxWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            Ok((
                Box::pin(BrokenIdReadStream {
                    error: stream_connection_error("open bidi reader stream id failed"),
                }) as BoxReadStream,
                Box::pin(BrokenIdWriteStream {
                    error: stream_connection_error("open bidi writer stream id failed"),
                }) as BoxWriteStream,
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(Box::pin(BrokenIdWriteStream {
                error: stream_connection_error("open uni writer stream id failed"),
            }) as BoxWriteStream)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            Ok((
                Box::pin(BrokenIdReadStream {
                    error: stream_connection_error("accept bidi reader stream id failed"),
                }) as BoxReadStream,
                Box::pin(BrokenIdWriteStream {
                    error: stream_connection_error("accept bidi writer stream id failed"),
                }) as BoxWriteStream,
            ))
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            Ok(Box::pin(BrokenIdReadStream {
                error: stream_connection_error("accept uni reader stream id failed"),
            }) as BoxReadStream)
        }
    }

    impl quic::WithLocalAgent for BrokenIdQuicConnection {
        type LocalAgent = TestLocalAgent;

        async fn local_agent(&self) -> Result<Option<Self::LocalAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAgent for BrokenIdQuicConnection {
        type RemoteAgent = TestRemoteAgent;

        async fn remote_agent(&self) -> Result<Option<Self::RemoteAgent>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for BrokenIdQuicConnection {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            connection_error("broken id closed")
        }
    }

    fn spawn_rpc_connection<C>(connection: Arc<C>) -> (AbortOnDropHandle<()>, ConnectionClient)
    where
        C: super::Connection + 'static,
    {
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

    fn stream_connection_error(reason: &'static str) -> quic::StreamError {
        quic::StreamError::Connection {
            source: connection_error(reason),
        }
    }

    fn assert_reason(error: &quic::ConnectionError, expected: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    fn assert_stream_reason(error: &quic::StreamError, expected: &str) {
        let quic::StreamError::Connection { source } = error else {
            panic!("expected connection-scoped stream error");
        };
        assert_reason(source, expected);
    }

    fn expected_signature(scheme: SignatureScheme, data: &[u8]) -> Vec<u8> {
        let mut signature = u16::from(scheme).to_be_bytes().to_vec();
        signature.extend_from_slice(data);
        signature
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
        let connection = Arc::new(TestQuicConnection::new());
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
        let connection = Arc::new(TestQuicConnection::with_agents());
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

        let local_agent = quic::WithLocalAgent::local_agent(&remote)
            .await
            .expect("local agent")
            .expect("local agent should exist");
        assert_eq!(agent::LocalAgent::name(&local_agent), "local.example");
        assert_eq!(agent::LocalAgent::cert_chain(&local_agent).len(), 1);
        assert_eq!(
            agent::LocalAgent::sign_algorithm(&local_agent),
            rustls::SignatureAlgorithm::ECDSA,
        );
        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        let signature = agent::LocalAgent::sign(&local_agent, scheme, b"payload")
            .await
            .expect("local agent sign");
        assert_eq!(signature, expected_signature(scheme, b"payload"));

        let remote_agent = quic::WithRemoteAgent::remote_agent(&remote)
            .await
            .expect("remote agent")
            .expect("remote agent should exist");
        assert_eq!(agent::RemoteAgent::name(&remote_agent), "remote.example");
        assert_eq!(agent::RemoteAgent::cert_chain(&remote_agent).len(), 1);

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
    async fn remote_connection_preserves_absent_agents() {
        let connection = Arc::new(TestQuicConnection::new());
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let local_agent = quic::WithLocalAgent::local_agent(&remote)
            .await
            .expect("local agent lookup should succeed");
        assert!(local_agent.is_none());

        let remote_agent = quic::WithRemoteAgent::remote_agent(&remote)
            .await
            .expect("remote agent lookup should succeed");
        assert!(remote_agent.is_none());

        quic::Lifecycle::check(&remote).expect("absent agents should not close connection");
    }

    #[tokio::test]
    async fn remote_connection_latches_agent_lookup_errors() {
        let connection = Arc::new(TestQuicConnection::fail_local_agent(
            "local agent lookup failed",
        ));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let Err(error) = quic::WithLocalAgent::local_agent(&remote).await else {
            panic!("local agent error should surface");
        };
        assert_reason(&error, "local agent lookup failed");

        let latched = quic::Lifecycle::check(&remote).expect_err("local agent error should latch");
        assert_reason(&latched, "local agent lookup failed");

        let connection = Arc::new(TestQuicConnection::fail_remote_agent(
            "remote agent lookup failed",
        ));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let Err(error) = quic::WithRemoteAgent::remote_agent(&remote).await else {
            panic!("remote agent error should surface");
        };
        assert_reason(&error, "remote agent lookup failed");

        let closed = quic::Lifecycle::closed(&remote).await;
        assert_reason(&closed, "remote agent lookup failed");
    }

    #[tokio::test]
    async fn remote_connection_latches_remote_errors() {
        let connection = Arc::new(TestQuicConnection::fail_open_bi("quic open bidi failed"));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let Err(error) = quic::ManageStream::open_bi(&remote).await else {
            panic!("open error should surface");
        };
        assert_reason(&error, "quic open bidi failed");

        let latched = quic::Lifecycle::check(&remote).expect_err("open error should latch");
        assert_reason(&latched, "quic open bidi failed");

        let closed = quic::Lifecycle::closed(&remote).await;
        assert_reason(&closed, "quic open bidi failed");
    }

    #[tokio::test]
    async fn remote_connection_maps_each_stream_operation_error() {
        let connection = Arc::new(TestQuicConnection::fail_open_uni("quic open uni failed"));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();
        let Err(error) = quic::ManageStream::open_uni(&remote).await else {
            panic!("open uni error should surface");
        };
        assert_reason(&error, "quic open uni failed");

        let connection = Arc::new(TestQuicConnection::fail_accept_bi(
            "quic accept bidi failed",
        ));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();
        let Err(error) = quic::ManageStream::accept_bi(&remote).await else {
            panic!("accept bidi error should surface");
        };
        assert_reason(&error, "quic accept bidi failed");

        let connection = Arc::new(TestQuicConnection::fail_accept_uni(
            "quic accept uni failed",
        ));
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();
        let Err(error) = quic::ManageStream::accept_uni(&remote).await else {
            panic!("accept uni error should surface");
        };
        assert_reason(&error, "quic accept uni failed");
    }

    #[tokio::test]
    async fn remote_connection_synthesizes_remoc_channel_errors_when_server_stops() {
        let connection = Arc::new(TestQuicConnection::new());
        let (task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();
        drop(task);

        let error = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match quic::Lifecycle::check(&remote) {
                    Ok(()) => tokio::task::yield_now().await,
                    Err(error) => break error,
                }
            }
        })
        .await
        .expect("lifecycle check should complete in time");
        assert_reason(&error, "remoc connection channel closed");

        let closed = tokio::time::timeout(Duration::from_secs(1), quic::Lifecycle::closed(&remote))
            .await
            .expect("connection closed should complete in time");
        assert_reason(&closed, "remoc connection channel closed");

        let Err(error) = quic::ManageStream::open_uni(&remote).await else {
            panic!("closed remoc connection should reject operations");
        };
        assert_reason(&error, "remoc connection channel closed");
    }

    #[tokio::test]
    async fn remote_connection_boxed_streams_surface_stream_id_failures() {
        let connection = Arc::new(BrokenIdQuicConnection);
        let (_task, client) = spawn_rpc_connection(connection);
        let remote = client.into_quic();

        let (mut reader, mut writer) = quic::ManageStream::open_bi(&remote)
            .await
            .expect("open bidi should return boxed streams");
        let error = reader
            .stream_id()
            .await
            .expect_err("reader stream id should fail");
        assert_stream_reason(&error, "open bidi reader stream id failed");
        let error = writer
            .stream_id()
            .await
            .expect_err("writer stream id should fail");
        assert_stream_reason(&error, "open bidi writer stream id failed");

        let mut writer = quic::ManageStream::open_uni(&remote)
            .await
            .expect("open uni should return boxed writer");
        let error = writer
            .stream_id()
            .await
            .expect_err("writer stream id should fail");
        assert_stream_reason(&error, "open uni writer stream id failed");

        let (mut reader, mut writer) = quic::ManageStream::accept_bi(&remote)
            .await
            .expect("accept bidi should return boxed streams");
        let error = reader
            .stream_id()
            .await
            .expect_err("reader stream id should fail");
        assert_stream_reason(&error, "accept bidi reader stream id failed");
        let error = writer
            .stream_id()
            .await
            .expect_err("writer stream id should fail");
        assert_stream_reason(&error, "accept bidi writer stream id failed");

        let mut reader = quic::ManageStream::accept_uni(&remote)
            .await
            .expect("accept uni should return boxed reader");
        let error = reader
            .stream_id()
            .await
            .expect_err("reader stream id should fail");
        assert_stream_reason(&error, "accept uni reader stream id failed");
    }
}
