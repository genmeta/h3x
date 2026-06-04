use std::{error::Error, sync::Arc};

use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Empty};
use snafu::{ResultExt, Snafu};
use tracing::Instrument;

use crate::{
    connection::Connection,
    hyper::SendMessageError,
    message::stream::{
        InitialMessageStreamError, MessageStreamError,
        hyper::{
            read::Either,
            upgrade::{RemainStream, TakeoverSlot},
            write::send_message_error,
        },
    },
    qpack::field::{Protocol, hyper::validated_hyper_request_parts_to_field_lines},
    quic::{self, GetStreamIdExt},
    stream_id::StreamId,
};

fn protocol_from_extensions(extensions: &http::Extensions) -> Option<Protocol> {
    if let Some(protocol) = extensions.get::<Protocol>() {
        return Some(protocol.clone());
    }

    extensions.get::<::hyper::ext::Protocol>().map(|protocol| {
        Protocol::try_from(Bytes::copy_from_slice(protocol.as_ref()))
            .expect("hyper protocol token is valid UTF-8")
    })
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum RequestError<E: Error + 'static> {
    #[snafu(display("failed to open initial message stream"))]
    InitialStream { source: InitialMessageStreamError },
    #[snafu(display("failed to send request"))]
    SendRequest { source: SendMessageError<E> },
    #[snafu(display("failed to receive response"))]
    ReceiveResponse { source: MessageStreamError },
    #[snafu(display("failed to read request stream ID"))]
    StreamId { source: quic::StreamError },
}

impl<E: Error + 'static> From<InitialMessageStreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: InitialMessageStreamError) -> Self {
        RequestError::InitialStream { source }
    }
}

impl<E: Error + 'static> From<SendMessageError<E>> for RequestError<E> {
    #[track_caller]
    fn from(source: SendMessageError<E>) -> Self {
        RequestError::SendRequest { source }
    }
}

impl<E: Error + 'static> From<MessageStreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: MessageStreamError) -> Self {
        RequestError::ReceiveResponse { source }
    }
}

impl<C: quic::Connection> Connection<C> {
    /// Execute a hyper-compatible HTTP request over this H3 connection.
    ///
    /// The response body type is intentionally opaque and does not guarantee
    /// [`Unpin`]. This keeps the native streaming body shape visible to the
    /// compiler instead of imposing a boxing policy on every caller. Callers
    /// that need an [`Unpin`] body should choose the pinning or boxing strategy
    /// appropriate for that call site, such as `pin!`, `Pin<Box<_>>`, or an
    /// `http_body_util` boxed body.
    #[tracing::instrument(level = "debug", skip_all, fields(method = %request.method(), uri = %request.uri()))]
    pub async fn execute_hyper_request<B: Body + Send + 'static>(
        &self,
        request: http::Request<B>,
    ) -> Result<
        http::Response<impl Body<Data = Bytes, Error = MessageStreamError> + use<B, C>>,
        RequestError<B::Error>,
    >
    where
        B::Data: Send,
        B::Error: Error + Send + 'static,
    {
        let is_connect = request.method() == http::Method::CONNECT;
        let protocol = if is_connect {
            protocol_from_extensions(request.extensions())
        } else {
            None
        };
        let (parts, body) = request.into_parts();
        let fields = validated_hyper_request_parts_to_field_lines(parts)
            .context(send_message_error::MalformedHeaderSnafu)?;
        let (mut read_stream, mut write_stream) = self.initial_message_stream().await?;

        if is_connect {
            // CONNECT: no body or trailers — join send + receive headers.
            let stream_id = write_stream
                .stream_id()
                .await
                .context(request_error::StreamIdSnafu)?;
            let (send_result, recv_result) = tokio::join!(
                async {
                    write_stream
                        .write_header(fields)
                        .await
                        .context(send_message_error::StreamSnafu)
                },
                async {
                    loop {
                        let parts = read_stream.read_hyper_response_parts().await?;
                        if !parts.status.is_informational() {
                            return Ok::<_, MessageStreamError>(parts);
                        }
                        tracing::debug!(
                            status = %parts.status,
                            headers = ?parts.headers,
                            "skipping informational response",
                        );
                    }
                },
            );
            send_result?;
            let mut response_parts = recv_result?;

            response_parts.extensions.insert(StreamId::from(stream_id));
            response_parts.extensions.insert(Arc::new(self.erase()));
            if let Some(protocol) = protocol {
                response_parts.extensions.insert(protocol);
            }
            response_parts
                .extensions
                .insert(TakeoverSlot::new(RemainStream::immediately(read_stream)));
            response_parts
                .extensions
                .insert(TakeoverSlot::new(RemainStream::immediately(write_stream)));
            let body = Either::right(Empty::new().map_err(|never| match never {}));
            Ok(http::Response::from_parts(response_parts, body))
        } else {
            // Non-CONNECT: send headers, spawn body sender, read response.
            write_stream
                .write_header(fields)
                .await
                .context(send_message_error::StreamSnafu)?;

            // Spawn background task to send request body + close write stream.
            // Guard ensures stream cleanup on failure.
            tokio::spawn(
                async move {
                    if write_stream.send_hyper_body(body).await.is_ok() {
                        _ = write_stream.close().await;
                    }
                }
                .in_current_span(),
            );

            // Read response headers, skipping informational.
            let mut response_parts = read_stream.read_hyper_response_parts().await?;
            while response_parts.status.is_informational() {
                tracing::debug!(
                    status = %response_parts.status,
                    headers = ?response_parts.headers,
                    "skipping informational response",
                );
                response_parts = read_stream.read_hyper_response_parts().await?;
            }

            let body = Either::left(read_stream.into_hyper_body());
            Ok(http::Response::from_parts(response_parts, body))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        fmt,
        future::pending,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, Ordering},
        },
        task::{Context, Poll},
    };

    use futures::{Sink, SinkExt, Stream};
    use http::Extensions;
    use http_body_util::{BodyExt, Full};

    use super::*;
    use crate::{
        codec::{SinkWriter, StreamReader},
        connection::{ConnectionBuilder, ConnectionState, StreamError},
        dhttp::{protocol::DHttpProtocol, settings::Settings},
        message::stream::{MessageReader, MessageWriter, guard},
        protocol::Protocols,
        qpack::{
            decoder::DecoderInstruction,
            encoder::EncoderInstruction,
            field::MalformedHeaderSection,
            protocol::{QPackDecoder, QPackEncoder},
        },
        varint::VarInt,
    };

    struct ClientReadStream {
        stream_id: Result<VarInt, quic::StreamError>,
        inner: quic::BoxQuicStreamReader,
    }

    impl ClientReadStream {
        fn new(
            stream_id: Result<VarInt, quic::StreamError>,
            inner: quic::BoxQuicStreamReader,
        ) -> Self {
            Self { stream_id, inner }
        }
    }

    impl Unpin for ClientReadStream {}

    impl quic::GetStreamId for ClientReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(self.get_mut().stream_id.clone())
        }
    }

    impl quic::StopStream for ClientReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.get_mut().inner.as_mut().poll_stop(cx, code)
        }
    }

    impl Stream for ClientReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.get_mut().inner.as_mut().poll_next(cx)
        }
    }

    struct ClientWriteStream {
        stream_id: Result<VarInt, quic::StreamError>,
        inner: quic::BoxQuicStreamWriter,
    }

    impl ClientWriteStream {
        fn new(
            stream_id: Result<VarInt, quic::StreamError>,
            inner: quic::BoxQuicStreamWriter,
        ) -> Self {
            Self { stream_id, inner }
        }
    }

    impl Unpin for ClientWriteStream {}

    impl quic::GetStreamId for ClientWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(self.get_mut().stream_id.clone())
        }
    }

    impl quic::ResetStream for ClientWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.get_mut().inner.as_mut().poll_reset(cx, code)
        }
    }

    impl Sink<Bytes> for ClientWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.as_mut().poll_ready(cx)
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.get_mut().inner.as_mut().start_send(item)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.as_mut().poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut().inner.as_mut().poll_close(cx)
        }
    }

    #[derive(Default)]
    struct QueuedConnection {
        bi_streams: Mutex<VecDeque<(ClientReadStream, ClientWriteStream)>>,
        next_uni_stream_id: AtomicU32,
        uni_readers: Mutex<Vec<quic::BoxQuicStreamReader>>,
    }

    impl fmt::Debug for QueuedConnection {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("QueuedConnection").finish_non_exhaustive()
        }
    }

    impl QueuedConnection {
        fn stage_bi_stream(&self, reader: ClientReadStream, writer: ClientWriteStream) {
            self.bi_streams
                .lock()
                .expect("bi stream queue mutex should not be poisoned")
                .push_back((reader, writer));
        }
    }

    impl quic::ManageStream for QueuedConnection {
        type StreamReader = ClientReadStream;
        type StreamWriter = ClientWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            self.bi_streams
                .lock()
                .expect("bi stream queue mutex should not be poisoned")
                .pop_front()
                .ok_or_else(|| test_connection_error("no staged bidirectional stream"))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            let stream_id =
                VarInt::from_u32(100 + self.next_uni_stream_id.fetch_add(4, Ordering::Relaxed));
            let (reader, writer) = quic::test::mock_stream_pair_with_capacity(stream_id, 256);
            self.uni_readers
                .lock()
                .expect("uni stream reader list mutex should not be poisoned")
                .push(Box::pin(reader));
            Ok(ClientWriteStream::new(Ok(stream_id), Box::pin(writer)))
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAuthority for QueuedConnection {
        type LocalAuthority = crate::connection::tests::TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for QueuedConnection {
        type RemoteAuthority = crate::connection::tests::TestRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for QueuedConnection {
        fn close(&self, _code: crate::error::Code, _reason: std::borrow::Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    fn test_connection_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn qpack_decoder_sink() -> Pin<Box<dyn Sink<DecoderInstruction, Error = StreamError> + Send>> {
        Box::pin(futures::sink::drain::<DecoderInstruction>().sink_map_err(|never| match never {}))
    }

    fn qpack_decoder_stream()
    -> Pin<Box<dyn Stream<Item = Result<EncoderInstruction, StreamError>> + Send>> {
        Box::pin(futures::stream::empty::<
            Result<EncoderInstruction, StreamError>,
        >())
    }

    fn qpack_encoder_sink() -> Pin<Box<dyn Sink<EncoderInstruction, Error = StreamError> + Send>> {
        Box::pin(futures::sink::drain::<EncoderInstruction>().sink_map_err(|never| match never {}))
    }

    fn qpack_encoder_stream()
    -> Pin<Box<dyn Stream<Item = Result<DecoderInstruction, StreamError>> + Send>> {
        Box::pin(futures::stream::empty::<
            Result<DecoderInstruction, StreamError>,
        >())
    }

    fn server_connection_state() -> ConnectionState<dyn quic::DynConnection> {
        let erased: Arc<dyn quic::DynConnection> =
            Arc::new(crate::connection::tests::MockConnection::new());
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        ConnectionState::new_for_test(erased, Arc::new(protocols))
    }

    fn server_streams(
        stream_id: VarInt,
        reader: impl quic::ReadStream + Unpin + 'static,
        writer: impl quic::WriteStream + Unpin + 'static,
    ) -> (MessageReader, MessageWriter) {
        let state = server_connection_state();
        let reader = StreamReader::new(guard::GuardedQuicReader::new(
            Box::pin(reader) as crate::quic::BoxQuicStreamReader
        ));
        let writer = SinkWriter::new(guard::GuardedQuicWriter::new(
            Box::pin(writer) as crate::quic::BoxQuicStreamWriter
        ));

        (
            MessageReader::new(
                stream_id,
                reader,
                Arc::new(QPackDecoder::new(
                    Arc::new(Settings::default()),
                    qpack_decoder_sink(),
                    qpack_decoder_stream(),
                )),
                state.clone(),
            ),
            MessageWriter::new(
                writer,
                Arc::new(QPackEncoder::new(
                    Arc::new(Settings::default()),
                    qpack_encoder_sink(),
                    qpack_encoder_stream(),
                )),
                state,
            ),
        )
    }

    async fn connection_with_staged_bi_stream(
        stream_id: VarInt,
        write_stream_id: Result<VarInt, quic::StreamError>,
    ) -> (Connection<QueuedConnection>, MessageReader, MessageWriter) {
        let quic = Arc::new(QueuedConnection::default());
        let (server_reader, client_writer) =
            quic::test::mock_stream_pair_with_capacity(stream_id, 256);
        let (client_reader, server_writer) =
            quic::test::mock_stream_pair_with_capacity(stream_id, 256);

        quic.stage_bi_stream(
            ClientReadStream::new(Ok(stream_id), Box::pin(client_reader)),
            ClientWriteStream::new(write_stream_id, Box::pin(client_writer)),
        );

        let connection = ConnectionBuilder::new(Arc::new(Settings::default()))
            .build(quic)
            .await
            .expect("connection should build");
        let (server_reader, server_writer) =
            server_streams(stream_id, server_reader, server_writer);

        (connection, server_reader, server_writer)
    }

    async fn connection_without_staged_stream() -> Connection<QueuedConnection> {
        ConnectionBuilder::new(Arc::new(Settings::default()))
            .build(Arc::new(QueuedConnection::default()))
            .await
            .expect("connection should build")
    }

    fn response_parts(status: http::StatusCode) -> http::response::Parts {
        http::Response::builder()
            .status(status)
            .header("x-response", "present")
            .body(())
            .expect("response should be valid")
            .into_parts()
            .0
    }

    #[test]
    fn protocol_from_extensions_captures_h3x_protocol() {
        let mut extensions = Extensions::new();
        extensions.insert(Protocol::new("webtransport"));

        let protocol = protocol_from_extensions(&extensions).expect("protocol is captured");

        assert_eq!(protocol.as_str(), "webtransport");
    }

    #[test]
    fn protocol_from_extensions_captures_hyper_protocol() {
        let mut extensions = Extensions::new();
        extensions.insert(::hyper::ext::Protocol::from_static("websocket"));

        let protocol = protocol_from_extensions(&extensions).expect("protocol is captured");

        assert_eq!(protocol.as_str(), "websocket");
    }

    #[test]
    fn protocol_from_extensions_prefers_h3x_protocol() {
        let mut extensions = Extensions::new();
        extensions.insert(::hyper::ext::Protocol::from_static("websocket"));
        extensions.insert(Protocol::new("webtransport"));

        let protocol = protocol_from_extensions(&extensions).expect("protocol is captured");

        assert_eq!(protocol.as_str(), "webtransport");
    }

    #[test]
    fn protocol_from_extensions_returns_none_without_protocol() {
        let extensions = Extensions::new();

        assert!(protocol_from_extensions(&extensions).is_none());
    }

    #[tokio::test]
    async fn execute_non_connect_sends_request_and_skips_informational_response() {
        let stream_id = VarInt::from_u32(0);
        let (connection, mut server_reader, mut server_writer) =
            connection_with_staged_bi_stream(stream_id, Ok(stream_id)).await;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.test/upload")
            .header("x-request", "present")
            .body(Full::new(Bytes::from_static(b"request body")))
            .expect("request should be valid");

        let client = connection.execute_hyper_request(request);
        let server = async move {
            let request_parts = server_reader
                .read_hyper_request_parts()
                .await
                .expect("request headers should be readable");
            assert_eq!(request_parts.method, http::Method::POST);
            assert_eq!(request_parts.uri, "https://example.test/upload");
            assert_eq!(request_parts.headers["x-request"], "present");

            let request_body = server_reader
                .into_hyper_body()
                .collect()
                .await
                .expect("request body should be readable")
                .to_bytes();
            assert_eq!(request_body, Bytes::from_static(b"request body"));

            server_writer
                .send_hyper_response_parts(response_parts(http::StatusCode::EARLY_HINTS))
                .await
                .expect("informational response should be written");
            server_writer
                .send_hyper_response(
                    http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header("x-final", "present")
                        .body(Full::new(Bytes::from_static(b"response body")))
                        .expect("response should be valid"),
                )
                .await
                .expect("final response should be written");
            server_writer
                .close()
                .await
                .expect("response stream should close");
        };

        let (response, ()) = tokio::join!(client, server);
        let response = response.expect("client response should succeed");

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers()["x-final"], "present");
        let body = response
            .into_body()
            .collect()
            .await
            .expect("response body should be readable")
            .to_bytes();
        assert_eq!(body, Bytes::from_static(b"response body"));
    }

    #[tokio::test]
    async fn execute_connect_returns_upgrade_extensions_and_empty_body() {
        let stream_id = VarInt::from_u32(4);
        let (connection, mut server_reader, mut server_writer) =
            connection_with_staged_bi_stream(stream_id, Ok(stream_id)).await;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.test:443")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");

        let client = connection.execute_hyper_request(request);
        let server = async move {
            let request_parts = server_reader
                .read_hyper_request_parts()
                .await
                .expect("connect headers should be readable");
            assert_eq!(request_parts.method, http::Method::CONNECT);
            assert_eq!(request_parts.uri, "example.test:443");

            server_writer
                .send_hyper_response_parts(response_parts(http::StatusCode::EARLY_HINTS))
                .await
                .expect("informational response should be written");
            server_writer
                .send_hyper_response_parts(response_parts(http::StatusCode::OK))
                .await
                .expect("connect response should be written");
            server_writer
                .close()
                .await
                .expect("connect response stream should close");
        };

        let (response, ()) = tokio::join!(client, server);
        let response = response.expect("connect response should succeed");

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.extensions().get::<StreamId>().copied(),
            Some(StreamId(stream_id))
        );
        assert!(
            response
                .extensions()
                .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()
                .is_some()
        );
        assert!(response.extensions().get::<Protocol>().is_none());
        assert!(
            response
                .extensions()
                .get::<TakeoverSlot<MessageReader>>()
                .is_some()
        );
        assert!(
            response
                .extensions()
                .get::<TakeoverSlot<MessageWriter>>()
                .is_some()
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("connect body should be readable")
            .to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn execute_connect_preserves_protocol_extension() {
        let stream_id = VarInt::from_u32(12);
        let (connection, mut server_reader, mut server_writer) =
            connection_with_staged_bi_stream(stream_id, Ok(stream_id)).await;
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/connect")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");
        request
            .extensions_mut()
            .insert(::hyper::ext::Protocol::from_static("webtransport"));

        let client = connection.execute_hyper_request(request);
        let server = async move {
            let request_parts = server_reader
                .read_hyper_request_parts()
                .await
                .expect("connect headers should be readable");
            assert_eq!(request_parts.method, http::Method::CONNECT);

            server_writer
                .send_hyper_response_parts(response_parts(http::StatusCode::OK))
                .await
                .expect("connect response should be written");
            server_writer
                .close()
                .await
                .expect("connect response stream should close");
        };

        let (response, ()) = tokio::join!(client, server);
        let response = response.expect("connect response should succeed");

        let protocol = response
            .extensions()
            .get::<Protocol>()
            .expect("protocol should be preserved");
        assert_eq!(protocol.as_str(), "webtransport");
    }

    #[tokio::test]
    async fn execute_request_reports_initial_stream_errors() {
        let connection = connection_without_staged_stream().await;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");

        let error = match connection.execute_hyper_request(request).await {
            Ok(_) => panic!("missing staged stream should be reported"),
            Err(error) => error,
        };

        assert!(matches!(error, RequestError::InitialStream { .. }));
    }

    #[tokio::test]
    async fn execute_request_reports_response_read_errors() {
        let stream_id = VarInt::from_u32(16);
        let (connection, mut server_reader, mut server_writer) =
            connection_with_staged_bi_stream(stream_id, Ok(stream_id)).await;
        let request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");

        let client = connection.execute_hyper_request(request);
        let server = async move {
            let request_parts = server_reader
                .read_hyper_request_parts()
                .await
                .expect("request headers should be readable");
            assert_eq!(request_parts.method, http::Method::GET);

            server_writer
                .close()
                .await
                .expect("response stream should close without response");
        };

        let (error, ()) = tokio::join!(
            async {
                match client.await {
                    Ok(_) => panic!("missing response should be reported"),
                    Err(error) => error,
                }
            },
            server,
        );

        assert!(matches!(error, RequestError::ReceiveResponse { .. }));
    }

    #[tokio::test]
    async fn execute_request_reports_malformed_header_as_send_request_error() {
        let connection = connection_without_staged_stream().await;
        let mut request = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");
        request
            .extensions_mut()
            .insert(Protocol::new("webtransport"));

        let error = match connection.execute_hyper_request(request).await {
            Ok(_) => panic!("protocol on non-CONNECT request should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            RequestError::SendRequest {
                source: SendMessageError::MalformedHeader {
                    source: MalformedHeaderSection::ProtocolInNonConnectRequest
                }
            }
        ));
    }

    #[tokio::test]
    async fn execute_connect_reports_stream_id_errors() {
        let stream_id = VarInt::from_u32(8);
        let stream_id_error = quic::StreamError::Reset {
            code: VarInt::from_u32(0x10),
        };
        let (connection, _server_reader, _server_writer) =
            connection_with_staged_bi_stream(stream_id, Err(stream_id_error)).await;
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.test:443")
            .body(Full::new(Bytes::new()))
            .expect("request should be valid");

        let error = match connection.execute_hyper_request(request).await {
            Ok(_) => panic!("stream id failure should be reported"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            RequestError::StreamId {
                source: quic::StreamError::Reset { code }
            } if code == VarInt::from_u32(0x10)
        ));
    }

    #[test]
    fn request_error_from_send_message_error_preserves_variant() {
        let source = SendMessageError::<Infallible>::MalformedHeader {
            source: MalformedHeaderSection::ProtocolInNonConnectRequest,
        };

        let error: RequestError<Infallible> = source.into();

        assert!(matches!(error, RequestError::SendRequest { .. }));
    }

    #[test]
    fn request_error_from_initial_stream_error_preserves_variant() {
        let source = InitialMessageStreamError::InitialRawStream {
            source: crate::dhttp::protocol::InitialRawMessageStreamError::Connection {
                source: test_connection_error("initial stream failed"),
            },
        };

        let error: RequestError<Infallible> = source.into();

        assert!(matches!(error, RequestError::InitialStream { .. }));
    }

    #[test]
    fn request_error_from_message_stream_error_preserves_variant() {
        let source = MessageStreamError::Quic {
            source: quic::StreamError::Reset {
                code: VarInt::from_u32(0x20),
            },
        };

        let error: RequestError<Infallible> = source.into();

        assert!(matches!(error, RequestError::ReceiveResponse { .. }));
    }
}
