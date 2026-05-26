use std::{
    error::Error,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::{self, BoxFuture};
use http::Method;
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use snafu::{ResultExt, Snafu};
use tracing::Instrument;

use crate::{
    endpoint::server::UnresolvedRequest,
    message::stream::{
        MessageStreamError, ReadStream,
        hyper::{
            upgrade::{RemainStream, TakeoverSlot},
            write::SendMessageError,
        },
    },
    qpack::field::MalformedHeaderSection,
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum HandleRequestError<S: Error + 'static, B: Error + 'static> {
    #[snafu(display("failed to handle message stream"))]
    Stream { source: MessageStreamError },
    #[snafu(display("response pseudo-header section is malformed"))]
    MalformedHeader { source: MalformedHeaderSection },
    #[snafu(display("service error"))]
    Service { source: S },
    #[snafu(display("response body error"))]
    Body { source: B },
}

impl<S: Error + 'static, B: Error + 'static> From<SendMessageError<B>>
    for HandleRequestError<S, B>
{
    fn from(source: SendMessageError<B>) -> Self {
        match source {
            SendMessageError::Stream { source } => HandleRequestError::Stream { source },
            SendMessageError::MalformedHeader { source } => {
                HandleRequestError::MalformedHeader { source }
            }
            SendMessageError::Body { source } => HandleRequestError::Body { source },
        }
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TowerService<S>(pub S);

impl<S, RespBody, ServiceE> tower_service::Service<UnresolvedRequest> for TowerService<S>
where
    S: tower_service::Service<
            http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
            Response = http::Response<RespBody>,
            Error = ServiceE,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    ServiceE: Error + 'static,
    RespBody: Body<Data: Send, Error: Error + Send + 'static> + Send,
{
    type Response = ();
    type Error = HandleRequestError<ServiceE, RespBody::Error>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0
            .poll_ready(cx)
            .map_err(|source| HandleRequestError::Service { source })
    }

    fn call(
        &mut self,
        UnresolvedRequest {
            stream_id,
            read_stream,
            write_stream: mut response_stream,
            connection,
        }: UnresolvedRequest,
    ) -> Self::Future {
        let span = tracing::info_span!(
            "handle_request",
            method = tracing::field::Empty,
            uri = tracing::field::Empty
        );

        let mut service = self.0.clone();
        let future = async move {
            future::poll_fn(|cx| service.poll_ready(cx))
                .await
                .context(handle_request_error::ServiceSnafu)?;

            let mut request = read_stream
                .into_hyper_request()
                .await
                .context(handle_request_error::StreamSnafu)?
                .map(UnsyncBoxBody::new);
            tracing::Span::current()
                .record("method", request.method().as_str())
                .record("uri", request.uri().to_string());

            tracing::trace!("converted request stream to hyper request, serving...");
            let is_connect = request.method() == Method::CONNECT;
            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();

            request.extensions_mut().insert(stream_id);
            request.extensions_mut().insert(connection);
            if is_connect
                && request
                    .extensions()
                    .get::<TakeoverSlot<ReadStream>>()
                    .is_some()
            {
                request
                    .extensions_mut()
                    .insert(TakeoverSlot::new(remain_write_stream.clone()));
            }

            let response = service
                .call(request)
                .await
                .context(handle_request_error::ServiceSnafu)?;

            response_stream.send_hyper_response(response).await?;
            if is_connect {
                response_stream
                    .flush()
                    .await
                    .context(handle_request_error::StreamSnafu)?;
                _ = remain_write_stream_tx.send(response_stream);
            } else {
                response_stream
                    .close()
                    .await
                    .context(handle_request_error::StreamSnafu)?;
            }

            Ok(())
        };
        Box::pin(future.instrument(span))
    }
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct HyperService<S>(pub S);

impl<S, RespBody, ServiceE> tower_service::Service<UnresolvedRequest> for HyperService<S>
where
    S: hyper::service::Service<
            http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
            Response = http::Response<RespBody>,
            Error = ServiceE,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    ServiceE: Error + 'static,
    RespBody: Body<Data: Send, Error: Error + Send + 'static> + Send,
{
    type Response = ();
    type Error = HandleRequestError<ServiceE, RespBody::Error>;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &mut self,
        UnresolvedRequest {
            stream_id,
            read_stream,
            write_stream: mut response_stream,
            connection,
        }: UnresolvedRequest,
    ) -> Self::Future {
        let span = tracing::info_span!(
            "handle_request",
            method = tracing::field::Empty,
            uri = tracing::field::Empty
        );

        let service = self.0.clone();
        let future = async move {
            let mut request = read_stream
                .into_hyper_request()
                .await
                .context(handle_request_error::StreamSnafu)?
                .map(UnsyncBoxBody::new);
            tracing::Span::current()
                .record("method", request.method().as_str())
                .record("uri", request.uri().to_string());

            tracing::trace!("converted request stream to hyper request, serving...");
            let is_connect = request.method() == Method::CONNECT;
            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();

            request.extensions_mut().insert(stream_id);
            request.extensions_mut().insert(connection);
            if is_connect
                && request
                    .extensions()
                    .get::<TakeoverSlot<ReadStream>>()
                    .is_some()
            {
                request
                    .extensions_mut()
                    .insert(TakeoverSlot::new(remain_write_stream.clone()));
            }

            let response = service
                .call(request)
                .await
                .context(handle_request_error::ServiceSnafu)?;

            response_stream.send_hyper_response(response).await?;
            if is_connect {
                response_stream
                    .flush()
                    .await
                    .context(handle_request_error::StreamSnafu)?;
                _ = remain_write_stream_tx.send(response_stream);
            } else {
                response_stream
                    .close()
                    .await
                    .context(handle_request_error::StreamSnafu)?;
            }

            Ok(())
        };
        Box::pin(future.instrument(span))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::Poll,
    };

    use futures::{Sink, SinkExt, Stream, future::poll_fn};
    use http::StatusCode;
    use http_body_util::{BodyExt, Full};
    use tower_service::Service as _;

    use super::*;
    use crate::{
        codec::{SinkWriter, StreamReader},
        connection::{ConnectionState, StreamError, tests::MockConnection},
        dhttp::{protocol::DHttpProtocol, settings::Settings},
        message::stream::{WriteStream, guard},
        protocol::Protocols,
        qpack::{
            decoder::DecoderInstruction,
            encoder::EncoderInstruction,
            protocol::{QPackDecoder, QPackEncoder},
        },
        quic,
        stream_id::StreamId,
        varint::VarInt,
    };

    #[derive(Debug, snafu::Snafu)]
    #[snafu(display("test service failed"))]
    struct TestServiceError;

    #[derive(Debug, Default)]
    struct ServiceState {
        ready: AtomicUsize,
        calls: AtomicUsize,
        method: Mutex<Option<Method>>,
        uri: Mutex<Option<http::Uri>>,
        stream_id_seen: Mutex<Option<StreamId>>,
        connection_seen: AtomicUsize,
        body: Mutex<Option<Bytes>>,
    }

    impl ServiceState {
        fn record_request(
            &self,
            request: &http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
        ) {
            *self
                .method
                .lock()
                .expect("method mutex should not be poisoned") = Some(request.method().clone());
            *self.uri.lock().expect("uri mutex should not be poisoned") =
                Some(request.uri().clone());
            *self
                .stream_id_seen
                .lock()
                .expect("stream id mutex should not be poisoned") =
                request.extensions().get::<StreamId>().copied();
            if request
                .extensions()
                .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()
                .is_some()
            {
                self.connection_seen.fetch_add(1, Ordering::Relaxed);
            }
        }

        fn method(&self) -> Option<Method> {
            self.method
                .lock()
                .expect("method mutex should not be poisoned")
                .clone()
        }

        fn uri(&self) -> Option<http::Uri> {
            self.uri
                .lock()
                .expect("uri mutex should not be poisoned")
                .clone()
        }

        fn stream_id(&self) -> Option<StreamId> {
            *self
                .stream_id_seen
                .lock()
                .expect("stream id mutex should not be poisoned")
        }

        fn body(&self) -> Option<Bytes> {
            self.body
                .lock()
                .expect("body mutex should not be poisoned")
                .clone()
        }
    }

    #[derive(Clone, Debug)]
    struct TestTowerService {
        state: Arc<ServiceState>,
    }

    impl tower_service::Service<http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>>
        for TestTowerService
    {
        type Response = http::Response<Full<Bytes>>;
        type Error = TestServiceError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &mut self,
            _cx: &mut std::task::Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.state.ready.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }

        fn call(
            &mut self,
            request: http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
        ) -> Self::Future {
            self.state.calls.fetch_add(1, Ordering::Relaxed);
            self.state.record_request(&request);
            let state = self.state.clone();
            Box::pin(async move {
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .expect("request body should be readable")
                    .to_bytes();
                *state
                    .body
                    .lock()
                    .expect("body mutex should not be poisoned") = Some(body.clone());
                let mut response_body = b"tower:".to_vec();
                response_body.extend_from_slice(&body);
                Ok(http::Response::builder()
                    .status(StatusCode::CREATED)
                    .header("x-service", "tower")
                    .body(Full::new(Bytes::from(response_body)))
                    .expect("response should be valid"))
            })
        }
    }

    #[derive(Clone, Debug)]
    struct TestHyperService {
        state: Arc<ServiceState>,
    }

    impl hyper::service::Service<http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>>
        for TestHyperService
    {
        type Response = http::Response<Full<Bytes>>;
        type Error = TestServiceError;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn call(
            &self,
            request: http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
        ) -> Self::Future {
            self.state.calls.fetch_add(1, Ordering::Relaxed);
            self.state.record_request(&request);
            let state = self.state.clone();
            Box::pin(async move {
                let body = request
                    .into_body()
                    .collect()
                    .await
                    .expect("request body should be readable")
                    .to_bytes();
                *state
                    .body
                    .lock()
                    .expect("body mutex should not be poisoned") = Some(body.clone());
                let mut response_body = b"hyper:".to_vec();
                response_body.extend_from_slice(&body);
                Ok(http::Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .header("x-service", "hyper")
                    .body(Full::new(Bytes::from(response_body)))
                    .expect("response should be valid"))
            })
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

    fn connection_state() -> ConnectionState<dyn quic::DynConnection> {
        let erased: Arc<dyn quic::DynConnection> = Arc::new(MockConnection::new());
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        ConnectionState::new_for_test(erased, Arc::new(protocols))
    }

    fn stream_pair(stream_id: VarInt) -> (ReadStream, WriteStream) {
        let state = connection_state();
        let (reader, writer) = quic::test::mock_stream_pair_with_capacity(stream_id, 64);
        let reader = StreamReader::new(guard::GuardedQuicReader::new(
            Box::pin(reader) as crate::codec::BoxReadStream
        ));
        let writer = SinkWriter::new(guard::GuardedQuicWriter::new(
            Box::pin(writer) as crate::codec::BoxWriteStream
        ));

        (
            ReadStream::new(
                reader,
                Arc::new(QPackDecoder::new(
                    Arc::new(Settings::default()),
                    qpack_decoder_sink(),
                    qpack_decoder_stream(),
                )),
                state.clone(),
            ),
            WriteStream::new(
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

    async fn request_pair(request: http::Request<Full<Bytes>>) -> (UnresolvedRequest, ReadStream) {
        let stream_id = VarInt::from_u32(0);
        let (server_read, mut request_writer) = stream_pair(stream_id);
        request_writer
            .send_hyper_request(request)
            .await
            .expect("request should be written");
        request_writer
            .close()
            .await
            .expect("request stream should close");

        let (response_reader, server_write) = stream_pair(stream_id);
        (
            UnresolvedRequest {
                stream_id: StreamId(stream_id),
                read_stream: server_read,
                write_stream: server_write,
                connection: Arc::new(connection_state()),
            },
            response_reader,
        )
    }

    async fn read_response(response_reader: ReadStream) -> (http::response::Parts, Bytes) {
        let response = response_reader
            .into_hyper_response()
            .await
            .expect("response should be readable");
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .expect("response body should be readable")
            .to_bytes();
        (parts, body)
    }

    #[tokio::test]
    async fn tower_service_converts_request_and_writes_response() {
        let state = Arc::new(ServiceState::default());
        let mut service = TowerService(TestTowerService {
            state: state.clone(),
        });
        poll_fn(|cx| service.poll_ready(cx))
            .await
            .expect("tower service should be ready");
        let request = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.test/upload")
            .body(Full::new(Bytes::from_static(b"payload")))
            .expect("request should be valid");
        let (unresolved, response_reader) = request_pair(request).await;

        service
            .call(unresolved)
            .await
            .expect("request should be handled");

        let (parts, body) = read_response(response_reader).await;
        assert_eq!(parts.status, StatusCode::CREATED);
        assert_eq!(parts.headers.get("x-service").unwrap(), "tower");
        assert_eq!(body, Bytes::from_static(b"tower:payload"));
        assert_eq!(state.ready.load(Ordering::Relaxed), 2);
        assert_eq!(state.calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.method(), Some(Method::POST));
        assert_eq!(
            state.uri(),
            Some("https://example.test/upload".parse().unwrap())
        );
        assert_eq!(state.stream_id(), Some(StreamId(VarInt::from_u32(0))));
        assert_eq!(state.connection_seen.load(Ordering::Relaxed), 1);
        assert_eq!(state.body(), Some(Bytes::from_static(b"payload")));
    }

    #[tokio::test]
    async fn hyper_service_converts_request_and_writes_response() {
        let state = Arc::new(ServiceState::default());
        let mut service = HyperService(TestHyperService {
            state: state.clone(),
        });
        poll_fn(|cx| service.poll_ready(cx))
            .await
            .expect("hyper wrapper should be ready");
        let request = http::Request::builder()
            .method(Method::PUT)
            .uri("https://example.test/resource")
            .body(Full::new(Bytes::from_static(b"body")))
            .expect("request should be valid");
        let (unresolved, response_reader) = request_pair(request).await;

        service
            .call(unresolved)
            .await
            .expect("request should be handled");

        let (parts, body) = read_response(response_reader).await;
        assert_eq!(parts.status, StatusCode::ACCEPTED);
        assert_eq!(parts.headers.get("x-service").unwrap(), "hyper");
        assert_eq!(body, Bytes::from_static(b"hyper:body"));
        assert_eq!(state.calls.load(Ordering::Relaxed), 1);
        assert_eq!(state.method(), Some(Method::PUT));
        assert_eq!(
            state.uri(),
            Some("https://example.test/resource".parse().unwrap())
        );
        assert_eq!(state.stream_id(), Some(StreamId(VarInt::from_u32(0))));
        assert_eq!(state.connection_seen.load(Ordering::Relaxed), 1);
        assert_eq!(state.body(), Some(Bytes::from_static(b"body")));
    }

    #[test]
    fn handle_request_error_from_body_error_preserves_variant() {
        #[derive(Debug, snafu::Snafu)]
        #[snafu(display("body failed"))]
        struct TestBodyError;

        let error: HandleRequestError<TestServiceError, TestBodyError> = SendMessageError::Body {
            source: TestBodyError,
        }
        .into();

        assert!(matches!(error, HandleRequestError::Body { .. }));
    }

    #[test]
    fn service_wrappers_are_transparent_newtypes() {
        let tower = TowerService(7_u8);
        let hyper = HyperService(9_u8);

        assert_eq!(tower, TowerService(7));
        assert_eq!(hyper, HyperService(9));
        assert_eq!(format!("{tower:?}"), "TowerService(7)");
        assert_eq!(format!("{hyper:?}"), "HyperService(9)");
    }
}
