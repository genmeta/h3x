use std::{
    error::Error,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::{self, BoxFuture};
use http::Method;
use http_body::Body;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use snafu::{Report, ResultExt, Snafu};
use tracing::Instrument;

use crate::{
    message::stream::{
        MessageStreamError, ReadStream,
        hyper::{
            upgrade::{RemainStream, TakeoverSlot},
            write::SendMessageError,
        },
    },
    server::{Request, Response, UnresolvedRequest},
};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TowerService<S>(pub S);

impl<S, RespBody> crate::server::Service for TowerService<S>
where
    S: tower_service::Service<
            http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
            Response = http::Response<RespBody>,
            Error: Error + Send,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send + 'static> + Send,
{
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, req: &'s mut Request, resp: &'s mut Response) -> Self::Future<'s> {
        let mut service = self.0.clone();
        Box::pin(async move {
            if let Err(error) = future::poll_fn(|cx| service.poll_ready(cx)).await {
                tracing::debug!(error = %Report::from_error(error), "service cannot be ready");
                return;
            }

            let mut read_stream = Some(req.read_stream().take());
            let mut write_stream = resp.write_stream().take();
            resp.mark_taken_over();

            let is_connect = req.method() == Method::CONNECT;

            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();
            let request = if is_connect {
                let remain_read_stream = RemainStream::immediately(
                    read_stream
                        .take()
                        .expect("connect request must have read stream"),
                );
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .extension(TakeoverSlot::new(remain_read_stream))
                    .extension(TakeoverSlot::new(remain_write_stream.clone()))
                    .body(UnsyncBoxBody::new(Empty::new().map_err(|n| match n {})))
            } else {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .body(UnsyncBoxBody::new(
                        read_stream
                            .take()
                            .expect("non-connect request must have read stream")
                            .into_hyper_body(),
                    ))
            };

            let mut request = match request {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(error), "failed to convert request, skip serving");
                    return;
                }
            };

            *request.headers_mut() = req.headers().clone();
            request.extensions_mut().insert(resp.agent().clone());
            request.extensions_mut().insert(req.stream_id());
            request.extensions_mut().insert(req.protocols().clone());
            if let Some(remote_agent) = req.agent().cloned() {
                request.extensions_mut().insert(remote_agent);
            }

            match service.call(request).await {
                Ok(response) => {
                    if let Err(error) = write_stream.send_hyper_response(response).await {
                        tracing::debug!(error = %Report::from_error(error), "failed to send response");
                    }
                    if is_connect {
                        // Flush the buffered response so the client receives
                        // it before the stream is handed to the upgrade layer.
                        _ = write_stream.flush().await;
                        _ = remain_write_stream_tx.send(write_stream);
                    } else {
                        _ = write_stream.close().await;
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %Report::from_error(error), "service failed")
                }
            }
        })
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum HandleRequestError<S: Error + 'static, B: Error + 'static> {
    #[snafu(display("failed to handle message stream"))]
    Stream { source: MessageStreamError },
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
            SendMessageError::Body { source } => HandleRequestError::Body { source },
        }
    }
}

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
        let future =
            async move {
                future::poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .context(handle_request_error::ServiceSnafu)?;

                // Agents + protocols live on the owning connection; fetch them
                // once per request. The local agent is guaranteed to exist on an
                // accepted server connection (SNI check runs during accept).
                let local_agent = connection
                    .local_agent()
                    .await
                    .map_err(|source| HandleRequestError::Stream {
                        source: MessageStreamError::from(source),
                    })?
                    .expect("accepted server connection must have a local agent");
                let remote_agent = connection.remote_agent().await.map_err(|source| {
                    HandleRequestError::Stream {
                        source: MessageStreamError::from(source),
                    }
                })?;
                let protocols = connection.protocols().clone();

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

                request.extensions_mut().insert(local_agent);
                if let Some(remote_agent) = remote_agent {
                    request.extensions_mut().insert(remote_agent);
                }
                request.extensions_mut().insert(stream_id);
                request.extensions_mut().insert(protocols);
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

impl<S, RespBody> crate::server::Service for HyperService<S>
where
    S: hyper::service::Service<
            http::Request<UnsyncBoxBody<Bytes, MessageStreamError>>,
            Response = http::Response<RespBody>,
            Error: Error + Send,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send + 'static> + Send,
{
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, req: &'s mut Request, resp: &'s mut Response) -> Self::Future<'s> {
        let service = self.0.clone();
        Box::pin(async move {
            let mut read_stream = Some(req.read_stream().take());
            let mut write_stream = resp.write_stream().take();
            resp.mark_taken_over();

            let is_connect = req.method() == Method::CONNECT;

            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();
            let request = if is_connect {
                let remain_read_stream = RemainStream::immediately(
                    read_stream
                        .take()
                        .expect("connect request must have read stream"),
                );
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .extension(TakeoverSlot::new(remain_read_stream))
                    .extension(TakeoverSlot::new(remain_write_stream.clone()))
                    .body(UnsyncBoxBody::new(Empty::new().map_err(|n| match n {})))
            } else {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .body(UnsyncBoxBody::new(
                        read_stream
                            .take()
                            .expect("non-connect request must have read stream")
                            .into_hyper_body(),
                    ))
            };

            let mut request = match request {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(error), "failed to convert request, skip serving");
                    return;
                }
            };

            *request.headers_mut() = req.headers().clone();
            request.extensions_mut().insert(resp.agent().clone());
            request.extensions_mut().insert(req.stream_id());
            request.extensions_mut().insert(req.protocols().clone());
            if let Some(remote_agent) = req.agent().cloned() {
                request.extensions_mut().insert(remote_agent);
            }

            match service.call(request).await {
                Ok(response) => {
                    if let Err(error) = write_stream.send_hyper_response(response).await {
                        tracing::debug!(error = %Report::from_error(error), "failed to send response");
                    }
                    if is_connect {
                        _ = write_stream.flush().await;
                        _ = remain_write_stream_tx.send(write_stream);
                    } else {
                        _ = write_stream.close().await;
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %Report::from_error(error), "service failed")
                }
            }
        })
    }
}

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
        let future =
            async move {
                let local_agent = connection
                    .local_agent()
                    .await
                    .map_err(|source| HandleRequestError::Stream {
                        source: MessageStreamError::from(source),
                    })?
                    .expect("accepted server connection must have a local agent");
                let remote_agent = connection.remote_agent().await.map_err(|source| {
                    HandleRequestError::Stream {
                        source: MessageStreamError::from(source),
                    }
                })?;
                let protocols = connection.protocols().clone();

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

                request.extensions_mut().insert(local_agent);
                if let Some(remote_agent) = remote_agent {
                    request.extensions_mut().insert(remote_agent);
                }
                request.extensions_mut().insert(stream_id);
                request.extensions_mut().insert(protocols);
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
