use std::{
    error::Error,
    fmt::Display,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::{self, BoxFuture};
use http::Method;
use http_body::Body;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use snafu::Report;
use tracing::Instrument;

use crate::{
    message::stream::{
        StreamError,
        hyper::{upgrade::RemainStream, write::SendMesageError},
    },
    server::{Request, Response, UnresolvedRequest},
};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TowerService<S>(pub S);

impl<S, RespBody> crate::server::Service for TowerService<S>
where
    S: tower_service::Service<
            http::Request<UnsyncBoxBody<Bytes, StreamError>>,
            Response = http::Response<RespBody>,
            Error: Error + Send,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send> + Send,
{
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, req: &'s mut Request, resp: &'s mut Response) -> Self::Future<'s> {
        let mut service = self.0.clone();
        Box::pin(async move {
            if let Err(error) = future::poll_fn(|cx| service.poll_ready(cx)).await {
                tracing::debug!(error = %Report::from_error(error), "Service cannot be ready");
                return;
            }

            let read_stream = req.read_stream().take();
            let mut write_stream = resp.write_stream().take();

            let is_connect = req.method() == Method::CONNECT;

            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();
            let request = if is_connect {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .extension(RemainStream::immediately(read_stream))
                    .extension(remain_write_stream)
                    .body(UnsyncBoxBody::new(Empty::new().map_err(|n| match n {})))
            } else {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .body(UnsyncBoxBody::new(read_stream.into_hyper_body()))
            };

            let mut request = match request {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(error), "Failed to convert request, skip serving");
                    return;
                }
            };

            *request.headers_mut() = request.headers().clone();
            request.extensions_mut().insert(resp.agent().clone());
            if let Some(remote_agent) = req.agent().cloned() {
                request.extensions_mut().insert(remote_agent);
            }

            match service.call(request).await {
                Ok(response) => {
                    if let Err(error) = write_stream.send_hyper_response(response).await {
                        tracing::debug!(error = %Report::from_error(error), "Failed to send response");
                    }
                    if is_connect {
                        _ = remain_write_stream_tx.send(write_stream);
                    } else {
                        _ = write_stream.close().await;
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %Report::from_error(error), "Service failed")
                }
            }
        })
    }
}

#[derive(Debug)]
pub enum HandleRequestError<S, B> {
    Stream { source: StreamError },
    Service { source: S },
    Body { source: B },
}

impl<S: Display, B: Display> Display for HandleRequestError<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandleRequestError::Stream { source } => source.fmt(f),
            HandleRequestError::Service { source } => source.fmt(f),
            HandleRequestError::Body { source } => source.fmt(f),
        }
    }
}

impl<S: Error, B: Error> Error for HandleRequestError<S, B> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            HandleRequestError::Stream { source } => source.source(),
            HandleRequestError::Service { source } => source.source(),
            HandleRequestError::Body { source } => source.source(),
        }
    }
}

impl<S, B> From<SendMesageError<B>> for HandleRequestError<S, B> {
    fn from(source: SendMesageError<B>) -> Self {
        match source {
            SendMesageError::Stream { source } => HandleRequestError::Stream { source },
            SendMesageError::Body { source } => HandleRequestError::Body { source },
        }
    }
}

impl<S, RespBody, ServiceE> tower_service::Service<UnresolvedRequest> for TowerService<S>
where
    S: tower_service::Service<
            http::Request<UnsyncBoxBody<Bytes, StreamError>>,
            Response = http::Response<RespBody>,
            Error = ServiceE,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send> + Send,
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
            request_stream,
            remote_agent,
            mut response_stream,
            local_agent,
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
                .map_err(|source| HandleRequestError::Service { source })?;

            let mut request = request_stream
                .into_hyper_request()
                .await
                .map_err(|source| HandleRequestError::Stream { source })?
                .map(UnsyncBoxBody::new);
            tracing::Span::current()
                .record("method", request.method().as_str())
                .record("uri", request.uri().to_string());

            tracing::debug!("Converted request stream to hyper request, serving...");
            let is_connect = request.method() == Method::CONNECT;
            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();

            request.extensions_mut().insert(local_agent);
            if let Some(remote_agent) = remote_agent {
                request.extensions_mut().insert(remote_agent);
            }
            if is_connect {
                request.extensions_mut().insert(remain_write_stream);
            }

            let response = service
                .call(request)
                .await
                .map_err(|source| HandleRequestError::Service { source })?;

            response_stream.send_hyper_response(response).await?;
            if is_connect {
                _ = remain_write_stream_tx.send(response_stream);
            } else {
                response_stream
                    .close()
                    .await
                    .map_err(|source| HandleRequestError::Stream { source })?;
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
            http::Request<UnsyncBoxBody<Bytes, StreamError>>,
            Response = http::Response<RespBody>,
            Error: Error + Send,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send> + Send,
{
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, req: &'s mut Request, resp: &'s mut Response) -> Self::Future<'s> {
        let service = self.0.clone();
        Box::pin(async move {
            let read_stream = req.read_stream().take();
            let mut write_stream = resp.write_stream().take();

            let is_connect = req.method() == Method::CONNECT;

            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();
            let request = if is_connect {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .extension(RemainStream::immediately(read_stream))
                    .extension(remain_write_stream)
                    .body(UnsyncBoxBody::new(Empty::new().map_err(|n| match n {})))
            } else {
                http::Request::builder()
                    .method(req.method())
                    .uri(req.uri())
                    .body(UnsyncBoxBody::new(read_stream.into_hyper_body()))
            };

            let mut request = match request {
                Ok(request) => request,
                Err(error) => {
                    tracing::warn!(error = %Report::from_error(error), "Failed to convert request, skip serving");
                    return;
                }
            };

            *request.headers_mut() = request.headers().clone();
            request.extensions_mut().insert(resp.agent().clone());
            if let Some(remote_agent) = req.agent().cloned() {
                request.extensions_mut().insert(remote_agent);
            }

            match service.call(request).await {
                Ok(response) => {
                    if let Err(error) = write_stream.send_hyper_response(response).await {
                        tracing::debug!(error = %Report::from_error(error), "Failed to send response");
                    }
                    if is_connect {
                        _ = remain_write_stream_tx.send(write_stream);
                    } else {
                        _ = write_stream.close().await;
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %Report::from_error(error), "Service failed")
                }
            }
        })
    }
}

impl<S, RespBody, ServiceE> tower_service::Service<UnresolvedRequest> for HyperService<S>
where
    S: hyper::service::Service<
            http::Request<UnsyncBoxBody<Bytes, StreamError>>,
            Response = http::Response<RespBody>,
            Error = ServiceE,
            Future: Send,
        > + Clone
        + Send
        + 'static,
    RespBody: Body<Data: Send, Error: Error + Send> + Send,
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
            request_stream,
            remote_agent,
            mut response_stream,
            local_agent,
        }: UnresolvedRequest,
    ) -> Self::Future {
        let span = tracing::info_span!(
            "handle_request",
            method = tracing::field::Empty,
            uri = tracing::field::Empty
        );

        let service = self.0.clone();
        let future = async move {
            let mut request = request_stream
                .into_hyper_request()
                .await
                .map_err(|source| HandleRequestError::Stream { source })?
                .map(UnsyncBoxBody::new);
            tracing::Span::current()
                .record("method", request.method().as_str())
                .record("uri", request.uri().to_string());

            tracing::debug!("Converted request stream to hyper request, serving...");
            let is_connect = request.method() == Method::CONNECT;
            let (remain_write_stream_tx, remain_write_stream) = RemainStream::pending();

            request.extensions_mut().insert(local_agent);
            if let Some(remote_agent) = remote_agent {
                request.extensions_mut().insert(remote_agent);
            }
            if is_connect {
                request.extensions_mut().insert(remain_write_stream);
            }

            let response = service
                .call(request)
                .await
                .map_err(|source| HandleRequestError::Service { source })?;

            response_stream.send_hyper_response(response).await?;
            if is_connect {
                _ = remain_write_stream_tx.send(response_stream);
            } else {
                response_stream
                    .close()
                    .await
                    .map_err(|source| HandleRequestError::Stream { source })?;
            }

            Ok(())
        };
        Box::pin(future.instrument(span))
    }
}
