use std::{
    error::Error,
    fmt::Display,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::{self, BoxFuture};
use http_body::Body;
use http_body_util::combinators::UnsyncBoxBody;
use snafu::Report;

use crate::{
    message::stream::{StreamError, http_body::SendMesageError},
    server::{Request, Response, UnresolvedRequest},
};

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TowerService<S>(pub S);

impl<S, RespBody> super::Service for TowerService<S>
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
            let (body, remain) = read_stream.take_hyper_body();

            let request = http::Request::builder()
                .method(req.method())
                .uri(req.uri())
                .body(UnsyncBoxBody::new(body));

            let mut request = match request {
                Ok(request) => request,
                Err(error) => {
                    tracing::error!(error = %Report::from_error(&error), "Failed to build hyper request, this should not happen");
                    return;
                }
            };

            *request.headers_mut() = request.headers().clone();
            request.extensions_mut().insert(remain);
            request.extensions_mut().insert(resp.agent().clone());
            if let Some(remote_agent) = req.agent().cloned() {
                request.extensions_mut().insert(remote_agent);
            }

            match service.call(request).await {
                Ok(response) => {
                    if let Err(error) = resp.write_stream().send_hyper_response(response).await {
                        tracing::debug!(error = %Report::from_error(error), "Failed to send response");
                    }
                }
                Err(error) => {
                    tracing::debug!(error = %Report::from_error(error), "Service failed");
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
            mut request_stream,
            remote_agent,
            mut response_stream,
            local_agent,
        }: UnresolvedRequest,
    ) -> Self::Future {
        let mut service = self.0.clone();
        Box::pin(async move {
            future::poll_fn(|cx| service.poll_ready(cx))
                .await
                .map_err(|source| HandleRequestError::Service { source })?;

            let request_parts = request_stream
                .read_hyper_request_parts()
                .await
                .map_err(|source| HandleRequestError::Stream { source })?;

            let (request_body, remain_stream) = request_stream.take_hyper_body();

            let mut request =
                http::Request::from_parts(request_parts, UnsyncBoxBody::new(request_body));
            request.extensions_mut().insert(remain_stream);
            request.extensions_mut().insert(local_agent);
            if let Some(remote_agent) = remote_agent {
                request.extensions_mut().insert(remote_agent);
            }

            let response = service
                .call(request)
                .await
                .map_err(|source| HandleRequestError::Service { source })?;

            response_stream.send_hyper_response(response).await?;

            Ok(())
        })
    }
}
