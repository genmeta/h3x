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
