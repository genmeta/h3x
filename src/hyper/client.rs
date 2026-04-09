use std::error::Error;

use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Empty};
use tracing::Instrument;

use crate::{
    connection::Connection,
    hyper::SendMessageError,
    message::stream::{
        InitialMessageStreamError, MessageStreamError,
        hyper::{
            read::Either,
            upgrade::{RemainStream, TakeoverSlot},
        },
    },
    quic,
};

#[derive(Debug)]
pub enum RequestError<E> {
    InitialStream { source: InitialMessageStreamError },
    SendRequest { source: SendMessageError<E> },
    ReceiveResponse { source: MessageStreamError },
}

impl<E> From<InitialMessageStreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: InitialMessageStreamError) -> Self {
        RequestError::InitialStream { source }
    }
}

impl<E> From<SendMessageError<E>> for RequestError<E> {
    #[track_caller]
    fn from(source: SendMessageError<E>) -> Self {
        RequestError::SendRequest { source }
    }
}

impl<E> From<MessageStreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: MessageStreamError) -> Self {
        RequestError::ReceiveResponse { source }
    }
}

impl<E: Error + 'static> std::fmt::Display for RequestError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        #[allow(unused_variables)]
        match self {
            RequestError::InitialStream { source, .. } => source.fmt(f),
            RequestError::SendRequest { source, .. } => source.fmt(f),
            RequestError::ReceiveResponse { source, .. } => source.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for RequestError<E> {
    fn source(&self) -> ::core::option::Option<&(dyn ::snafu::Error + 'static)> {
        match *self {
            RequestError::InitialStream { ref source, .. } => source.source(),
            RequestError::SendRequest { ref source, .. } => source.source(),
            RequestError::ReceiveResponse { ref source, .. } => source.source(),
        }
    }
}

impl<C: quic::Connection> Connection<C> {
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
        B::Error: Send,
    {
        let (mut read_stream, mut write_stream) = self.initial_message_stream().await?;
        let is_connect = request.method() == http::Method::CONNECT;

        if is_connect {
            // CONNECT: no body or trailers — join send + receive headers.
            let (parts, _body) = request.into_parts();
            let (send_result, recv_result) =
                tokio::join!(write_stream.send_hyper_request_parts(parts), async {
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
                },);
            send_result.map_err(|source| SendMessageError::Stream { source })?;
            let mut response_parts = recv_result?;

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
            let (parts, body) = request.into_parts();
            write_stream
                .send_hyper_request_parts(parts)
                .await
                .map_err(|source| SendMessageError::Stream { source })?;

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
