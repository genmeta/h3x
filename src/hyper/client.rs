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
    qpack::field::Protocol,
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
        let (mut read_stream, mut write_stream) = self.initial_message_stream().await?;
        let is_connect = request.method() == http::Method::CONNECT;

        if is_connect {
            // CONNECT: no body or trailers — join send + receive headers.
            let protocol = protocol_from_extensions(request.extensions());
            let stream_id = write_stream
                .stream_id()
                .await
                .context(request_error::StreamIdSnafu)?;
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
            send_result.context(send_message_error::StreamSnafu)?;
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
            let (parts, body) = request.into_parts();
            write_stream
                .send_hyper_request_parts(parts)
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
    use http::Extensions;

    use super::*;

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
}
