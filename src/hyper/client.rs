use std::error::Error;

use http_body::Body;
use http_body_util::{BodyExt, Empty};

use crate::{
    connection::{Connection, OpenRequestStreamError},
    hyper::SendMesageError,
    message::stream::{
        StreamError,
        hyper::{read::Either, upgrade::RemainStream},
    },
    quic,
};

#[derive(Debug)]
pub enum RequestError<E> {
    OpenStream { source: OpenRequestStreamError },
    SendRequest { source: SendMesageError<E> },
    ReceiveResponse { source: StreamError },
}

impl<E> From<OpenRequestStreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: OpenRequestStreamError) -> Self {
        RequestError::OpenStream { source }
    }
}

impl<E> From<SendMesageError<E>> for RequestError<E> {
    #[track_caller]
    fn from(source: SendMesageError<E>) -> Self {
        RequestError::SendRequest { source }
    }
}

impl<E> From<StreamError> for RequestError<E> {
    #[track_caller]
    fn from(source: StreamError) -> Self {
        RequestError::ReceiveResponse { source }
    }
}

impl<E: Error + 'static> std::fmt::Display for RequestError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        #[allow(unused_variables)]
        match self {
            RequestError::OpenStream { source, .. } => source.fmt(f),
            RequestError::SendRequest { source, .. } => source.fmt(f),
            RequestError::ReceiveResponse { source, .. } => source.fmt(f),
        }
    }
}

impl<E: Error + 'static> Error for RequestError<E> {
    fn source(&self) -> ::core::option::Option<&(dyn ::snafu::Error + 'static)> {
        match *self {
            RequestError::OpenStream { ref source, .. } => source.source(),
            RequestError::SendRequest { ref source, .. } => source.source(),
            RequestError::ReceiveResponse { ref source, .. } => source.source(),
        }
    }
}

impl<C: quic::Connection> Connection<C> {
    #[tracing::instrument(level = "debug", skip_all, fields(method = %request.method(), uri = %request.uri()))]
    pub async fn execute_hyper_request<B: Body>(
        &self,
        request: http::Request<B>,
    ) -> Result<
        http::Response<impl Body<Data = bytes::Bytes, Error = StreamError> + use<B, C>>,
        RequestError<B::Error>,
    > {
        let (mut read_stream, mut write_stream) = self.open_request_stream().await?;
        let is_connect = request.method() == http::Method::CONNECT;
        write_stream.send_hyper_request(request).await?;

        let mut response_parts = read_stream.read_hyper_response_parts().await?;
        // skip informational responses
        while response_parts.status.is_informational() {
            tracing::debug!(
                status = %response_parts.status,
                hedaers = ?response_parts.headers,
                "Skipping informational response",
            );
            response_parts = read_stream.read_hyper_response_parts().await?
        }

        let body = if !is_connect {
            Either::left(read_stream.into_hyper_body())
        } else {
            let read_stream = RemainStream::immediately(read_stream);
            response_parts.extensions.insert(read_stream);
            let write_stream = RemainStream::immediately(write_stream);
            response_parts.extensions.insert(write_stream);
            Either::right(Empty::new().map_err(|never| match never {}))
        };

        Ok(hyper::Response::from_parts(response_parts, body))
    }
}
