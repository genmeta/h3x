use std::{error::Error, fmt::Display, pin::pin};

use futures::TryFutureExt;
use http_body::Body;
use http_body_util::BodyExt;

use super::{MessageStreamError, WriteStream};
use crate::qpack::field::hyper::{
    header_map_to_field_lines, hyper_request_parts_to_field_lines,
    hyper_response_parts_to_field_lines,
};

#[derive(Debug)]
pub enum SendMessageError<E> {
    Stream { source: MessageStreamError },
    Body { source: E },
}

impl<E> SendMessageError<E> {
    pub fn map_body_error<E1>(self, f: impl FnOnce(E) -> E1) -> SendMessageError<E1> {
        match self {
            SendMessageError::Stream { source } => SendMessageError::Stream { source },
            SendMessageError::Body { source } => SendMessageError::Body { source: f(source) },
        }
    }
}

impl<E: Display> Display for SendMessageError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendMessageError::Stream { source } => source.fmt(f),
            SendMessageError::Body { source } => source.fmt(f),
        }
    }
}

impl<E: Error> Error for SendMessageError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SendMessageError::Stream { source } => source.source(),
            SendMessageError::Body { source } => source.source(),
        }
    }
}

impl WriteStream {
    pub(crate) async fn send_hyper_body<B: Body>(
        &mut self,
        body: B,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
    {
        let mut body = pin!(body);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|source| SendMessageError::Body { source })?;
            let frame = match frame.into_data() {
                Ok(data) => {
                    self.send_data(data)
                        .map_err(|source| SendMessageError::Stream { source })
                        .await?;
                    continue;
                }
                Err(frame) => frame,
            };
            let frame = match frame.into_trailers() {
                Ok(trailers) => {
                    self.send_header(header_map_to_field_lines(trailers))
                        .map_err(|source| SendMessageError::Stream { source })
                        .await?;
                    break;
                }
                Err(frame) => frame,
            };

            tracing::warn!("ignore unknown http body frame");
            _ = frame;
        }
        Ok(())
    }

    pub async fn send_hyper_request_parts(
        &mut self,
        parts: http::request::Parts,
    ) -> Result<(), MessageStreamError> {
        self.send_header(hyper_request_parts_to_field_lines(parts))
            .await
    }

    pub async fn send_hyper_request<B: Body>(
        &mut self,
        request: http::Request<B>,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
    {
        let (parts, body) = request.into_parts();
        self.send_header(hyper_request_parts_to_field_lines(parts))
            .map_err(|source| SendMessageError::Stream { source })
            .await?;
        self.send_hyper_body(body).await
    }

    pub async fn send_hyper_response_parts(
        &mut self,
        parts: http::response::Parts,
    ) -> Result<(), MessageStreamError> {
        self.send_header(hyper_response_parts_to_field_lines(parts))
            .await
    }

    pub async fn send_hyper_response<B: Body>(
        &mut self,
        response: http::Response<B>,
    ) -> Result<(), SendMessageError<B::Error>>
    where
        B::Data: Send,
    {
        let (parts, body) = response.into_parts();
        self.send_header(hyper_response_parts_to_field_lines(parts))
            .map_err(|source| SendMessageError::Stream { source })
            .await?;
        self.send_hyper_body(body).await
    }
}
