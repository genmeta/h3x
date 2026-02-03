use std::{error::Error, fmt::Display, pin::pin};

use futures::TryFutureExt;
use http_body::Body;
use http_body_util::BodyExt;

use super::{StreamError, WriteStream};
use crate::{
    hyper::header_map_to_field_lines,
    qpack::field::hyper::{
        hyper_request_parts_to_field_lines, hyper_response_parts_to_field_lines,
    },
};

#[derive(Debug)]
pub enum SendMesageError<E> {
    Stream { source: StreamError },
    Body { source: E },
}

impl<E> SendMesageError<E> {
    pub fn map_body_error<E1>(self, f: impl FnOnce(E) -> E1) -> SendMesageError<E1> {
        match self {
            SendMesageError::Stream { source } => SendMesageError::Stream { source },
            SendMesageError::Body { source } => SendMesageError::Body { source: f(source) },
        }
    }
}

impl<E: Display> Display for SendMesageError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendMesageError::Stream { source } => source.fmt(f),
            SendMesageError::Body { source } => source.fmt(f),
        }
    }
}

impl<E: Error> Error for SendMesageError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SendMesageError::Stream { source } => source.source(),
            SendMesageError::Body { source } => source.source(),
        }
    }
}

impl WriteStream {
    async fn send_hyper_body<B: Body>(&mut self, body: B) -> Result<(), SendMesageError<B::Error>> {
        let mut body = pin!(body);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|source| SendMesageError::Body { source })?;
            let frame = match frame.into_data() {
                Ok(data) => {
                    self.send_data(data)
                        .map_err(|source| SendMesageError::Stream { source })
                        .await?;
                    continue;
                }
                Err(frame) => frame,
            };
            let frame = match frame.into_trailers() {
                Ok(trailers) => {
                    self.send_header(header_map_to_field_lines(trailers))
                        .map_err(|source| SendMesageError::Stream { source })
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

    pub async fn send_hyper_request<B: Body>(
        &mut self,
        request: http::Request<B>,
    ) -> Result<(), SendMesageError<B::Error>> {
        let (parts, body) = request.into_parts();
        self.send_header(hyper_request_parts_to_field_lines(parts))
            .map_err(|source| SendMesageError::Stream { source })
            .await?;
        self.send_hyper_body(body).await
    }

    pub async fn send_hyper_response<B: Body>(
        &mut self,
        response: http::Response<B>,
    ) -> Result<(), SendMesageError<B::Error>> {
        let (parts, body) = response.into_parts();
        self.send_header(hyper_response_parts_to_field_lines(parts))
            .map_err(|source| SendMesageError::Stream { source })
            .await?;
        self.send_hyper_body(body).await
    }
}
