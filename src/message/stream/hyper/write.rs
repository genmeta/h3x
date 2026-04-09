use std::pin::pin;

use http_body::Body;
use http_body_util::BodyExt;
use snafu::{ResultExt, Snafu};

use super::{MessageStreamError, WriteStream};
use crate::qpack::field::hyper::{
    header_map_to_field_lines, hyper_request_parts_to_field_lines,
    hyper_response_parts_to_field_lines,
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum SendMessageError<E: std::error::Error + 'static> {
    #[snafu(display("failed to send message on stream"))]
    Stream { source: MessageStreamError },
    #[snafu(display("failed to read body frame"))]
    Body { source: E },
}

impl<E: std::error::Error + 'static> SendMessageError<E> {
    pub fn map_body_error<E1: std::error::Error + 'static>(
        self,
        f: impl FnOnce(E) -> E1,
    ) -> SendMessageError<E1> {
        match self {
            SendMessageError::Stream { source } => SendMessageError::Stream { source },
            SendMessageError::Body { source } => SendMessageError::Body { source: f(source) },
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
        B::Error: std::error::Error + 'static,
    {
        let mut body = pin!(body);
        while let Some(frame) = body.frame().await {
            let frame = frame.context(send_message_error::BodySnafu)?;
            let frame = match frame.into_data() {
                Ok(data) => {
                    self.send_data(data)
                        .await
                        .context(send_message_error::StreamSnafu)?;
                    continue;
                }
                Err(frame) => frame,
            };
            let frame = match frame.into_trailers() {
                Ok(trailers) => {
                    self.send_header(header_map_to_field_lines(trailers))
                        .await
                        .context(send_message_error::StreamSnafu)?;
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
        B::Error: std::error::Error + 'static,
    {
        let (parts, body) = request.into_parts();
        self.send_header(hyper_request_parts_to_field_lines(parts))
            .await
            .context(send_message_error::StreamSnafu)?;
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
        B::Error: std::error::Error + 'static,
    {
        let (parts, body) = response.into_parts();
        self.send_header(hyper_response_parts_to_field_lines(parts))
            .await
            .context(send_message_error::StreamSnafu)?;
        self.send_hyper_body(body).await
    }
}
