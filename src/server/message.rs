use bytes::{Buf, Bytes};
use futures::{Sink, Stream, future::BoxFuture, sink, stream};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::Report;
use tracing::Instrument;

use crate::{
    agent::{LocalAgent, RemoteAgent},
    error::Code,
    message::{
        MalformedMessageError, Message, MessageStage,
        stream::{ReadStream, ReadToStringError, StreamError, WriteStream},
    },
    qpack::field_section::PseudoHeaders,
};

pub struct UnresolvedRequest {
    pub request_stream: ReadStream,
    pub remote_agent: Option<RemoteAgent>,
    pub response_stream: WriteStream,
    pub local_agent: LocalAgent,
}

impl UnresolvedRequest {
    pub async fn resolve(self) -> Result<(Request, Response), StreamError> {
        let mut request = Request {
            message: Message::unresolved_request(),
            stream: self.request_stream,
            agent: self.remote_agent,
        };
        request
            .stream
            .read_message_header(&mut request.message)
            .await?;
        let response = Response {
            message: Message::unresolved_response(),
            stream: self.response_stream,
            agent: self.local_agent,
        };
        Ok((request, response))
    }
}

impl IntoFuture for UnresolvedRequest {
    type Output = Result<(Request, Response), StreamError>;

    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.resolve())
    }
}

pub struct Request {
    message: Message,
    stream: ReadStream,
    agent: Option<RemoteAgent>,
}

impl Request {
    pub fn method(&self) -> Method {
        self.message.header().method()
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.message.header().scheme()
    }

    pub fn authority(&self) -> Option<Authority> {
        self.message.header().authority()
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        self.message.header().path()
    }

    pub fn uri(&self) -> Uri {
        self.message.header().uri()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.message.header().header_map
    }

    pub fn header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, StreamError>> {
        self.stream.read_message(&mut self.message).await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_message_full_body(&mut self.message).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, StreamError> {
        self.stream
            .read_message_body_to_bytes(&mut self.message)
            .await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.stream
            .read_message_body_to_string(&mut self.message)
            .await
    }

    pub fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::unfold(self, async |this| {
            this.read().await.map(|item| (item, this))
        })
    }

    pub fn into_stream(self) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::unfold(self, async |mut this| {
            this.read().await.map(|item| (item, this))
        })
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_message_trailer(&mut self.message).await
    }

    /// Low level access to the underlying read stream
    pub fn read_stream(&mut self) -> &mut ReadStream {
        &mut self.stream
    }

    pub fn agent(&self) -> Option<&RemoteAgent> {
        self.agent.as_ref()
    }
}

pub struct Response {
    message: Message,
    stream: WriteStream,
    agent: LocalAgent,
}

impl Response {
    fn check_message_operation(
        &mut self,
        operation: &str,
        operate: impl FnOnce(&mut Self) -> Result<(), MalformedMessageError>,
    ) {
        if self.message.is_malformed() {
            tracing::warn!(
                target: "h3x::server", operation,
                "Response is malformed, operation will not affect the response stream",
            );
        }
        if let Err(error) = operate(self) {
            tracing::warn!(
                target: "h3x::server", operation, error = %Report::from_error(error),
                "Operation malformed the response message, response stream will be cancelled with H3_REQUEST_CANCELLED",
            );
            self.message.set_malformed();
        }
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.message.header().header_map
    }

    pub fn headers_mut(&mut self) -> &mut http::HeaderMap {
        self.check_message_operation("modify_headers", |this| {
            if this.message.stage() > MessageStage::Header {
                return Err(MalformedMessageError::HeaderAlreadySent);
            }
            Ok(())
        });
        &mut self.message.header_mut().header_map
    }

    pub fn set_header(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.headers_mut().insert(name, value);
        self
    }

    pub fn status(&self) -> Option<http::StatusCode> {
        match self.message.header().pseudo_headers {
            Some(PseudoHeaders::Response { ref status }) => *status,
            _ => unreachable!(),
        }
    }

    pub fn set_status(&mut self, status: http::StatusCode) -> &mut Self {
        self.check_message_operation("set_status", |this| {
            if this.message.stage() > MessageStage::Header {
                return Err(MalformedMessageError::HeaderAlreadySent);
            }
            Ok(())
        });
        self.message.header_mut().set_status(status);
        self
    }

    pub fn set_body(&mut self, content: impl Buf) -> &mut Self {
        self.check_message_operation("write_chunked_body", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            if this.message.stage() > MessageStage::Body {
                return Err(MalformedMessageError::BodyAlreadySending);
            }
            if this.message.stage() == MessageStage::Body {
                return Err(MalformedMessageError::BodyReplacementDuringSend);
            }
            this.message.chunked_body()?;
            Ok(())
        });
        self.message.set_body(content);
        self
    }

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.check_message_operation("write_streaming_body", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            this.message.streaming_body()?;
            Ok(())
        });
        self.stream
            .send_message_streaming_body(&mut self.message, content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.check_message_operation("flush_response", |this| {
            if !this.message.header().is_empty() {
                this.message.header().check_pseudo()?;
            }
            Ok(())
        });
        self.stream.flush_message(&mut self.message).await?;
        Ok(self)
    }

    pub fn as_sink<B: Buf>(&mut self) -> impl Sink<B, Error = StreamError> {
        sink::unfold(self, async |this, item: B| this.write(item).await)
    }

    pub fn into_sink<B: Buf>(self) -> impl Sink<B, Error = StreamError> {
        sink::unfold(self, async |mut this, item: B| {
            this.write(item).await?;
            Ok(this)
        })
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.message.trailers()
    }

    pub fn trailers_mut(&mut self) -> &mut HeaderMap {
        self.check_message_operation("modify_trailers", |this| {
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::BodyOrTrailerOnInterimResponse);
            }
            if this.message.stage() > MessageStage::Trailer {
                return Err(MalformedMessageError::TrailerAlreadySent);
            }
            Ok(())
        });
        self.message.trailers_mut()
    }

    pub fn set_trailer(&mut self, name: impl IntoHeaderName, value: HeaderValue) -> &mut Self {
        self.trailers_mut().insert(name, value);
        self
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> &mut Self {
        *self.trailers_mut() = map;
        self
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.check_message_operation("close_response", |this| {
            this.message.header().check_pseudo()?;
            if this.message.is_interim_response() {
                return Err(MalformedMessageError::FinalResponseRequired);
            }
            Ok(())
        });
        self.stream.close_message(&mut self.message).await
    }

    pub async fn cancel(&mut self, code: Code) -> Result<(), StreamError> {
        self.stream.cancel(code).await
    }

    /// Low level access to the underlying write stream
    pub fn write_stream(&mut self) -> &mut WriteStream {
        &mut self.stream
    }

    pub fn agent(&self) -> &LocalAgent {
        &self.agent
    }

    /// Async drop the response properly
    pub(crate) fn drop(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if self.message.is_complete() || self.message.is_dropped() {
            return None;
        }
        // It's ok to take: Response will not be used after drop
        let mut stream = self.stream.take();
        let mut message = self.message.take();

        if !message.is_malformed() {
            let check = || {
                message.header().check_pseudo()?;
                if message.is_interim_response() {
                    return Err(MalformedMessageError::FinalResponseRequired);
                }
                Ok(())
            };
            if let Err(error) = check() {
                message.set_malformed();
                tracing::warn!(
                    target: "h3x::server", error = %Report::from_error(error),
                    "Response stream cannot be closed properly as its malformed",
                );
            }
        }

        Some(async move {
            _ = stream.close_message(&mut message).await;
        })
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        if let Some(future) = self.drop() {
            tokio::spawn(future.in_current_span());
        }
    }
}
