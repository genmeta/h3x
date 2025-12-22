use bytes::{Buf, Bytes};
use futures::future::BoxFuture;
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::Report;
use tracing::Instrument;

use crate::{
    agent::{LocalAgent, RemoteAgent},
    message::{
        Message, MessageError, MessageStage,
        stream::{ReadStream, ReadToStringError, StreamError, WriteStream},
    },
    varint::VarInt,
};

pub struct UnresolvedRequest {
    request_stream: ReadStream,
    remote_agent: Option<RemoteAgent>,
    response_stream: WriteStream,
    local_agent: LocalAgent,
}

impl UnresolvedRequest {
    pub(super) fn new(
        read_stream: ReadStream,
        write_stream: WriteStream,
        local_agent: LocalAgent,
        remote_agent: Option<RemoteAgent>,
    ) -> Self {
        Self {
            request_stream: read_stream,
            remote_agent,
            response_stream: write_stream,
            local_agent,
        }
    }

    pub async fn resolve(self) -> Result<(Request, Response), StreamError> {
        let mut request = Request {
            message: Message::unresolved_request(),
            stream: self.request_stream,
            agent: self.remote_agent,
        };
        request.stream.read_header(&mut request.message).await?;
        let response = Response {
            entity: Message::unresolved_response(),
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
        self.stream.read(&mut self.message).await
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_all(&mut self.message).await
    }

    pub async fn read_to_bytes(&mut self) -> Result<Bytes, StreamError> {
        self.stream.read_to_bytes(&mut self.message).await
    }

    pub async fn read_to_string(&mut self) -> Result<String, ReadToStringError> {
        self.stream.read_to_string(&mut self.message).await
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_trailer(&mut self.message).await
    }

    pub fn agent(&self) -> Option<&RemoteAgent> {
        self.agent.as_ref()
    }
}

pub struct Response {
    entity: Message,
    stream: WriteStream,
    agent: LocalAgent,
}

impl Response {
    pub fn headers(&self) -> &http::HeaderMap {
        &self.entity.header().header_map
    }

    pub fn headers_mut(&mut self) -> Result<&mut http::HeaderMap, StreamError> {
        if self.entity.stage() > MessageStage::Header {
            return Err(MessageError::HeaderAlreadySent.into());
        }
        Ok(&mut self.entity.header_mut().header_map)
    }

    pub fn set_header(
        &mut self,
        name: impl IntoHeaderName,
        value: HeaderValue,
    ) -> Result<&mut Self, StreamError> {
        self.headers_mut()?.insert(name, value);
        Ok(self)
    }

    pub fn status(&self) -> Option<http::StatusCode> {
        Some(self.entity.header().status())
    }

    pub fn set_status(&mut self, status: http::StatusCode) -> Result<&mut Self, StreamError> {
        self.entity.header_mut().set_status(status);
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.flush(&mut self.entity).await?;
        Ok(self)
    }

    pub fn set_body(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        if self.entity.stage() > MessageStage::Body {
            return Err(MessageError::BodyAlreadySending.into());
        }
        if self.entity.stage() == MessageStage::Body {
            return Err(MessageError::BodyReplacementDuringSend.into());
        }
        self.entity.set_body(content)?;
        Ok(self)
    }

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.stream
            .send_streaming_body(&mut self.entity, content)
            .await?;
        Ok(self)
    }

    pub fn trailers(&self) -> &HeaderMap {
        self.entity.trailers()
    }

    pub fn trailers_mut(&mut self) -> Result<&mut HeaderMap, StreamError> {
        if self.entity.stage() > MessageStage::Trailer {
            return Err(MessageError::TrailerAlreadySent.into());
        }
        Ok(self.entity.trailers_mut()?)
    }

    pub fn set_trailer(
        &mut self,
        name: impl IntoHeaderName,
        value: HeaderValue,
    ) -> Result<&mut Self, StreamError> {
        self.trailers_mut()?.insert(name, value);
        Ok(self)
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> Result<&mut Self, StreamError> {
        *self.trailers_mut()? = map;
        Ok(self)
    }

    pub async fn close(&mut self) -> Result<(), StreamError> {
        self.stream.close(&mut self.entity).await
    }

    pub async fn cancel(&mut self, code: VarInt) -> Result<(), StreamError> {
        self.stream.cancel(code).await
    }

    pub fn agent(&self) -> &LocalAgent {
        &self.agent
    }

    /// Async drop the response properly
    pub(crate) fn drop(&mut self) -> Option<impl Future<Output = ()> + Send + use<>> {
        if self.entity.is_complete() || self.entity.is_destroyed() {
            return None;
        }
        // It's ok to take: Response will not be used after drop
        let mut stream = self.stream.take();
        let mut entity = self.entity.take();
        Some(async move {
            if let Err(StreamError::MessageOperation { source }) = stream.close(&mut entity).await {
                tracing::warn!(
                    target: "h3x::server", error = %Report::from_error(source),
                    "Response stream cannot be closed properly",
                );
            }
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
