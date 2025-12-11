use std::mem;

use bytes::{Buf, Bytes};
use futures::future::BoxFuture;
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{AsHeaderName, IntoHeaderName},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::Report;

use crate::{
    entity::{
        Entity, EntityStage, IllegalEntityOperator,
        stream::{ReadStream, StreamError, WriteStream},
    },
    varint::VarInt,
};

pub struct UnresolvedRequest {
    request: Request,
    response: Response,
}

impl UnresolvedRequest {
    pub(super) fn new(read_stream: ReadStream, write_stream: WriteStream) -> Self {
        Self {
            request: Request {
                entity: Entity::unresolved_request(),
                stream: read_stream,
            },
            response: Response {
                entity: Entity::unresolved_response(),
                stream: write_stream,
            },
        }
    }

    pub async fn resolve(mut self) -> Result<(Request, Response), StreamError> {
        self.request
            .stream
            .read_header(&mut self.request.entity)
            .await?;
        Ok((self.request, self.response))
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
    entity: Entity,
    stream: ReadStream,
    // agent: RemoteAgent,
    // parameters: Parameters
}

impl Request {
    pub fn method(&self) -> Method {
        self.entity.header().method()
    }

    pub fn set_method(&mut self, new: Method) {
        self.entity.header_mut().set_method(new);
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.entity.header().scheme()
    }

    pub fn set_scheme(&mut self, new: Scheme) {
        self.entity.header_mut().set_scheme(new);
    }

    pub fn authority(&self) -> Option<Authority> {
        self.entity.header().authority()
    }

    pub fn set_authority(&mut self, new: Authority) {
        self.entity.header_mut().set_authority(new);
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        self.entity.header().path()
    }

    pub fn set_path(&mut self, new: PathAndQuery) {
        self.entity.header_mut().set_path(new);
    }

    pub fn uri(&self) -> Uri {
        self.entity.header().uri()
    }

    pub fn headers(&self) -> &http::HeaderMap {
        &self.entity.header().header_map
    }

    pub fn headers_mut(&mut self) -> Result<&mut http::HeaderMap, StreamError> {
        Ok(&mut self.entity.header_mut().header_map)
    }

    pub fn header(&self, name: impl AsHeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_all(&mut self.entity).await
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, StreamError>> {
        self.stream.read(&mut self.entity).await
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_trailer(&mut self.entity).await
    }
}

// TODO: check whether request completion or not in drop?

pub struct Response {
    entity: Entity,
    stream: WriteStream,
    // agent: LocalAgent
}

impl Response {
    pub fn headers(&self) -> &http::HeaderMap {
        &self.entity.header().header_map
    }

    pub fn headers_mut(&mut self) -> Result<&mut http::HeaderMap, StreamError> {
        if self.entity.stage() > EntityStage::Header {
            return Err(IllegalEntityOperator::ModifyHeaderAfterSent.into());
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

    pub fn set_status(&mut self, status: http::StatusCode) -> Result<&mut Self, StreamError> {
        if self.entity.stage() > EntityStage::Header {
            return Err(IllegalEntityOperator::ModifyHeaderAfterSent.into());
        }
        self.entity.header_mut().set_status(status);
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.flush(&mut self.entity).await?;
        Ok(self)
    }

    pub fn set_body(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        if self.entity.stage() > EntityStage::Body {
            return Err(IllegalEntityOperator::ModifyBodyAfterSent.into());
        }
        if self.entity.stage() == EntityStage::Body {
            return Err(IllegalEntityOperator::ReplaceBodyWhileSending.into());
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
        if self.entity.stage() > EntityStage::Trailer {
            return Err(IllegalEntityOperator::ModifyTrailerAfterSent.into());
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
}

impl Drop for Response {
    fn drop(&mut self) {
        if !self.entity.is_complete() {
            // It's ok to take: Response will not be used after drop
            let mut stream = self.stream.take();
            let mut entity = mem::replace(&mut self.entity, Entity::unresolved_response());
            tokio::spawn(async move {
                if let Err(StreamError::IllegalEntityOperator { source }) =
                    stream.close(&mut entity).await
                {
                    tracing::warn!(
                        target: "h3x::server",
                        "Response stream cannot be closed properly: {}", Report::from_error(source)
                    );
                }
            });
        }
    }
}
