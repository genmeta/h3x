use std::mem;

use bytes::{Buf, Bytes};
use futures::future::BoxFuture;
use http::{
    HeaderMap, HeaderValue,
    header::{AsHeaderName, IntoHeaderName},
};

use crate::{
    entity::{
        Entity,
        stream::{ReadStream, StreamError, WriteStream},
    },
    varint::VarInt,
};

pub struct UnresolvedRequest {
    request: Request,
    response: Response,
}

impl UnresolvedRequest {
    pub fn streaming(self) -> Self {
        self
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
}

impl Request {
    pub fn headers(&self) -> &http::HeaderMap {
        &self.entity.header().header_map
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

pub struct Response {
    entity: Entity,
    stream: WriteStream,
}

impl Response {
    pub fn headers(&self) -> &http::HeaderMap {
        &self.entity.header().header_map
    }

    pub fn headers_mut(&mut self) -> Result<&mut http::HeaderMap, StreamError> {
        Ok(&mut self.entity.header_mut()?.header_map)
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
        self.entity.header_mut()?.set_status(status);
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.flush(&mut self.entity).await?;
        Ok(self)
    }

    pub fn set_body(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.entity.set_body(content)?;
        Ok(self)
    }

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.stream
            .send_streaming_body(&mut self.entity, content)
            .await?;
        Ok(self)
    }

    pub fn set_trailer(
        &mut self,
        name: impl IntoHeaderName,
        value: HeaderValue,
    ) -> Result<&mut Self, StreamError> {
        self.entity.trailers_mut()?.insert(name, value);
        Ok(self)
    }

    pub fn set_trailers(&mut self, map: HeaderMap) -> Result<&mut Self, StreamError> {
        *self.entity.trailers_mut()? = map;
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
            let stream = self.stream.take();
            let entity = mem::replace(&mut self.entity, Entity::unresolved_request());
            let mut response = Response { entity, stream };
            tokio::spawn(async move { response.close().await });
        }
    }
}
