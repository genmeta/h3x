use std::{error::Error, mem};

use bytes::{Buf, Bytes};
use futures::{Stream, stream};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{IntoHeaderName, InvalidHeaderValue},
    uri::{Authority, PathAndQuery, Scheme},
};
use snafu::Snafu;
use tokio::io::AsyncBufRead;

use crate::{
    codec::StreamReader,
    endpoint::{client::Client, pool::ConnectError},
    entity::{
        Entity, EntityStage, IllegalEntityOperator,
        stream::{ReadStream, StreamError, WriteStream},
    },
    quic,
    varint::VarInt,
};

#[derive(Clone)]
pub struct PendingRequest<'c, C: quic::Connect> {
    client: &'c Client<C>,
    request: Entity,
}

impl<'c, C: quic::Connect + std::fmt::Debug> std::fmt::Debug for PendingRequest<'c, C>
where
    C::Connection: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRequest")
            .field("client", &self.client)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Debug, Snafu)]
pub enum RequestError<E: Error + 'static> {
    #[snafu(transparent)]
    Connect { source: ConnectError<E> },
    #[snafu(transparent)]
    Stream { source: StreamError },
}

impl<C: quic::Connect> Client<C> {
    pub fn new_request(&self) -> PendingRequest<'_, C> {
        let mut request = Entity::unresolved_request();
        _ = request.enable_streaming();
        PendingRequest {
            client: self,
            request,
        }
    }
}

impl<C: quic::Connect> PendingRequest<'_, C> {
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.request.header_mut().header_map
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.request.header().scheme()
    }

    pub fn set_scheme(mut self, scheme: Scheme) -> Self {
        self.request.header_mut().set_scheme(scheme);
        self
    }

    pub fn authority(&self) -> Option<Authority> {
        self.request.header().authority()
    }

    pub fn set_authority(mut self, authority: Authority) -> Self {
        self.request.header_mut().set_authority(authority);
        self
    }

    pub fn set_path(mut self, path: PathAndQuery) -> Self {
        self.request.header_mut().set_path(path);
        self
    }

    pub fn set_uri(mut self, uri: Uri) -> Self {
        self.request.header_mut().set_uri(uri);
        self
    }

    pub fn set_header(
        mut self,
        name: impl IntoHeaderName,
        value: impl TryInto<HeaderValue, Error = InvalidHeaderValue>,
    ) -> Result<Self, InvalidHeaderValue> {
        let value = value.try_into()?;
        self.headers_mut().insert(name, value);
        Ok(self)
    }

    pub fn set_headers(mut self, headers: HeaderMap) -> Self {
        *self.headers_mut() = headers;
        self
    }

    pub fn set_body(mut self, body: impl Buf) -> Self {
        self.request
            .set_body(body)
            .expect("Request in Header stage as it unsend");
        self
    }
}

impl<C: quic::Connect> PendingRequest<'_, C>
where
    C::Connection: Send + 'static,
    <C::Connection as quic::ManageStream>::StreamReader: Send,
    <C::Connection as quic::ManageStream>::StreamWriter: Send,
{
    pub async fn r#do(
        mut self,
        method: Method,
    ) -> Result<(Request, Response), RequestError<C::Error>> {
        self.request.header_mut().set_method(method);

        let authority = self
            .request
            .header()
            .authority()
            .expect("TODO: validate reqeust pseudo headers");
        let host = authority.host();
        let connection = self.client.connect(host).await?;

        let (read_stream, write_stream) = connection
            .open_request_stream()
            .await
            .map_err(StreamError::from)?;

        let mut response = Response {
            entity: Entity::unresolved_response(),
            stream: read_stream,
        };

        let mut request = Request {
            entity: self.request,
            stream: write_stream,
        };

        let do_request = async {
            request.stream.send_header(&mut request.entity).await?;
            // non-streaming body: application called `set_body`
            if !request.entity.is_streaming() {
                request
                    .stream
                    .send_chunked_body(&mut request.entity)
                    .await?
            }
            Ok::<_, StreamError>(())
        };

        let read_response_header = async {
            response.stream.read_header(&mut response.entity).await?;
            Ok::<_, StreamError>(())
        };

        tokio::try_join!(do_request, read_response_header,)?;
        debug_assert!(response.entity.is_response(), "Checked in read_header");

        Ok((request, response))
    }

    pub async fn options(self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.r#do(Method::OPTIONS).await
    }

    pub async fn get(self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.r#do(Method::GET).await
    }

    pub async fn post(self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.r#do(Method::POST).await
    }

    pub async fn put(self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.r#do(Method::PUT).await
    }

    pub async fn head(self) -> Result<(Request, Response), RequestError<C::Error>> {
        self.r#do(Method::HEAD).await
    }
}

pub struct Request {
    entity: Entity,
    stream: WriteStream,
}

impl Request {
    pub fn method(&self) -> Method {
        self.entity.header().method()
    }

    pub fn scheme(&self) -> Option<Scheme> {
        self.entity.header().scheme()
    }

    pub fn authority(&self) -> Option<Authority> {
        self.entity.header().authority()
    }

    pub fn path(&self) -> Option<PathAndQuery> {
        self.entity.header().path()
    }

    pub fn uri(&self) -> Uri {
        self.entity.header().uri()
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.entity.header().header_map
    }

    pub async fn write(&mut self, content: impl Buf) -> Result<&mut Self, StreamError> {
        self.stream
            .send_streaming_body(&mut self.entity, content)
            .await?;
        Ok(self)
    }

    pub async fn flush(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.flush(&mut self.entity).await?;
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

impl Drop for Request {
    fn drop(&mut self) {
        if !self.entity.is_complete() {
            // Its ok to take: Request will not be used after drop
            let stream = self.stream.take();
            let entity = mem::replace(&mut self.entity, Entity::unresolved_request());
            let mut request = Request { entity, stream };
            tokio::spawn(async move { request.close().await });
        }
    }
}

pub struct Response {
    entity: Entity,
    stream: ReadStream,
}

impl Response {
    pub fn streaming(mut self) -> Result<Self, StreamError> {
        self.entity.enable_streaming()?;
        Ok(self)
    }

    pub async fn next_response(&mut self) -> Result<&mut Self, StreamError> {
        self.stream.read_header(&mut self.entity).await?;
        Ok(self)
    }

    pub fn status(&self) -> http::StatusCode {
        self.entity.header().status()
    }

    pub async fn read_all(&mut self) -> Result<impl Buf, StreamError> {
        self.stream.read_all(&mut self.entity).await
    }

    pub async fn read(&mut self) -> Option<Result<Bytes, StreamError>> {
        self.stream.read(&mut self.entity).await
    }

    pub fn as_stream(&mut self) -> impl Stream<Item = Result<Bytes, StreamError>> + '_ {
        stream::unfold(self, |response| async {
            let result = response.read().await?;
            Some((result, response))
        })
    }

    pub fn into_stream(self) -> impl Stream<Item = Result<Bytes, StreamError>> {
        stream::unfold(self, |mut response| async {
            let result = response.read().await?;
            Some((result, response))
        })
    }

    pub fn as_reader(&mut self) -> impl AsyncBufRead + '_ {
        StreamReader::new(self.as_stream())
    }

    pub fn into_reader(self) -> impl AsyncBufRead {
        StreamReader::new(self.into_stream())
    }

    pub async fn trailers(&mut self) -> Result<&HeaderMap, StreamError> {
        self.stream.read_trailer(&mut self.entity).await
    }
}
