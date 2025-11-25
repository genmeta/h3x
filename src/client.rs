use std::{mem, pin::Pin, sync::Arc};

use bytes::{Buf, Bytes};
use futures::{Stream, future::BoxFuture, stream};
use http::{
    HeaderMap, HeaderValue, Method, Uri,
    header::{IntoHeaderName, InvalidHeaderValue},
    uri::{Authority, PathAndQuery, Scheme},
};
use tokio::io::AsyncBufRead;

use crate::{
    codec::StreamReader,
    connection::{ConnectionState, QPackDecoder, QPackEncoder},
    entity::{
        Entity,
        stream::{ReadStream, StreamError, WriteStream},
    },
    qpack::field_section::FieldSection,
    quic,
    varint::VarInt,
};

type PendingStream = BoxFuture<
    'static,
    Result<
        (
            Pin<Box<dyn quic::ReadStream + Send>>,
            Pin<Box<dyn quic::WriteStream + Send>>,
        ),
        quic::ConnectionError,
    >,
>;

pub struct PendingRequest {
    stream: PendingStream,
    request: Entity,
    // response: Entity
    encoder: Arc<QPackEncoder>,
    decoder: Arc<QPackDecoder>,
    connection: Arc<ConnectionState<dyn quic::Close + Unpin + Send>>,
}

impl PendingRequest {
    fn header_mut(&mut self) -> &mut FieldSection {
        self.request
            .header_mut()
            .expect("Request in Header stage as it unsend")
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.header_mut().header_map
    }

    pub fn set_scheme(mut self, scheme: Scheme) -> Self {
        self.header_mut().set_scheme(scheme);
        self
    }

    pub fn set_authority(mut self, authority: Authority) -> Self {
        self.header_mut().set_authority(authority);
        self
    }

    pub fn set_path(mut self, path: PathAndQuery) -> Self {
        self.header_mut().set_path(path);
        self
    }

    pub fn set_uri(mut self, uri: Uri) -> Self {
        self.header_mut().set_uri(uri);
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

    pub async fn r#do(mut self, method: Method) -> Result<(Request, Response), StreamError> {
        self.header_mut().set_method(method);

        let (reader, writer) = self.stream.await.map_err(quic::StreamError::from)?;
        let mut response = Response {
            entity: Entity::unresolved_response(),
            stream: ReadStream::new(reader, self.decoder, self.connection.clone()),
        };

        let mut request = Request {
            entity: Entity::unresolved_request(),
            stream: WriteStream::new(writer, self.encoder, self.connection.clone()),
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

    pub async fn options(self) -> Result<(Request, Response), StreamError> {
        self.r#do(Method::OPTIONS).await
    }

    pub async fn get(self) -> Result<(Request, Response), StreamError> {
        self.r#do(Method::GET).await
    }

    pub async fn post(self) -> Result<(Request, Response), StreamError> {
        self.r#do(Method::POST).await
    }

    pub async fn put(self) -> Result<(Request, Response), StreamError> {
        self.r#do(Method::PUT).await
    }

    pub async fn head(self) -> Result<(Request, Response), StreamError> {
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

impl Drop for Request {
    fn drop(&mut self) {
        if !self.entity.is_complete() {
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
