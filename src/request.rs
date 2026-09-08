use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use http_body::Body as _;

use crate::{
    BodyWriter, Chunk, Endpoint, Error, Fixed, Response, ResponseFuture, platform::BoxFuture,
};

/// A one-shot client request. Construction never starts network or body work.
pub struct Request<B> {
    builder: http::request::Builder,
    body: B,
    local: Option<Arc<Endpoint>>,
}

impl<B> Request<B> {
    pub(crate) fn new(
        endpoint: Arc<Endpoint>,
        method: http::Method,
        url: &str,
        body: B,
    ) -> Result<Self, Error> {
        let uri: http::Uri = url.parse().map_err(|source| Error::InvalidMessage {
            source: Arc::new(source),
        })?;
        if uri.authority().is_none() || method != http::Method::CONNECT && uri.scheme().is_none() {
            return Err(Error::InvalidMessage {
                source: Arc::new(std::io::Error::other(
                    "request URL requires a scheme and authority",
                )),
            });
        }
        Ok(Self {
            builder: http::Request::builder()
                .method(method)
                .uri(uri)
                .version(http::Version::HTTP_3),
            body,
            local: Some(endpoint),
        })
    }

    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        K::Error: Into<http::Error>,
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        self.builder = self.builder.header(name, value);
        self
    }

    fn build(self) -> Result<(http::Request<B>, Option<Arc<Endpoint>>), Error> {
        let request = self
            .builder
            .body(self.body)
            .map_err(|source| Error::InvalidMessage {
                source: Arc::new(source),
            })?;
        Ok((request, self.local))
    }
}

impl Request<Fixed> {
    pub fn body(mut self, data: impl Into<Bytes>) -> Self {
        self.body = Fixed::from(data.into());
        self
    }
}

pub struct RequestFuture(BoxFuture<'static, Result<Response, Error>>);
pub struct ChunkRequestFuture(BoxFuture<'static, Result<(BodyWriter, ResponseFuture), Error>>);

impl Future for RequestFuture {
    type Output = Result<Response, Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
impl Future for ChunkRequestFuture {
    type Output = Result<(BodyWriter, ResponseFuture), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

impl IntoFuture for Request<Fixed> {
    type Output = Result<Response, Error>;
    type IntoFuture = RequestFuture;
    fn into_future(self) -> Self::IntoFuture {
        RequestFuture(Box::pin(async move {
            let (mut request, local) = self.build()?;
            #[cfg(target_arch = "wasm32")]
            return execute_fixed(local, request).await;
            #[cfg(not(target_arch = "wasm32"))]
            {
                let length = request
                    .body()
                    .size_hint()
                    .exact()
                    .expect("Fixed has a known length");
                if request.method() != http::Method::CONNECT {
                    match crate::protocol::headers::content_length(request.headers())
                        .map_err(Error::into_invalid_message)?
                    {
                        Some(declared) if declared != length => {
                            return Err(Error::InvalidMessage {
                                source: Arc::new(std::io::Error::other(
                                    "Content-Length does not match Fixed body",
                                )),
                            });
                        }
                        None => {
                            request
                                .headers_mut()
                                .insert(http::header::CONTENT_LENGTH, length.into());
                        }
                        _ => {}
                    }
                }
                execute_fixed(local, request).await
            }
        }))
    }
}

impl IntoFuture for Request<Chunk> {
    type Output = Result<(BodyWriter, ResponseFuture), Error>;
    type IntoFuture = ChunkRequestFuture;
    fn into_future(self) -> Self::IntoFuture {
        ChunkRequestFuture(Box::pin(async move {
            let (request, local) = self.build()?;
            execute_chunk(local, request).await
        }))
    }
}

async fn execute_fixed(
    local: Option<Arc<Endpoint>>,
    request: http::Request<Fixed>,
) -> Result<Response, Error> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let target = request
            .uri()
            .authority()
            .ok_or_else(|| Error::invalid_state("request target"))?
            .as_str();
        let connection = crate::runtime::Runtime::get(local, target).await?;
        let response = connection.sender().request(request).await?;
        Ok(Response::new(
            response,
            connection.remote_authority().cloned(),
        ))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (local, request);
        Err(Error::Unsupported {
            operation: "pooled request",
        })
    }
}

async fn execute_chunk(
    local: Option<Arc<Endpoint>>,
    request: http::Request<Chunk>,
) -> Result<(BodyWriter, ResponseFuture), Error> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let target = request
            .uri()
            .authority()
            .ok_or_else(|| Error::invalid_state("request target"))?
            .as_str();
        let connection = crate::runtime::Runtime::get(local, target).await?;
        let (writer, response) = connection
            .sender()
            .request_streaming(request.into_parts().0)
            .await?;
        Ok((
            writer,
            ResponseFuture::new(response, connection.remote_authority().cloned()),
        ))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (local, request);
        Err(Error::Unsupported {
            operation: "pooled streaming request",
        })
    }
}
