use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue};
use http_body::Body as _;

use super::Response;
use crate::{BodyWriter, Chunk, Endpoint, Error, Fixed, platform::BoxFuture};

/// A one-shot client request. Construction never starts network or body work.
pub struct Request<B> {
    request: http::Request<B>,
    identity: Option<Arc<Endpoint>>,
}

impl<B> Request<B> {
    pub fn new(method: http::Method, url: &str, body: B) -> Result<Self, Error> {
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
            request: http::Request::builder()
                .method(method)
                .uri(uri)
                .version(http::Version::HTTP_3)
                .body(body)
                .map_err(|source| Error::InvalidMessage {
                    source: Arc::new(source),
                })?,
            identity: None,
        })
    }

    pub fn header<K, V>(mut self, name: K, value: V) -> Result<Self, Error>
    where
        K: TryInto<HeaderName>,
        K::Error: Into<http::Error>,
        V: TryInto<HeaderValue>,
        V::Error: Into<http::Error>,
    {
        let name = name.try_into().map_err(|source| Error::InvalidMessage {
            source: Arc::new(source.into()),
        })?;
        let value = value.try_into().map_err(|source| Error::InvalidMessage {
            source: Arc::new(source.into()),
        })?;
        self.request.headers_mut().append(name, value);
        Ok(self)
    }

    pub fn with_identity(mut self, identity: Arc<Endpoint>) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn request(&self) -> &http::Request<B> {
        &self.request
    }

    pub fn identity(&self) -> Option<&Arc<Endpoint>> {
        self.identity.as_ref()
    }
}

impl Request<Fixed> {
    pub fn body(mut self, data: impl Into<Bytes>) -> Self {
        *self.request.body_mut() = Fixed::from(data.into());
        self
    }
}

pub struct Executing(BoxFuture<'static, Result<Response, Error>>);
pub struct Streaming(BoxFuture<'static, Result<(BodyWriter, Executing), Error>>);

impl Future for Executing {
    type Output = Result<Response, Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}
impl Future for Streaming {
    type Output = Result<(BodyWriter, Executing), Error>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.as_mut().poll(cx)
    }
}

impl IntoFuture for Request<Fixed> {
    type Output = Result<Response, Error>;
    type IntoFuture = Executing;

    fn into_future(self) -> Self::IntoFuture {
        Executing(Box::pin(async move {
            let Self {
                request,
                identity: local,
            } = self;
            #[cfg(not(target_arch = "wasm32"))]
            {
                let mut request = request;
                prepare_fixed_body(&mut request)?;
                let target = request
                    .uri()
                    .authority()
                    .ok_or_else(|| Error::invalid_state("request target"))?
                    .as_str();
                let connection = crate::runtime::Runtime::get(local, target).await?;
                let authority = connection
                    .remote_authority()
                    .cloned()
                    .ok_or(Error::IdentityMismatch)?;
                let response = connection.protocol().request(request).await?;
                Ok(Response::new(response, authority))
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = (local, request);
                Err(Error::Unsupported {
                    operation: "pooled request",
                })
            }
        }))
    }
}

impl IntoFuture for Request<Chunk> {
    type Output = Result<(BodyWriter, Executing), Error>;
    type IntoFuture = Streaming;

    fn into_future(self) -> Self::IntoFuture {
        Streaming(Box::pin(async move {
            let Self {
                request,
                identity: local,
            } = self;
            #[cfg(not(target_arch = "wasm32"))]
            {
                let target = request
                    .uri()
                    .authority()
                    .ok_or_else(|| Error::invalid_state("request target"))?
                    .as_str();
                let connection = crate::runtime::Runtime::get(local, target).await?;
                let authority = connection
                    .remote_authority()
                    .cloned()
                    .ok_or(Error::IdentityMismatch)?;
                let (writer, response) = connection
                    .protocol()
                    .request_streaming(request.into_parts().0)
                    .await?;
                Ok((
                    writer,
                    Executing(Box::pin(async move {
                        Ok(Response::new(response.await?, authority))
                    })),
                ))
            }
            #[cfg(target_arch = "wasm32")]
            {
                let _ = (local, request);
                Err(Error::Unsupported {
                    operation: "pooled streaming request",
                })
            }
        }))
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn prepare_fixed_body(request: &mut http::Request<Fixed>) -> Result<(), Error> {
    if request.method() == http::Method::CONNECT {
        return Ok(());
    }
    let length = request
        .body()
        .size_hint()
        .exact()
        .expect("Fixed has a known length");
    match crate::protocol::headers::content_length(request.headers())
        .map_err(Error::into_invalid_message)?
    {
        Some(declared) if declared != length => Err(Error::InvalidMessage {
            source: Arc::new(std::io::Error::other(
                "Content-Length does not match Fixed body",
            )),
        }),
        None => {
            request
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, length.into());
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_validation_identity_and_response_cancellation() {
        let request = || {
            Request::new(
                http::Method::POST,
                "https://peer.example/",
                Fixed::default(),
            )
            .unwrap()
        };
        assert!(request().identity().is_none());
        assert!(Request::new(http::Method::GET, "/relative", Fixed::default()).is_err());
        assert!(request().header("bad\nname", "value").is_err());
        assert!(request().header("valid", "bad\nvalue").is_err());
        let repeated = request()
            .header("x-value", "one")
            .unwrap()
            .header("x-value", "two")
            .unwrap()
            .body("body");
        assert_eq!(
            repeated
                .request()
                .headers()
                .get_all("x-value")
                .iter()
                .count(),
            2
        );
        assert_eq!(repeated.request().body().size_hint().exact(), Some(4));
        assert!(matches!(
            request()
                .header("content-length", "9")
                .unwrap()
                .body("body")
                .await,
            Err(Error::InvalidMessage { .. })
        ));

        let cert = rcgen::generate_simple_self_signed(vec!["peer.example".to_owned()]).unwrap();
        let endpoint = Endpoint::new(
            "peer.example",
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            None,
        )
        .unwrap();
        let identified = endpoint.get("https://peer.example/").unwrap();
        assert!(Arc::ptr_eq(identified.identity().unwrap(), &endpoint));
        let authority = crate::RemoteAuthority::from_authenticated(
            endpoint.name(),
            endpoint.certificate().cert.clone(),
        )
        .unwrap();
        let response = Response::new(http::Response::new(()), authority.clone());
        assert_eq!(response.authority().name(), endpoint.name());
        assert_eq!(
            response
                .into_http()
                .extensions()
                .get::<crate::RemoteAuthority>()
                .unwrap()
                .name(),
            endpoint.name()
        );

        let (_tx, reply) = tokio::sync::oneshot::channel();
        let (stop, registration) = futures::future::AbortHandle::new_pair();
        let pending = crate::protocol::ResponseFuture {
            reply,
            stop: Some(stop),
        };
        let executing = Executing(Box::pin(async move {
            Ok(Response::new(pending.await?, authority))
        }));
        drop(executing);
        assert!(
            futures::future::Abortable::new(std::future::pending::<()>(), registration)
                .await
                .is_err()
        );
    }
}
