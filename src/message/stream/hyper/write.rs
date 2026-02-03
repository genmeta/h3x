use std::{error::Error, fmt::Display, pin::pin};

use bytes::Bytes;
use futures::TryFutureExt;
use http::HeaderName;
use http_body::Body;
use http_body_util::BodyExt;

use super::{StreamError, WriteStream};
use crate::qpack::field_section::{FieldLine, PseudoHeaders};

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

struct AsRefStrToAsStrBytes<T: ?Sized>(T);

impl<T: AsRef<str> + ?Sized> AsRef<[u8]> for AsRefStrToAsStrBytes<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_bytes()
    }
}

fn header_map_to_field_lines(headers: http::HeaderMap) -> impl Iterator<Item = FieldLine> {
    headers
        .into_iter()
        .scan(None::<HeaderName>, |last_name, (name, value)| {
            let name = match name {
                Some(name) => {
                    *last_name = Some(name.clone());
                    name
                }
                None => match last_name.clone() {
                    Some(name) => name,
                    None => return Some(None),
                },
            };

            Some(Some(FieldLine {
                name: Bytes::from_owner(name),
                value: Bytes::from_owner(value),
            }))
        })
        .flatten()
}

fn hyper_request_parts_to_field_lines(
    parts: http::request::Parts,
) -> impl Iterator<Item = FieldLine> {
    let uri_parts = parts.uri.into_parts();
    let pseudo_headers = [
        Some(FieldLine {
            name: Bytes::from_static(PseudoHeaders::METHOD.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(parts.method)),
        }),
        uri_parts.scheme.map(|scheme| FieldLine {
            name: Bytes::from_static(PseudoHeaders::SCHEME.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(scheme)),
        }),
        uri_parts.authority.map(|authority| FieldLine {
            name: Bytes::from_static(PseudoHeaders::AUTHORITY.as_bytes()),
            value: Bytes::from_owner(AsRefStrToAsStrBytes(authority)),
        }),
        uri_parts.path_and_query.map(|path| FieldLine {
            name: Bytes::from_static(PseudoHeaders::PATH.as_bytes()),
            value: Bytes::copy_from_slice(path.as_str().as_bytes()),
        }),
    ];

    pseudo_headers
        .into_iter()
        .flatten()
        .chain(header_map_to_field_lines(parts.headers))
}

fn hyper_response_parts_to_field_lines(
    parts: http::response::Parts,
) -> impl Iterator<Item = FieldLine> {
    let pseudo_headers = [Some(FieldLine {
        name: Bytes::from_static(PseudoHeaders::STATUS.as_bytes()),
        value: Bytes::copy_from_slice(parts.status.as_str().as_bytes()),
    })];

    pseudo_headers
        .into_iter()
        .flatten()
        .chain(header_map_to_field_lines(parts.headers))
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
