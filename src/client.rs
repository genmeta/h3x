//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.

use std::{future::Future, sync::Arc};

use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result, Transport,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        message::{ArcMessage, Message, ReadBody, WriteResponse},
    },
    protocol::{
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers,
        qpack::Qpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

/// Outgoing request selected by body storage.
pub type Request<B = Bytes> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

/// Prepare independent upload and response futures. Neither runs until polled.
/// The response future carries the request method (including HEAD/CONNECT semantics).
/// Dropping either future releases its transport direction; uploads are never detached.
/// Body producers use reset explicitly to cancel or finish to signal EOF.
pub fn write_bytes_request<RS, WS, T: Transport>(
    request: Request<Bytes>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack<T>>,
) -> Result<(
    impl Future<Output = Result<()>> + Send,
    impl Future<Output = Result<Response>> + Send,
)>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    let sending = send_bytes_request(&request, ws, qpack.clone())?;
    Ok((sending, read_response(rs, qpack, Some(method))))
}

/// Prepare a streaming upload and independent response future.
/// Retain a producer (request clone or body handle) until finish/reset. Poll the
/// upload concurrently with production and response reception to avoid backpressure deadlocks.
pub fn write_streaming_request<RS, WS, T: Transport>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack<T>>,
) -> Result<(
    impl Future<Output = Result<()>> + Send,
    impl Future<Output = Result<Response>> + Send,
)>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    let sending = send_streaming_request(&request, ws, qpack.clone())?;
    Ok((sending, read_response(rs, qpack, Some(method))))
}

fn send_bytes_request<WS, T: Transport>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: Arc<Qpack<T>>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, T>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
{
    let (fields, body) = {
        let message = req.message.0.lock().unwrap();
        (message.fields(), message.body())
    };
    let parts = headers::request_parts(fields.clone())?;
    if headers::content_length(&parts.headers)?.is_some_and(|length| length != body.len() as u64) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let headers = Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?;
    Ok(async move {
        let result = async {
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            if !body.is_empty() {
                buf.clear();
                buf.put_frame(&Frame::new(Data(body.len()))?);
                ws.write_all(&buf).await?;
                ws.write_all(&body).await?;
            }
            ws.shutdown().await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = result {
            ws.cancel_with_error(error);
        }
        result
    })
}

fn send_streaming_request<WS, T: Transport>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: Arc<Qpack<T>>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, T>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
{
    let (fields, mut body) = {
        let message = req.message.0.lock().unwrap();
        (message.fields(), message.body_stream())
    };
    // Validate before sending so malformed requests fail synchronously and wake producers.
    let (headers, mode) = (|| {
        let parts = headers::request_parts(fields.clone())?;
        let mode = match headers::content_length(&parts.headers)? {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        };
        let headers = Frame::new(Headers {
            field_section: qpack.encode(ws.stream_id(), fields)?,
        })?;
        Ok::<_, Error>((headers, mode))
    })()
    .inspect_err(|error| body.set_error(*error))?;
    let cancellation = body.clone();
    Ok(async move {
        let result = tokio::select! {
            biased;
            error = cancellation.error() => Err(error),
            result = async {
                let mut buf = Vec::new();
                buf.put_frame(&headers);
                ws.write_all(&buf).await?;
                body::write_streaming_body(&mut body, &mut ws, mode).await?;
                ws.shutdown().await?;
                Ok::<_, Error>(())
            } => result,
        };
        if let Err(error) = result {
            ws.cancel_with_error(error);
            body.set_error(error);
        }
        result
    })
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + Unpin + Send + 'static, T: Transport>(
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack<T>>,
    method: Option<http::Method>,
) -> Result<crate::common::Response<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let (parts, mode) = async {
        let (parts, length) = loop {
            let frame = match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
                    continue;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
            };
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let parts = headers::response_parts(fields)?;
            let length = headers::content_length(&parts.headers)?;
            if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if (parts.status.is_informational() || parts.status == StatusCode::NO_CONTENT)
                && length.is_some()
            {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if !parts.status.is_informational() {
                break (parts, length);
            }
        };
        if method.as_ref() == Some(&http::Method::CONNECT)
            && parts.status.is_success()
            && length.is_some()
        {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::resolve(&parts, method.as_ref())?;
        Ok((parts, mode))
    }
    .await
    .inspect_err(|error| {
        let _ = qpack.cancel(stream_id);
        qpack.on_error(*error);
    })?;
    let mut message = Message::<Bytes>::default();
    message.set_status(parts.status);
    for (name, value) in &parts.headers {
        message.append_header(name.clone(), value.clone());
    }
    Ok(match body::receive(rs, mode, qpack).await? {
        common::Body::Bytes(body) => {
            common::Response::Bytes(ArcMessage::from(message.with_body(body)).into())
        }
        common::Body::Streaming(body) => {
            common::Response::Streaming(ArcMessage::from(message.with_body(body)).into())
        }
    })
}

#[cfg(test)]
mod tests;
