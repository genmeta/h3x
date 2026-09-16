//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.

use std::{
    future::{Future, IntoFuture},
    sync::Arc,
};

use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, ErrorCode, Result,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        headers::{self, Write as _},
        message::{ArcMessage, Message},
    },
    protocol::{
        frame::{self, Frame, H3Frame, Headers, Write as _, be_frame},
        qpack::Qpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

/// Outgoing request selected by body storage.
pub type Request<B = Bytes> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

/// Start a buffered request upload and return its response future.
/// The upload task continues independently if the response arrives early or this
/// future is dropped. Upload failures cancel the write direction.
pub fn write_bytes_request<RS, WS>(
    request: Request<Bytes>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack>,
) -> Result<impl IntoFuture<Output = Result<Response>, IntoFuture: Send> + Send>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    tokio::spawn(send_bytes_request(&request, ws, &qpack)?);
    Ok(read_response(rs, qpack, Some(method)))
}

/// Start a streaming request upload and return its response future.
/// Retain a producer (request clone or body handle) until finish/reset. The upload
/// task drains body data independently of response reception.
pub fn write_streaming_request<RS, WS>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack>,
) -> Result<impl IntoFuture<Output = Result<Response>, IntoFuture: Send> + Send>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();

    let sending = send_streaming_request(&request, ws, &qpack)?;
    tokio::spawn(sending);
    Ok(read_response(rs, qpack, Some(method)))
}

fn send_bytes_request<WS>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: &Qpack,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
{
    let (fields, body) = {
        let head = req.message.head.lock().unwrap();
        let body = req.message.body.lock().unwrap().storage.clone();
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        if headers::content_length(&head.headers)?.is_some_and(|length| length != body.len() as u64)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        (fields, body)
    };
    let headers = Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?;
    Ok(async move {
        let result = async {
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            body::write_bytes_body(&body, &mut ws).await?;
            ws.shutdown().await?;
            Ok::<_, ErrorCode>(())
        }
        .await;
        if let Err(error) = result {
            ws.cancel_with_error(error);
        }
        result
    })
}

fn send_streaming_request<WS>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: &Qpack,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
{
    let (head, mut body) = {
        let head = req.message.head.lock().unwrap().clone();
        let body = req.message.body_stream();
        (head, body)
    };
    // Validate before sending so malformed requests fail synchronously and wake producers.
    let (headers, mode) = (|| {
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        let mode = match headers::content_length(&head.headers)? {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        };
        let headers = Frame::new(Headers {
            field_section: qpack.encode(ws.stream_id(), fields)?,
        })?;
        Ok::<_, ErrorCode>((headers, mode))
    })()
    .inspect_err(|error| body.on_error(*error))?;
    Ok(async move {
        let result = async {
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            body::write_streaming_body(&mut body, &mut ws, mode).await?;
            ws.shutdown().await?;
            Ok::<_, ErrorCode>(())
        }
        .await;
        if let Err(error) = result {
            ws.cancel_with_error(error);
            body.on_error(error);
        }
        result
    })
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack>,
    method: Option<http::Method>,
) -> Result<crate::common::Response<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let result = async {
        let (head, length) = loop {
            let frame = match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
                    continue;
                }
                _ => return Err(ErrorCode::H3_FRAME_UNEXPECTED),
            };
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let head = headers::be_response(fields)?;
            let status = head.status()?;
            let length = headers::content_length(&head.headers)?;
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(ErrorCode::H3_MESSAGE_ERROR);
            }
            if (status.is_informational() || status == StatusCode::NO_CONTENT) && length.is_some() {
                return Err(ErrorCode::H3_MESSAGE_ERROR);
            }
            if !status.is_informational() {
                break (head, length);
            }
        };
        if method.as_ref() == Some(&http::Method::CONNECT)
            && head.status()?.is_success()
            && length.is_some()
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::resolve(&head, method.as_ref())?;
        Ok((head, mode))
    }
    .await;
    let (head, mode) = match result {
        Ok(value) => value,
        Err(error) => {
            let _ = qpack.cancel(stream_id);
            return Err(error);
        }
    };
    let body = body::receive(rs, mode, qpack);
    Ok(common::Response::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

#[cfg(test)]
mod tests;
