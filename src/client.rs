//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
use std::future::{Future, IntoFuture};

use bytes::Bytes;
use http::StatusCode;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    ArcWndBuf, Error, ErrorCode, Result,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        headers::{self, Write as _},
        message::{ArcMessage, Message},
    },
    protocol::{
        frame::{self, Frame, H3Frame, Headers, Write as _, be_frame},
        qpack::ArcQpack,
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
    qpack: ArcQpack,
) -> Result<impl IntoFuture<Output = Result<Response>, IntoFuture: Send> + Send>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    let sending = tokio::spawn(send_bytes_request(&request, ws, &qpack)?);
    Ok(async move {
        let mut response = std::pin::pin!(read_response(rs, qpack, Some(method)));
        tokio::select! {
            biased;
            result = &mut response => result,
            sent = sending => {
                sent.map_err(|source| ErrorCode::H3_INTERNAL_ERROR
                    .with_reason(format!("request upload task failed: {source}")))??;
                response.await
            }
        }
    })
}

/// Start a streaming request upload and return its response future.
/// Retain a producer (request clone or body handle) until finish/reset. The upload
/// task drains body data independently of response reception.
pub fn write_streaming_request<RS, WS>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<impl IntoFuture<Output = Result<Response>, IntoFuture: Send> + Send>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();

    let sending = tokio::spawn(send_streaming_request(&request, ws, &qpack)?);
    Ok(async move {
        let mut response = std::pin::pin!(read_response(rs, qpack, Some(method)));
        // An early response leaves the spawned upload running independently.
        tokio::select! {
            biased;
            result = &mut response => result,
            sent = sending => {
                sent.map_err(|source| ErrorCode::H3_INTERNAL_ERROR
                    .with_reason(format!("request upload task failed: {source}")))??;
                response.await
            }
        }
    })
}

fn send_bytes_request<WS>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: &ArcQpack,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS>>
where
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let (fields, body) = {
        let head = req.message.head.lock().unwrap();
        let body = req.message.body.lock().unwrap().storage.clone();
        if head.method == http::Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("use client::connect for CONNECT"));
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        if headers::content_length(&head.headers)?.is_some_and(|length| length != body.len() as u64)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("request body length does not match Content-Length"));
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
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = &result {
            ws.cancel_with_error(error.clone());
        }
        result
    })
}

fn send_streaming_request<WS>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: &ArcQpack,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS>>
where
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let (head, mut body) = {
        let head = req.message.head.lock().unwrap().clone();
        let body = req.message.body_stream();
        (head, body)
    };
    // Validate before sending so malformed requests fail synchronously and wake producers.
    let (headers, mode) = (|| {
        if head.method == http::Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("use client::connect for CONNECT"));
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        let mode = match headers::content_length(&head.headers)? {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        };
        let headers = Frame::new(Headers {
            field_section: qpack.encode(ws.stream_id(), fields)?,
        })?;
        Ok::<_, Error>((headers, mode))
    })()
    .inspect_err(|error| body.on_error(error.clone()))?;
    Ok(async move {
        let result = async {
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            body::write_streaming_body(&mut body, &mut ws, mode).await?;
            ws.shutdown().await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = &result {
            ws.cancel_with_error(error.clone());
            body.on_error(error.clone());
        }
        result
    })
}

async fn read_final_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
    connect: bool,
) -> Result<headers::ResponseHead> {
    let stream_id = rs.stream_id();
    let result = async {
        loop {
            let frame = match be_frame(rs).await? {
                H3Frame::Headers(frame) => frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(rs, length.into_u64()).await?;
                    continue;
                }
                _ => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .with_reason("expected response HEADERS before message body"));
                }
            };
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let head = headers::be_response(fields)?;
            let status = head.status()?;
            if connect && status.is_success() {
                return Ok(head);
            }
            let length = headers::content_length(&head.headers)?;
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(
                    ErrorCode::H3_MESSAGE_ERROR.with_reason("status 101 is forbidden in HTTP/3")
                );
            }
            if (status.is_informational() || status == StatusCode::NO_CONTENT) && length.is_some() {
                return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason(
                    "informational and 204 responses must not include Content-Length",
                ));
            }
            if !status.is_informational() {
                return Ok(head);
            }
        }
    }
    .await;
    if let Err(error) = &result {
        rs.close(error.clone());
        if matches!(
            error.code,
            ErrorCode::H3_FRAME_ERROR | ErrorCode::H3_FRAME_UNEXPECTED
        ) {
            qpack.on_error(error.clone());
        }
        let _ = qpack.cancel(stream_id);
    }
    result
}

/// HTTP rejection is a response, not a transport failure.
pub enum ConnectOutcome<S> {
    Connected {
        response: http::Response<()>,
        tunnel: S,
    },
    Rejected(Response),
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("peer does not support Extended CONNECT")]
    NotSupported,
    #[error(transparent)]
    H3(#[from] crate::Error),
}

/// Perform a CONNECT handshake on an existing connection. No application bytes
/// are sent before successful response HEADERS. Cancellation drops both halves.
pub async fn connect<T: crate::Transport>(
    request: Request<Bytes>,
    connection: &crate::H3Connection<T>,
) -> std::result::Result<
    ConnectOutcome<crate::Tunnel<T::StreamReader, T::StreamWriter>>,
    ConnectError,
> {
    let head = request.message.head.lock().unwrap().clone();
    if head.method != http::Method::CONNECT
        || !request.message.body.lock().unwrap().storage.is_empty()
        || head.headers.contains_key(http::header::CONTENT_LENGTH)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("CONNECT requires an empty handshake without body framing")
            .into());
    }
    let mut fields = Vec::new();
    fields.put_request(&head)?;
    if head.extensions.get::<crate::ext::Protocol>().is_some() {
        let settings = tokio::select! {
            settings = connection.peer_settings.received() => settings,
            error = connection.transport.terminated() => return Err(error.into()),
        };
        if settings.get(frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0) != 1 {
            return Err(ConnectError::NotSupported);
        }
    }
    let (mut ws, rs) = connection.open_bi().await?;
    let qpack = connection.qpack().clone();
    let mut bytes = Vec::new();
    bytes.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    ws.write_all(&bytes).await.map_err(Error::from)?;
    ws.flush().await.map_err(Error::from)?;
    let mut recv = rs;
    let head = read_final_head(&mut recv, &qpack, true).await?;
    if head.status()?.is_success() {
        let mut response = http::Response::new(());
        *response.status_mut() = head.status()?;
        *response.headers_mut() = head.headers;
        Ok(ConnectOutcome::Connected {
            response,
            tunnel: crate::Tunnel::new(recv, ws, qpack),
        })
    } else {
        let mode = BodyMode::resolve(&head, Some(&http::Method::CONNECT))?;
        let body = body::receive(recv, mode, qpack);
        Ok(ConnectOutcome::Rejected(common::Response::Streaming(
            ArcMessage::from(Message::from_parts(head, body)).into(),
        )))
    }
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    mut rs: H3ReadStream<RS>,
    qpack: ArcQpack,
    method: Option<http::Method>,
) -> Result<crate::common::Response<Read>> {
    let stream_id = rs.stream_id();
    let result = async {
        let head = read_final_head(&mut rs, &qpack, false).await?;
        let length = headers::content_length(&head.headers)?;
        if method.as_ref() == Some(&http::Method::CONNECT)
            && head.status()?.is_success()
            && length.is_some()
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("successful CONNECT response must not include Content-Length"));
        }
        let mode = BodyMode::resolve(&head, method.as_ref())?;
        Ok((head, mode))
    }
    .await;
    let (head, mode) = match result {
        Ok(value) => value,
        Err(error) => {
            rs.close(error.clone());
            if matches!(
                error.code,
                ErrorCode::H3_FRAME_ERROR | ErrorCode::H3_FRAME_UNEXPECTED
            ) {
                qpack.on_error(error.clone());
            }
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
