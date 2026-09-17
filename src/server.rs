//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::{Method, StatusCode};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    ArcQpack, ArcWndBuf, Error, ErrorCode, Result,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        headers::{self, Write as _},
        message::{ArcMessage, Message},
    },
    protocol::{
        frame::{self, Data, Frame, H3Frame, Headers, Write as _},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Read an HTTP request using the receive stream's ID and shared QPACK state.
pub async fn read_request<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    mut rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<crate::common::Request<Read>> {
    let head = read_request_head(&mut rs, &qpack).await?;
    read_request_body(head, rs, qpack)
}

/// Start ordinary body reception after read_request_head has consumed HEADERS.
/// `rs` and `qpack` must belong to the request whose metadata is supplied here.
pub fn read_request_body<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    request: http::Request<()>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<Request> {
    let (parts, ()) = request.into_parts();
    let head = headers::RequestHead {
        method: parts.method,
        uri: parts.uri,
        headers: parts.headers,
        extensions: parts.extensions,
    };
    if head.method == Method::CONNECT {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("use accept_connect for CONNECT"));
    }
    let mode = match headers::content_length(&head.headers)? {
        Some(content_length) => BodyMode::Length { content_length },
        None => BodyMode::Infinity,
    };
    let body = body::receive(rs, mode, qpack);
    Ok(common::Request::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

async fn read_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<(headers::RequestHead, Option<u64>)> {
    let stream_id = rs.stream_id();
    let read_head = async {
        let frame = loop {
            match frame::be_frame_or_eof(rs).await? {
                None => {
                    return Err(ErrorCode::H3_REQUEST_INCOMPLETE
                        .with_reason("request stream ended before request HEADERS"));
                }
                Some(H3Frame::Headers(frame)) => break frame,
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(rs, length.into_u64()).await?;
                }
                _ => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .with_reason("expected request HEADERS before message body"));
                }
            }
        };
        let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
        let head = headers::be_request(fields)?;
        let length = headers::content_length(&head.headers)?;
        Ok((head, length))
    }
    .await;
    let (head, length) = match read_head {
        Ok(value) => value,
        Err(error) => {
            rs.close(error.clone());
            if !matches!(
                error.code,
                ErrorCode::H3_REQUEST_CANCELLED
                    | ErrorCode::H3_REQUEST_REJECTED
                    | ErrorCode::H3_REQUEST_INCOMPLETE
                    | ErrorCode::H3_MESSAGE_ERROR
            ) {
                qpack.on_error(error.clone());
            }
            let _ = qpack.cancel(stream_id);
            return Err(error);
        }
    };
    Ok((head, length))
}

/// Read only initial HEADERS, leaving the receive direction with the caller.
/// No body task is started and no bytes beyond the field section are prefetched.
/// After success pass the same stream to read_request_body or accept_connect.
/// If this future is cancelled, discard the stream: a partial header may be consumed.
pub async fn read_request_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<http::Request<()>> {
    let (head, _) = read_head(rs, qpack).await?;
    let mut request = http::Request::new(());
    *request.method_mut() = head.method;
    *request.uri_mut() = head.uri;
    *request.headers_mut() = head.headers;
    *request.extensions_mut() = head.extensions;
    *request.version_mut() = http::Version::HTTP_3;
    Ok(request)
}

/// Accept CONNECT after application routing/authentication or upstream handshake.
/// Writes successful HEADERS without FIN and preserves any prefetched DATA.
///
/// The caller must supply both directions of the same request stream and its
/// connection's QPACK state. The method belongs to the original request.
pub async fn accept_connect<RS, WS>(
    response: http::Response<()>,
    mut ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
    method: &Method,
) -> Result<crate::Tunnel<RS, WS>>
where
    RS: AsyncRead + StopSending + Unpin,
    WS: AsyncWrite + CancelStream + Unpin,
{
    if method != Method::CONNECT {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("accept_connect requires CONNECT"));
    }
    if !response.status().is_success()
        || response
            .headers()
            .contains_key(http::header::CONTENT_LENGTH)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("CONNECT acceptance requires 2xx without body framing"));
    }
    let (parts, ()) = response.into_parts();
    let head = headers::ResponseHead {
        status: Some(parts.status),
        headers: parts.headers,
    };
    let mut fields = Vec::new();
    fields.put_response(&head)?;
    let mut bytes = Vec::new();
    bytes.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    ws.write_all(&bytes).await?;
    ws.flush().await?;
    Ok(crate::Tunnel::new(rs, ws, qpack))
}

/// Send a buffered response. The method belongs to the original request.
pub async fn write_bytes_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    method: &Method,
) -> Result<()> {
    let (fields, mode, body) = {
        let head = response.message.head.lock().unwrap();
        let body = response.message.body.lock().unwrap().storage.clone();
        let mut fields = Vec::new();
        fields.put_response(&head)?;
        let status = head.status()?;
        if method == Method::CONNECT && status.is_success() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("use accept_connect for successful CONNECT"));
        }
        let length = headers::content_length(&head.headers)?;
        if status.is_informational() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("a final response cannot use an informational status"));
        }
        if status == StatusCode::NO_CONTENT && length.is_some() {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .with_reason("204 response must not include Content-Length"));
        }
        let mode = BodyMode::resolve(&head, Some(method))?;
        (fields, mode, body)
    };
    if mode.is_forbidden() && !body.is_empty() {
        return Err(ErrorCode::H3_MESSAGE_ERROR.with_reason("response semantics forbid a body"));
    }
    if mode
        .content_length()
        .is_some_and(|length| length != body.len() as u64)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .with_reason("response body length does not match Content-Length"));
    }
    let headers = Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?;
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
    if let Err(error) = &result {
        (&ws).cancel(error.code.as_u64());
    }
    result
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
pub fn write_streaming_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS> {
    let (head, mut body) = {
        let head = response.message.head.lock().unwrap().clone();
        let body = response.message.body_stream();
        (head, body)
    };
    let request_method = request_method.clone();
    async move {
        let result = async {
            let mut fields = Vec::new();
            fields.put_response(&head)?;
            let status = head.status()?;
            if request_method == Method::CONNECT && status.is_success() {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .with_reason("use accept_connect for successful CONNECT"));
            }
            let length = headers::content_length(&head.headers)?;
            if status.is_informational() {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .with_reason("a final response cannot use an informational status"));
            }
            if status == StatusCode::NO_CONTENT && length.is_some() {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .with_reason("204 response must not include Content-Length"));
            }
            let mode = BodyMode::resolve(&head, Some(&request_method))?;
            let headers = Frame::new(Headers {
                field_section: qpack.encode(ws.stream_id(), fields)?,
            })?;
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            body::write_streaming_body(&mut body, &mut ws, mode).await?;
            ws.shutdown().await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = &result {
            (&ws).cancel(error.code.as_u64());
            body.on_error(error.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests;
