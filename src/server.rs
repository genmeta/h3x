//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::Method;
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
        frame::{self, Frame, H3Frame, Headers, Write as _},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Read an HTTP request using the receive stream's ID and shared QPACK state.
pub async fn read_request<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    mut rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<Request> {
    let head = read_request_head(&mut rs, &qpack).await?;
    read_request_body(head, rs, qpack)
}

/// Start body reception after read_request_head has consumed HEADERS.
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
    let length = headers::content_length(&head.headers)?;
    let mode = if head.method == Method::CONNECT {
        if length.is_some() {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT must not include Content-Length")
            );
        }
        BodyMode::Connect
    } else {
        match length {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        }
    };
    let body = body::receive(rs, mode, qpack);
    Ok(common::Request::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

/// Skip unknown frames and require request HEADERS, distinguishing clean EOF.
async fn be_headers_frame<R: AsyncRead + Unpin + ?Sized>(rs: &mut R) -> Result<Frame<Headers>> {
    loop {
        match frame::be_frame_or_eof(rs).await? {
            None => {
                return Err(ErrorCode::H3_REQUEST_INCOMPLETE
                    .reason("request stream ended before request HEADERS"));
            }
            Some(H3Frame::Headers(frame)) => return Ok(frame),
            Some(H3Frame::Unknown { length, .. }) => {
                frame::skip_payload(rs, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED
                    .reason("expected request HEADERS before message body"));
            }
        }
    }
}

async fn read_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<headers::RequestHead> {
    let stream_id = rs.stream_id();
    let result: Result<_> = async {
        let frame = be_headers_frame(rs).await?;
        let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
        let head = headers::be_request(fields)?;
        headers::content_length(&head.headers)?;
        Ok(head)
    }
    .await;
    if let Err(error) = &result {
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
    }
    result
}

/// Read only initial HEADERS, leaving the receive direction with the caller.
/// No body task is started and no bytes beyond the field section are prefetched.
/// After success pass the same stream to read_request_body.
/// If this future is cancelled, discard the stream: a partial header may be consumed.
pub async fn read_request_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<http::Request<()>> {
    let head = read_head(rs, qpack).await?;
    let mut request = http::Request::new(());
    *request.method_mut() = head.method;
    *request.uri_mut() = head.uri;
    *request.headers_mut() = head.headers;
    *request.extensions_mut() = head.extensions;
    *request.version_mut() = http::Version::HTTP_3;
    Ok(request)
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
        let mode = BodyMode::resolve(&head, Some(method))?;
        if matches!(mode, BodyMode::Connect) {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("use write_streaming_response for successful CONNECT"));
        }
        (fields, mode, body)
    };
    if mode.is_forbidden() && !body.is_empty() {
        return Err(ErrorCode::H3_MESSAGE_ERROR.reason("response semantics forbid a body"));
    }
    if mode
        .content_length()
        .is_some_and(|length| length != body.len() as u64)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR
            .reason("response body length does not match Content-Length"));
    }
    let headers = Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?;
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
    let head = response.message.head.lock().unwrap().clone();
    let mut body = response.message.body_stream();
    let request_method = request_method.clone();
    async move {
        let cancellation = body.clone();
        let sending = async {
            let mut fields = Vec::new();
            fields.put_response(&head)?;
            let mode = BodyMode::resolve(&head, Some(&request_method))?;
            let headers = Frame::new(Headers {
                field_section: qpack.encode(ws.stream_id(), fields)?,
            })?;
            let mut buf = Vec::new();
            buf.put_frame(&headers);
            ws.write_all(&buf).await?;
            ws.flush().await?;
            body::write_streaming_body(&mut body, &mut ws, mode).await?;
            ws.shutdown().await?;
            Ok::<_, Error>(())
        };
        let result = tokio::select! {
            biased;
            error = cancellation.wait_error() => Err(error),
            result = sending => result,
        };
        if let Err(error) = &result {
            (&ws).cancel(error.code.as_u64());
            body.on_error(error.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests;
