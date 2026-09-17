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
        message::Message,
    },
    protocol::{
        frame::{self, Frame, FrameType, H3Frame, Headers, Write as _},
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
    let mode = request_body_mode(&head).inspect_err(|error| {
        common::receive_error(&rs, &qpack, error);
    })?;
    let body = body::receive(rs, mode, qpack);
    Ok(common::Request::Streaming(
        Message::from_parts(head, body).into(),
    ))
}

fn request_body_mode(head: &headers::RequestHead) -> Result<BodyMode> {
    let length = headers::content_length(&head.headers)?;
    Ok(if head.method == Method::CONNECT {
        if length.is_some() {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("CONNECT must not include Content-Length")
            );
        }
        BodyMode::Connect
    } else {
        match length {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::UnspecifiedLength,
        }
    })
}

/// Skip unknown frames and require request HEADERS, distinguishing clean EOF.
async fn read_headers<R: AsyncRead + Unpin + ?Sized>(rs: &mut R) -> Result<Frame<Headers>> {
    loop {
        let Some(ty) = frame::be_frame_type(rs).await? else {
            return Err(ErrorCode::H3_REQUEST_INCOMPLETE
                .reason("request stream ended before request HEADERS"));
        };
        if !matches!(ty, FrameType::Headers | FrameType::Unknown(_)) {
            return Err(ErrorCode::H3_FRAME_UNEXPECTED
                .reason("expected request HEADERS before message body"));
        }
        let length = frame::be_frame_length(rs).await?;
        match frame::be_frame_payload(rs, ty, length).await? {
            H3Frame::Headers(frame) => return Ok(frame),
            H3Frame::Unknown { length, .. } => {
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
        let frame = read_headers(rs).await?;
        let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
        let head = headers::be_request(fields)?;
        request_body_mode(&head)?;
        Ok(head)
    }
    .await;
    if let Err(error) = &result {
        common::receive_error(rs, qpack, error);
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

/// Accept a CONNECT request returned by `read_request` after application checks.
/// The response must have a 2xx status without Content-Length. Retain
/// `response.body()` to send tunnel bytes after acceptance.
///
/// Metadata is validated on creation. When polled, the future sends and flushes
/// response HEADERS, starts the shared body sender, and returns without waiting
/// for the tunnel to end. Send failures cancel the write direction and wake the
/// producer. The caller retains the request and controls reception independently;
/// stop its body when abandoning the exchange. Dropping a pending acceptance
/// cancels the write direction; explicitly reset the retained producer as well.
/// Use the ordinary response writers to reject CONNECT with a non-2xx response.
pub fn accept_connect<WS>(
    request: &Request,
    response: Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
) -> impl Future<Output = Result<()>> + Send + use<WS>
where
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let mut producer = response.message.body_stream();
    let prepared = (|| {
        if crate::ReadRequest::method(request) != Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("accept_connect requires CONNECT"));
        }
        let response_head = response.message.head.lock().unwrap();
        let mut fields = Vec::new();
        fields.put_response(&response_head)?;
        if BodyMode::resolve(&response_head, Some(&Method::CONNECT))? != BodyMode::Connect {
            return Err(
                ErrorCode::H3_MESSAGE_ERROR.reason("accept_connect requires a 2xx response")
            );
        }
        Ok::<_, Error>(fields)
    })()
    .inspect_err(|error| {
        (&ws).cancel(error.code.as_u64());
        producer.on_error(error.clone());
    });
    async move {
        let fields = prepared?;
        let sending = async {
            let headers = Frame::new(Headers {
                field_section: qpack.encode(ws.stream_id(), fields)?,
            })?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            ws.write_all(&bytes).await?;
            ws.flush().await?;
            Ok::<_, Error>(())
        };
        let result = tokio::select! {
            biased;
            error = producer.wait_error() => Err(error),
            result = sending => result,
        };
        if let Err(error) = result {
            (&ws).cancel(error.code.as_u64());
            producer.on_error(error.clone());
            return Err(error);
        }
        tokio::spawn(async move {
            let cancellation = producer.clone();
            let result = tokio::select! {
                biased;
                error = cancellation.wait_error() => Err(error),
                result = async {
                    body::write_streaming_body(&mut producer, &mut ws, BodyMode::Connect).await?;
                    ws.shutdown().await?;
                    Ok::<_, Error>(())
                } => result,
            };
            if let Err(error) = result {
                (&ws).cancel(error.code.as_u64());
                producer.on_error(error);
            }
        });
        Ok(())
    }
}

/// Send a buffered response. The method belongs to the original request.
/// Snapshot metadata/body and validate locally on creation; send when polled.
/// Validation errors are returned by the future.
pub fn write_bytes_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    method: &Method,
) -> impl Future<Output = Result<()>> + use<WS> {
    let prepared = (|| {
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
        Ok::<_, Error>((fields, body))
    })();
    async move {
        let (fields, body) = prepared?;
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
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
/// Metadata is snapshotted and validated on creation. Validation errors wake the
/// producer immediately and are returned by the future.
pub fn write_streaming_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS> {
    let head = response.message.head.lock().unwrap().clone();
    let mut body = response.message.body_stream();
    let prepared = (|| {
        let mut fields = Vec::new();
        fields.put_response(&head)?;
        let mode = BodyMode::resolve(&head, Some(request_method))?;
        Ok::<_, Error>((fields, mode))
    })()
    .inspect_err(|error| body.on_error(error.clone()));
    async move {
        let cancellation = body.clone();
        let sending = async {
            let (fields, mode) = prepared?;
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
