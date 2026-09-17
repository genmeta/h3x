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
/// future is dropped. Upload failures cancel the write direction, but do not
/// fail response reception. Callers control the response timeout.
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
    tokio::spawn(send_bytes_request(&request, ws, &qpack)?);
    Ok(read_response(rs, qpack, Some(method)))
}

/// Start a streaming request upload and return its response future.
/// Retain a producer (request clone or body handle) until finish/reset. The upload
/// task drains body data independently of response reception. Upload failures
/// reach the producer, not the response future. CONNECT is driven
/// by the returned future until acceptance, then starts the same body pumps.
/// Dropping a pending CONNECT handshake cancels both stream directions.
/// Reset the retained body explicitly when abandoning the handshake.
pub fn write_streaming_request<RS, WS>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<std::pin::Pin<Box<dyn Future<Output = Result<Response>> + Send>>>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    if method == http::Method::CONNECT {
        return Ok(Box::pin(async move {
            // HTTP rejection is still a response for the ordinary request API.
            match connect(request, ws, rs, qpack).await {
                Ok(response) | Err(ConnectError::Rejected(response)) => Ok(response),
                Err(ConnectError::H3(error)) => Err(error),
            }
        }));
    }

    tokio::spawn(send_streaming_request(&request, ws, &qpack)?);
    Ok(Box::pin(read_response(rs, qpack, Some(method))))
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
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("use client::connect for CONNECT"));
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        if headers::content_length(&head.headers)?.is_some_and(|length| length != body.len() as u64)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("request body length does not match Content-Length"));
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
            (&ws).cancel(error.code.as_u64());
        }
        result
    })
}

/// Send an ordinary streaming request; CONNECT is routed by the public entry point.
fn send_streaming_request<WS>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: &ArcQpack,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS>>
where
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let head = req.message.head.lock().unwrap().clone();
    let mut body = req.message.body_stream();
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
        Ok::<_, Error>((headers, mode))
    })()
    .inspect_err(|error| body.on_error(error.clone()))?;
    Ok(async move {
        let cancellation = body.clone();
        let sending = async {
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
    })
}

/// Skip unknown extension frames and require the next known frame to be HEADERS.
async fn be_headers_frame<R: AsyncRead + Unpin + ?Sized>(rs: &mut R) -> Result<Frame<Headers>> {
    loop {
        match be_frame(rs).await? {
            H3Frame::Headers(frame) => return Ok(frame),
            H3Frame::Unknown { length, .. } => {
                frame::skip_payload(rs, length.into_u64()).await?;
            }
            _ => {
                return Err(ErrorCode::H3_FRAME_UNEXPECTED
                    .reason("expected response HEADERS before message body"));
            }
        }
    }
}

/// Read and validate final response HEADERS and resolve body framing once.
async fn read_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
    method: Option<&http::Method>,
) -> Result<(headers::ResponseHead, BodyMode)> {
    let stream_id = rs.stream_id();
    let result = async {
        loop {
            let frame = be_headers_frame(rs).await?;
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let head = headers::be_response(fields)?;
            let status = head.status()?;
            if status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(ErrorCode::H3_MESSAGE_ERROR.reason("status 101 is forbidden in HTTP/3"));
            }
            if method == Some(&http::Method::CONNECT) && status.is_success() {
                return Ok((head, BodyMode::Connect));
            }
            if (status.is_informational() || status == StatusCode::NO_CONTENT)
                && head.headers.contains_key(http::header::CONTENT_LENGTH)
            {
                return Err(ErrorCode::H3_MESSAGE_ERROR
                    .reason("informational and 204 responses must not include Content-Length"));
            }
            if status.is_informational() {
                continue;
            }
            let length = headers::content_length(&head.headers)?;
            let mode = BodyMode::from_parts(status, method, length);
            return Ok((head, mode));
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

#[derive(thiserror::Error)]
pub enum ConnectError {
    /// The peer rejected CONNECT; status, headers, and body remain available.
    #[error("CONNECT rejected with status {}", crate::ReadResponse::status(.0))]
    Rejected(Response),
    #[error(transparent)]
    H3(#[from] crate::Error),
}

impl std::fmt::Debug for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(response) => f
                .debug_tuple("Rejected")
                .field(&crate::ReadResponse::status(response))
                .finish(),
            Self::H3(error) => f.debug_tuple("H3").field(error).finish(),
        }
    }
}

/// Perform a CONNECT handshake on an open bidirectional stream. No application
/// bytes are sent before successful response HEADERS. Retain `request.body()`
/// to write after acceptance. Cancelling the handshake drops both stream halves;
/// reset the retained body explicitly when abandoning it.
/// Extended CONNECT assumes peer support without checking peer SETTINGS.
/// HTTP rejection returns [`ConnectError::Rejected`] with the complete response.
/// Header send failures do not end response reception; callers control its timeout.
pub async fn connect<RS, WS>(
    request: Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> std::result::Result<Response, ConnectError>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let producer = request.message.body_stream();
    let result = async move {
        let head = request.message.head.lock().unwrap().clone();
        if head.method != http::Method::CONNECT
            || head.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("CONNECT requires the CONNECT method without Content-Length")
                .into());
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        let mut bytes = Vec::new();
        bytes.put_frame(&Frame::new(Headers {
            field_section: qpack.encode(ws.stream_id(), fields)?,
        })?);
        let mut recv = rs;
        let handshake = async {
            let sending = async {
                ws.write_all(&bytes).await?;
                ws.flush().await
            };
            let receiving = read_head(&mut recv, &qpack, Some(&http::Method::CONNECT));
            tokio::pin!(receiving);
            tokio::select! {
                head = &mut receiving => head,
                // Sending and receiving fail independently.
                _ = sending => receiving.await,
            }
        };
        let cancellation = request.message.body_stream();
        let (head, mode) = tokio::select! {
            biased;
            error = cancellation.wait_error() => return Err(error.into()),
            head = handshake => head?,
        };
        if matches!(mode, BodyMode::Connect) {
            let mut body = request.message.body_stream();
            tokio::spawn(async move {
                let cancellation = body.clone();
                let result = tokio::select! {
                    biased;
                    error = cancellation.wait_error() => Err(error),
                    result = async {
                        body::write_streaming_body(&mut body, &mut ws, BodyMode::Connect).await?;
                        ws.shutdown().await?;
                        Ok::<_, Error>(())
                    } => result,
                };
                if let Err(error) = result {
                    (&ws).cancel(error.code.as_u64());
                    body.on_error(error);
                }
            });
        }
        let body = body::receive(recv, mode, qpack);
        let response =
            common::Response::Streaming(ArcMessage::from(Message::from_parts(head, body)).into());
        if matches!(mode, BodyMode::Connect) {
            Ok(response)
        } else {
            Err(ConnectError::Rejected(response))
        }
    }
    .await;
    if let Err(error) = &result {
        producer.on_error(match error {
            ConnectError::H3(error) => error.clone(),
            ConnectError::Rejected(_) => ErrorCode::H3_REQUEST_CANCELLED.reason("CONNECT rejected"),
        });
    }
    result
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    mut rs: H3ReadStream<RS>,
    qpack: ArcQpack,
    method: Option<http::Method>,
) -> Result<Response> {
    let (head, mode) = read_head(&mut rs, &qpack, method.as_ref()).await?;
    let body = body::receive(rs, mode, qpack);
    Ok(common::Response::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

#[cfg(test)]
mod tests;
