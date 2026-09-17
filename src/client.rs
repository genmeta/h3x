//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
use std::future::Future;

use bytes::Bytes;
use http::StatusCode;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    ArcWndBuf, Error, ErrorCode, Result,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        head::{self, WriteRequest as _},
        message::Message,
    },
    protocol::{
        frame::{self, Frame, FrameType, H3Frame, Headers, Write as _},
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
/// Metadata/body are snapshotted and validated before this function returns.
pub fn write_bytes_request<RS, WS>(
    request: Request<Bytes>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<impl Future<Output = Result<Response>> + Send>
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
/// reach the producer, not the response future. Use [`connect`] for CONNECT.
/// Metadata is snapshotted and validated before returning.
pub fn write_streaming_request<RS, WS>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<impl Future<Output = Result<Response>> + Send>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    // ws.write_request()
    // rs.read_response()
    tokio::spawn(send_streaming_request(&request, ws, &qpack)?);
    Ok(read_response(rs, qpack, Some(method)))
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
        if head.request_method() == http::Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("use client::connect for CONNECT"));
        }
        let mut fields = Vec::new();
        //TODO: encode_head
        fields.put_request(&head)?;
        if head
            .content_length()?
            .is_some_and(|length| length != body.len() as u64)
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

/// Send an ordinary streaming request; CONNECT requires the dedicated handshake.
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
        if head.request_method() == http::Method::CONNECT {
            return Err(ErrorCode::H3_MESSAGE_ERROR.reason("use client::connect for CONNECT"));
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        let mode = match head.content_length()? {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::UnspecifiedLength,
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
        let ty = frame::be_frame_type(rs).await?.ok_or_else(|| {
            ErrorCode::H3_FRAME_ERROR.reason("response stream ended before response HEADERS")
        })?;
        if !matches!(ty, FrameType::Headers | FrameType::Unknown(_)) {
            return Err(ErrorCode::H3_FRAME_UNEXPECTED
                .reason("expected response HEADERS before message body"));
        }
        let length = frame::be_frame_length(rs).await?;
        match frame::be_frame_payload(rs, ty, length).await? {
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
/// ReadResponseHead trait
/// ReadWriteHead
/// rs.read_head(qpack, method);
async fn read_final_response_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
    method: Option<&http::Method>,
) -> Result<(head::ResponseHead, BodyMode)> {
    let stream_id = rs.stream_id();
    let result = async {
        loop {
            let frame = be_headers_frame(rs).await?;
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let head = head::ResponseHead::decode(fields)?;
            let status = head.response_status()?;
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
            let length = head.content_length()?;
            let mode = BodyMode::from_parts(status, method, length);
            return Ok((head, mode));
        }
    }
    .await;
    if let Err(error) = &result {
        common::receive_error(rs, qpack, error);
    }
    result
}

// TODO: 放到 H3 error
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
/// Metadata is snapshotted and validated on creation; validation errors wake the
/// producer immediately and are returned by the future.
/// TODO: write_connect_request
///    内部函数传 response_type: Option<BodyMode>
/// 和 streaming_request 合并
///     内部函数判断 是否是 CONNECT
pub fn connect<RS, WS>(
    request: Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> impl Future<Output = std::result::Result<Response, ConnectError>> + Send
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    let producer = request.message.body_stream();
    let fields = (|| {
        let head = request.message.head.lock().unwrap().clone();
        if head.request_method() != http::Method::CONNECT
            || head.headers.contains_key(http::header::CONTENT_LENGTH)
        {
            return Err(ErrorCode::H3_MESSAGE_ERROR
                .reason("CONNECT requires the CONNECT method without Content-Length"));
        }
        let mut fields = Vec::new();
        fields.put_request(&head)?;
        Ok::<_, Error>(fields)
    })()
    .inspect_err(|error| producer.on_error(error.clone()));
    async move {
        let fields = fields?;
        let result = async {
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
                let receiving = read_final_response_head(&mut recv, &qpack, Some(&http::Method::CONNECT));
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
                error = cancellation.wait_error() => return Err(error),
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
                common::Response::Streaming(Message::from_parts(head, body).into());
            if !matches!(mode, BodyMode::Connect) {
                producer.on_error(ErrorCode::H3_REQUEST_CANCELLED.reason("CONNECT rejected"));
            }
            Ok(response)
        }
        .await;
        if let Err(error) = &result {
            producer.on_error(error.clone());
        }
        let response = result?;
        if crate::ReadResponse::status(&response).is_success() {
            Ok(response)
        } else {
            Err(ConnectError::Rejected(response))
        }
    }
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    mut rs: H3ReadStream<RS>,
    qpack: ArcQpack,
    method: Option<http::Method>,
) -> Result<Response> {
    let (head, mode) = read_final_response_head(&mut rs, &qpack, method.as_ref()).await?;
    let body = body::receive(rs, mode, qpack);
    Ok(common::Response::Streaming(
        Message::from_parts(head, body).into(),
    ))
}
