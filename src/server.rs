//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcQpack, ArcWndBuf, Error, ErrorCode, Result,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        headers::{self, Write as _},
        message::{ArcMessage, Message},
    },
    protocol::{
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Read an HTTP request using the receive stream's ID and shared QPACK state.
pub async fn read_request<RS: AsyncRead + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<crate::common::Request<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let read_head = async {
        let frame = loop {
            match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => break frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
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
    let mode = match length {
        Some(content_length) => BodyMode::Length { content_length },
        None => BodyMode::Infinity,
    };
    let body = body::receive(rs, mode, qpack);
    Ok(common::Request::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

/// Send a buffered response. The method belongs to the original request.
pub async fn write_bytes_response<WS: AsyncWrite + Unpin>(
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
        ws.cancel_with_error(error.clone());
    }
    result
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
pub fn write_streaming_response<WS: AsyncWrite + Unpin>(
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
            ws.cancel_with_error(error.clone());
            body.on_error(error.clone());
        }
        result
    }
}

#[cfg(test)]
mod tests;
