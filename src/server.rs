//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::{Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, ErrorCode, Result, Transport,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        headers::{self, Write as _},
        message::{ArcMessage, Message},
    },
    protocol::{
        connection::H3Connection,
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Read an HTTP request using the receive stream's ID and owning connection.
pub async fn read_request<RS: AsyncRead + Unpin + Send + 'static, T: Transport>(
    rs: H3ReadStream<RS>,
    connection: H3Connection<T>,
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
                _ => return Err(ErrorCode::H3_FRAME_UNEXPECTED),
            }
        };
        let fields = connection
            .qpack()
            .decode(stream_id, frame.payload.field_section)
            .await?;
        let head = headers::be_request(fields)?;
        let length = headers::content_length(&head.headers)?;
        Ok((head, length))
    }
    .await;
    let (head, length) = match read_head {
        Ok(value) => value,
        Err(error) => {
            let _ = connection.qpack().cancel(stream_id);
            connection.receive_error(error).await;
            return Err(error);
        }
    };
    let mode = match length {
        Some(content_length) => BodyMode::Length { content_length },
        None => BodyMode::Infinity,
    };
    let body = body::receive(rs, mode, connection.qpack().clone());
    Ok(common::Request::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

/// Send a buffered response. The method belongs to the original request.
pub async fn write_bytes_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
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
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        if status == StatusCode::NO_CONTENT && length.is_some() {
            return Err(ErrorCode::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::resolve(&head, Some(method))?;
        (fields, mode, body)
    };
    if mode.is_forbidden() && !body.is_empty() {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    if mode
        .content_length()
        .is_some_and(|length| length != body.len() as u64)
    {
        return Err(ErrorCode::H3_MESSAGE_ERROR);
    }
    let headers = Frame::new(Headers {
        field_section: connection.qpack().encode(ws.stream_id(), fields)?,
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
        Ok::<_, ErrorCode>(())
    }
    .await;
    if let Err(error) = result {
        ws.cancel_with_error(error);
    }
    result
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
pub fn write_streaming_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS, T> {
    let (head, mut body) = {
        let head = response.message.head.lock().unwrap().clone();
        let body = response.message.body_stream();
        (head, body)
    };
    let cancellation = body.clone();
    let request_method = request_method.clone();
    async move {
        let result = tokio::select! {
            biased;
            error = cancellation.error() => Err(error),
            result = async {
                let mut fields = Vec::new();
                fields.put_response(&head)?;
                let status = head.status()?;
                let length = headers::content_length(&head.headers)?;
                if status.is_informational() {
                    return Err(ErrorCode::H3_MESSAGE_ERROR);
                }
                if status == StatusCode::NO_CONTENT && length.is_some() {
                    return Err(ErrorCode::H3_MESSAGE_ERROR);
                }
                let mode = BodyMode::resolve(&head, Some(&request_method))?;
                let headers = Frame::new(Headers {
                    field_section: connection.qpack().encode(ws.stream_id(), fields)?,
                })?;
                let mut buf = Vec::new();
                buf.put_frame(&headers);
                ws.write_all(&buf).await?;
                body::write_streaming_body(&mut body, &mut ws, mode).await?;
                ws.shutdown().await?;
                Ok::<_, ErrorCode>(())
            } => result,
        };
        if let Err(error) = result {
            ws.cancel_with_error(error);
            body.set_error(error);
        }
        result
    }
}

#[cfg(test)]
mod tests;
