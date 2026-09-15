//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result, Transport,
    common::{
        self, Read, Write,
        body::{self, BodyMode},
        message::{ArcMessage, Message, ReadBody},
    },
    protocol::{
        connection::H3Connection,
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers,
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
    let result = async {
        let frame = loop {
            match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => break frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
            }
        };
        let fields = connection
            .qpack()
            .decode(stream_id, frame.payload.field_section)
            .await?;
        let parts = headers::request_parts(fields)?;
        let length = headers::content_length(&parts.headers)?;

        let mut message = Message::<Bytes>::default();
        for (name, value) in [
            (":method", Some(parts.method.as_str())),
            (
                ":authority",
                parts.uri.authority().map(|value| value.as_str()),
            ),
            (":scheme", parts.uri.scheme_str()),
            (
                ":path",
                parts.uri.path_and_query().map(|value| value.as_str()),
            ),
        ] {
            if let Some(value) = value {
                message.set_pseudo_header(name, HeaderValue::from_str(value).unwrap());
            }
        }
        for (name, value) in &parts.headers {
            message.append_header(name.clone(), value.clone());
        }
        Ok((message, length))
    }
    .await;
    let (message, length) = match result {
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
    Ok(match body::receive(rs, mode, connection).await? {
        common::Body::Bytes(body) => {
            common::Request::Bytes(ArcMessage::from(message.with_body(body)).into())
        }
        common::Body::Streaming(body) => {
            common::Request::Streaming(ArcMessage::from(message.with_body(body)).into())
        }
    })
}

/// Send a buffered response. The method belongs to the original request.
pub async fn write_bytes_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: Response<Bytes>,
    ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
    method: &Method,
) -> Result<()> {
    send_bytes_response(&response, ws, &connection, method).await
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
pub fn write_streaming_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: Response<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
    method: &Method,
) -> impl Future<Output = Result<()>> + use<WS, T> {
    prepare_streaming_response(&response, ws, connection, method)
}

/// Writes a buffered response using the original request method.
async fn send_bytes_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: &Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    connection: &H3Connection<T>,
    method: &Method,
) -> Result<()> {
    let (fields, mode, body) = {
        let message = response.message.0.lock().unwrap();
        let fields = message.fields();
        let parts = headers::response_parts(fields.clone())?;
        let length = headers::content_length(&parts.headers)?;
        if parts.status.is_informational() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if parts.status == StatusCode::NO_CONTENT && length.is_some() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::resolve(&parts, Some(method))?;
        (fields, mode, message.body())
    };
    if mode.is_forbidden() && !body.is_empty() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    if mode
        .content_length()
        .is_some_and(|length| length != body.len() as u64)
    {
        return Err(Error::H3_MESSAGE_ERROR);
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
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = result {
        ws.cancel_with_error(error);
    }
    result
}

/// Writes a streaming response using the original request method.
fn prepare_streaming_response<WS: AsyncWrite + Unpin, T: Transport>(
    response: &Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS, T> {
    let (fields, mut body) = {
        let message = response.message.0.lock().unwrap();
        (message.fields(), message.body_stream())
    };
    let cancellation = body.clone();
    let request_method = request_method.clone();
    async move {
        let result = tokio::select! {
            biased;
            error = cancellation.error() => Err(error),
            result = async {
                let parts = headers::response_parts(fields.clone())?;
                let length = headers::content_length(&parts.headers)?;
                if parts.status.is_informational() {
                    return Err(Error::H3_MESSAGE_ERROR);
                }
                if parts.status == StatusCode::NO_CONTENT && length.is_some() {
                    return Err(Error::H3_MESSAGE_ERROR);
                }
                let mode = BodyMode::resolve(&parts, Some(&request_method))?;
                let headers = Frame::new(Headers {
                    field_section: connection.qpack().encode(ws.stream_id(), fields)?,
                })?;
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
    }
}

#[cfg(test)]
mod tests;
