//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.

use std::future::Future;

use bytes::Bytes;
use http::StatusCode;
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

/// Outgoing request selected by body storage.
pub type Request<B = Bytes> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

/// Prepare independent upload and response futures. Neither runs until polled.
/// The response future carries the request method (including HEAD/CONNECT semantics).
/// Dropping either future releases its transport direction; uploads are never detached.
/// Body producers use reset explicitly to cancel or finish to signal EOF.
pub fn write_bytes_request<RS, WS, T: Transport>(
    request: Request<Bytes>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    // qpack
    connection: H3Connection<T>,
) -> Result<(
    // IntoFuture, 只返回一个
    // content-length 写完再返回
    impl Future<Output = Result<()>> + Send,
    impl Future<Output = Result<Response>> + Send,
)>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    Ok((
        send_bytes_request(&request, ws, connection.clone())?,
        read_response(rs, connection, Some(method)),
    ))
}

/// Prepare a streaming upload and independent response future.
/// Retain a producer (request clone or body handle) until finish/reset. Poll the
/// upload concurrently with production and response reception to avoid backpressure deadlocks.
pub fn write_streaming_request<RS, WS, T: Transport>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    connection: H3Connection<T>,
) -> Result<(
    impl Future<Output = Result<()>> + Send,
    impl Future<Output = Result<Response>> + Send,
)>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();

    Ok((
        send_streaming_request(&request, ws, connection.clone())?,
        read_response(rs, connection, Some(method)),
    ))
}

fn send_bytes_request<WS, T: Transport>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, T>>
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
        field_section: connection.qpack().encode(ws.stream_id(), fields)?,
    })?;
    Ok(async move {
        let result = async {
            // 用 while 循环写 栈上 buffer
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
    })
}

fn send_streaming_request<WS, T: Transport>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    connection: H3Connection<T>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, T>>
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
            field_section: connection.qpack().encode(ws.stream_id(), fields)?,
        })?;
        Ok::<_, ErrorCode>((headers, mode))
    })()
    .inspect_err(|error| body.set_error(*error))?;
    // 通过读写通知 error，不需要
    let cancellation = body.clone();
    Ok(async move {
        let result = tokio::select! {
            biased;
            error = cancellation.error() => Err(error),
            result = async {
                // 循环写
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
    })
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + Unpin + Send + 'static, T: Transport>(
    rs: H3ReadStream<RS>,
    connection: H3Connection<T>,
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
            let fields = connection
                .qpack()
                .decode(stream_id, frame.payload.field_section)
                .await?;
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
            let _ = connection.qpack().cancel(stream_id);
            connection.receive_error(error).await;
            return Err(error);
        }
    };
    let body = body::receive(rs, mode, connection);
    Ok(common::Response::Streaming(
        ArcMessage::from(Message::from_parts(head, body)).into(),
    ))
}

#[cfg(test)]
mod tests;
