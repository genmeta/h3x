//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.

use std::{future::Future, pin::Pin, sync::Arc};

use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result, Transport,
    common::{
        self, Read, Write,
        message::{ArcMessage, Message, ReadBody, WriteResponse},
    },
    protocol::{
        body::{self, BodyMode},
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers,
        qpack::Qpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

/// Outgoing request selected by body storage.
pub type Request<B = Bytes> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

/// Start one request and return its response independently of upload completion.
/// Streaming body writes may continue after this returns. Drive initial writes
/// concurrently with this future when the peer waits for body data before responding.
/// Sending errors never discard a valid response; streaming writers observe them
/// through their shared body. After a valid response, remaining uploads run in the background.
/// Applications finish or reset streaming bodies explicitly.
pub fn request<RS, WS, R, RW, SR, T: Transport>(
    request: R,
    recv: H3ReadStream<RS, RW>,
    send: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack<T>>,
) -> impl Future<Output = Result<Response>> + Send
where
    RS: AsyncRead + Unpin + Send + 'static,
    RW: Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
    SR: Send + 'static,
    R: Into<common::Request<Write>>,
{
    use crate::ReadRequest;
    let request = request.into();

    async move {
        let method = request.method();
        let encoder = qpack.clone();
        let receiving = read_response(recv, qpack, Some(method));
        let mut sending: Pin<Box<dyn Future<Output = Result<()>> + Send>> = match request {
            common::Request::Bytes(request) => {
                Box::pin(write_bytes_request(&request, send, encoder)?)
            }
            common::Request::Streaming(request) => {
                Box::pin(write_streaming_request(&request, send, encoder)?)
            }
        };
        tokio::pin!(receiving);
        let response = tokio::select! {
            response = &mut receiving => response,
            _ = &mut sending => return receiving.await,
        }?;
        // Only a delivered response transfers the remaining upload to the background.
        tokio::spawn(sending);
        Ok(response)
    }
}

fn write_bytes_request<WS, SR, T: Transport>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack<T>>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, SR, T>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
    SR: Send + 'static,
{
    let (fields, body) = {
        let message = req.message.0.lock().unwrap();
        (message.fields(), message.body())
    };
    let parts = headers::request_parts(fields.clone())?;
    if headers::content_length(&parts.headers)?.is_some_and(|length| length != body.len() as u64) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let mut frame = Vec::new();
    frame.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    if !body.is_empty() {
        frame.put_frame(&Frame::<Data>::new(Data(body.len()))?);
    }
    let stopped = ws.stopped();
    Ok(async move {
        let result = tokio::select! {
            biased;
            error = stopped => Err(error),
            result = async {
                ws.write_all(&frame).await?;
                ws.write_all(&body).await?;
                ws.shutdown().await?;
                Ok::<_, Error>(())
            } => result,
        };
        if let Err(error) = result {
            ws.cancel_with_error(error);
        }
        result
    })
}

fn write_streaming_request<WS, SR, T: Transport>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack<T>>,
) -> Result<impl Future<Output = Result<()>> + Send + use<WS, SR, T>>
where
    WS: AsyncWrite + Unpin + Send + 'static,
    SR: Send + 'static,
{
    let (fields, mut body) = {
        let message = req.message.0.lock().unwrap();
        (message.fields(), message.body_stream())
    };
    // Validate before sending so malformed requests fail synchronously and wake producers.
    let (frame, mode) = (|| {
        let parts = headers::request_parts(fields.clone())?;
        let mode = match headers::content_length(&parts.headers)? {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        };
        let mut frame = Vec::new();
        frame.put_frame(&Frame::new(Headers {
            field_section: qpack.encode(ws.stream_id(), fields)?,
        })?);
        Ok::<_, Error>((frame, mode))
    })()
    .inspect_err(|error| body.set_error(*error))?;
    let body_error = req.message.body_error();
    let stopped = ws.stopped();
    // Capture body and headers, never Request/ArcMessage: producer Drop must remain observable.
    Ok(async move {
        let result = tokio::select! {
            biased;
            error = stopped => Err(error),
            error = body_error => Err(error),
            result = async {
                ws.write_all(&frame).await?;
                body::write_body(&mut body, &mut ws, mode).await
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
async fn read_response<RS: AsyncRead + Unpin + Send + 'static, RW: Send + 'static, T: Transport>(
    rs: H3ReadStream<RS, RW>,
    qpack: Arc<Qpack<T>>,
    method: Option<http::Method>,
) -> Result<crate::common::Response<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let (parts, mode) = async {
        let (parts, length) = loop {
            let frame = match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
                    continue;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
            };
            let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
            let parts = headers::response_parts(fields)?;
            let length = headers::content_length(&parts.headers)?;
            if parts.status == StatusCode::SWITCHING_PROTOCOLS {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if (parts.status.is_informational() || parts.status == StatusCode::NO_CONTENT)
                && length.is_some()
            {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if !parts.status.is_informational() {
                break (parts, length);
            }
        };
        if method.as_ref() == Some(&http::Method::CONNECT)
            && parts.status.is_success()
            && length.is_some()
        {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::resolve(&parts, method.as_ref())?;
        Ok((parts, mode))
    }
    .await
    .inspect_err(|error| {
        let _ = qpack.cancel(stream_id);
        qpack.on_error(*error);
    })?;
    let mut message = Message::<Bytes>::default();
    message.set_status(parts.status);
    for (name, value) in &parts.headers {
        message.append_header(name.clone(), value.clone());
    }
    if !mode.streaming() {
        let mut body = Vec::new();
        body::read_body(&mut rs, &mut body, mode, &qpack)
            .await
            .inspect_err(|error| {
                let _ = qpack.cancel(stream_id);
                qpack.on_error(*error);
            })?;
        let response: common::response::Response<Read, _> =
            ArcMessage::from(message.with_body(Bytes::from(body))).into();
        Ok(common::Response::Bytes(response))
    } else {
        let mut body = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let response: common::response::Response<Read, _> =
            ArcMessage::from(message.with_body(body.clone())).into();
        let body_error = response.message.body_error();
        tokio::spawn(async move {
            let result = tokio::select! {
                biased;
                    error = body_error => Err(error),
                result = body::read_body(&mut rs, &mut body, mode, &qpack) => result,
            };
            match result {
                Ok(()) => {}
                Err(error) => {
                    let _ = qpack.cancel(stream_id);
                    qpack.on_error(error);
                    body.set_error(error);
                }
            }
        });
        Ok(crate::common::Response::Streaming(response))
    }
}

#[cfg(test)]
mod tests;
