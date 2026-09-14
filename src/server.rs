//! Incoming requests and responses on the original stream.

use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
};

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result,
    common::{
        self, Read, Write,
        message::{ArcMessage, Message, ReadBody},
    },
    protocol::{
        body::{self, BodyMode},
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers,
        qpack::Qpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Send one response on the accepted request's matching send stream.
///
/// `request_method` must be the original request's method so HEAD responses can
/// preserve `Content-Length` without sending a body.
pub async fn respond<WS, R, SR>(
    response: R,
    send: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack>,
    request_method: &Method,
) -> Result<()>
where
    WS: AsyncWrite + Unpin,
    R: Into<common::Response<Write>>,
{
    let response = response.into();
    tokio::select! {
        biased;
        error = qpack.terminated() => Err(error),
        result = async {
            match response {
                common::Response::Bytes(response) => {
                    write_bytes_response(&response, send, &qpack, request_method).await
                }
                common::Response::Streaming(response) => {
                    write_streaming_response(&response, send, &qpack, request_method).await
                }
            }
        } => result,
    }
}

/// Read an HTTP request using the receive stream's ID and explicit QPACK.
pub async fn accept<RS: AsyncRead + Unpin + Send + 'static, RW: Send + 'static>(
    rs: H3ReadStream<RS, RW>,
    qpack: Arc<Qpack>,
) -> Result<crate::common::Request<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let (message, length) = async {
        let frame = loop {
            match be_frame(&mut rs).await? {
                H3Frame::Headers(frame) => break frame,
                H3Frame::Unknown { length, .. } => {
                    frame::skip_payload(&mut rs, length.into_u64()).await?;
                }
                _ => return Err(Error::H3_FRAME_UNEXPECTED),
            }
        };
        let fields = qpack.decode(stream_id, frame.payload.field_section).await?;
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
    .await
    .inspect_err(|error| {
        let _ = qpack.cancel(stream_id);
        qpack.on_error(*error);
    })?;
    let mode = match length {
        Some(content_length) => BodyMode::Length { content_length },
        None => BodyMode::Infinity,
    };
    if !mode.streaming() {
        let mut body = Vec::new();
        body::read_body(&mut rs, &mut body, mode, &qpack)
            .await
            .inspect_err(|error| {
                let _ = qpack.cancel(stream_id);
                qpack.on_error(*error);
            })?;
        let request: common::request::Request<Read, _> =
            ArcMessage::from(message.with_body(Bytes::from(body))).into();
        Ok(common::Request::Bytes(request))
    } else {
        let mut body = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let request: common::request::Request<Read, _> =
            ArcMessage::from(message.with_body(body.clone().cancel_on_drop())).into();
        tokio::spawn(async move {
            let signal = body.clone();
            let result = {
                let receive = body::read_body(&mut rs, &mut body, mode, &qpack);
                tokio::pin!(receive);
                tokio::select! {
                    biased;
                    error = qpack.terminated() => Err(error),
                    result = poll_fn(|cx| {
                        if let Err(error) = signal.poll_error(cx) {
                            return Poll::Ready(Err(error));
                        }
                        receive.as_mut().poll(cx)
                    }) => result,
                }
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
        Ok(crate::common::Request::Streaming(request))
    }
}

/// Writes a buffered response using the original request method.
async fn write_bytes_response<WS: AsyncWrite + Unpin, SR>(
    response: &Response<Bytes>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: &Qpack,
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
    let mut frame = Vec::new();
    frame.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    ws.write_all(&frame).await?;
    if !body.is_empty() {
        frame.clear();
        frame.put_frame(&Frame::<Data>::new(Data(body.len()))?);
        ws.write_all(&frame).await?;
        ws.write_all(&body).await?;
    }
    ws.shutdown().await?;
    Ok(())
}

/// Writes a streaming response using the original request method.
async fn write_streaming_response<WS: AsyncWrite + Unpin, SR>(
    response: &Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: &Qpack,
    request_method: &Method,
) -> Result<()> {
    let mut body = response
        .message
        .0
        .lock()
        .unwrap()
        .body_stream()
        .cancel_on_drop();
    let (fields, mode) = {
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
        let mode = BodyMode::resolve(&parts, Some(request_method))?;
        (fields, mode)
    };
    let mut frame = Vec::new();
    frame.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    ws.write_all(&frame).await?;
    body::write_body(&mut body, &mut ws, mode).await?;
    body.complete();
    Ok(())
}

#[cfg(test)]
mod tests;
