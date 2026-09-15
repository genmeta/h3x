//! Incoming requests and responses on the original stream.

use std::{future::Future, sync::Arc};

use bytes::Bytes;
use http::{HeaderValue, Method, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result, Transport,
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
/// For streaming responses, retain a producer clone until it finishes or resets
/// the body. Dropping the last unfinished producer cancels sending.
///
/// `request_method` must be the original request's method so HEAD responses can
/// preserve `Content-Length` without sending a body.
/// Streaming bodies bind before the returned future is polled, so dropping that
/// future also cancels unfinished body operations.
pub fn respond<WS, R, SR, T: Transport>(
    response: R,
    send: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack<T>>,
    request_method: &Method,
) -> impl Future<Output = Result<()>>
where
    WS: AsyncWrite + Unpin,
    R: Into<common::Response<Write>>,
{
    let response = response.into();
    if let common::Response::Streaming(response) = &response {
        let body = response.message.0.lock().unwrap().body_stream();
        send.bind_body(&body);
    }
    async move {
        match response {
            common::Response::Bytes(response) => {
                write_bytes_response(&response, send, &qpack, request_method).await
            }
            common::Response::Streaming(response) => {
                let sending = write_streaming_response(&response, send, qpack, request_method);
                drop(response);
                sending.await
            }
        }
    }
}

/// Read an HTTP request using the receive stream's ID and explicit QPACK.
pub async fn accept<RS: AsyncRead + Unpin + Send + 'static, RW: Send + 'static, T: Transport>(
    rs: H3ReadStream<RS, RW>,
    qpack: Arc<Qpack<T>>,
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
        rs.get_ref().bind_body(&body);
        let request: common::request::Request<Read, _> =
            ArcMessage::from(message.with_body(body.clone())).into();
        let body_error = request.message.body_error();
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
        Ok(crate::common::Request::Streaming(request))
    }
}

/// Writes a buffered response using the original request method.
async fn write_bytes_response<WS: AsyncWrite + Unpin, SR, T: Transport>(
    response: &Response<Bytes>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: &Qpack<T>,
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
    let stopped = ws.stopped();
    let result = tokio::select! {
        biased;
        error = stopped => Err(error),
        result = async {
            ws.write_all(&frame).await?;
            if !body.is_empty() {
                frame.clear();
                frame.put_frame(&Frame::<Data>::new(Data(body.len()))?);
                ws.write_all(&frame).await?;
                ws.write_all(&body).await?;
            }
            ws.shutdown().await?;
            Ok::<_, Error>(())
        } => result,
    };
    if let Err(error) = result {
        ws.reset(error);
    }
    result
}

/// Writes a streaming response using the original request method.
fn write_streaming_response<WS: AsyncWrite + Unpin, SR, T: Transport>(
    response: &Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack<T>>,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS, SR, T> {
    let (fields, mut body) = {
        let message = response.message.0.lock().unwrap();
        (message.fields(), message.body_stream())
    };
    ws.bind_body(&body);
    let body_error = response.message.body_error();
    let stopped = ws.stopped();
    let request_method = request_method.clone();
    // Capture body and headers, never Response/ArcMessage: producer Drop must remain observable.
    async move {
        let result = tokio::select! {
            biased;
            error = stopped => Err(error),
            error = body_error => Err(error),
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
                let mut frame = Vec::new();
                frame.put_frame(&Frame::new(Headers {
                    field_section: qpack.encode(ws.stream_id(), fields)?,
                })?);
                ws.write_all(&frame).await?;
                body::write_body(&mut body, &mut ws, mode).await
            } => result,
        };
        if let Err(error) = result {
            ws.reset(error);
            body.set_error(error);
        }
        result
    }
}

#[cfg(test)]
mod tests;
