//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
};

use bytes::Bytes;
use http::StatusCode;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result,
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

/// Send one request and read its response on an existing bidirectional stream.
pub async fn request<RS, WS, R, RW, SR>(
    request: R,
    recv: H3ReadStream<RS, RW>,
    send: H3WriteStream<WS, SR>,
    qpack: Arc<Qpack>,
) -> Result<Response>
where
    RS: AsyncRead + Unpin + Send + 'static,
    RW: Send + 'static,
    WS: AsyncWrite + Unpin,
    R: Into<common::Request<Write>>,
{
    use crate::ReadRequest;
    let request = request.into();
    let method = request.method();
    let encoder = qpack.clone();
    let sending = async move {
        match request {
            common::Request::Bytes(request) => write_bytes_request(&request, send, &encoder).await,
            common::Request::Streaming(request) => {
                write_streaming_request(&request, send, &encoder).await
            }
        }
    };
    //TODO: FIXME 服务端发送 stop sending， try_join! 会因发送错误丢掉响应结果
    let (_, response) = tokio::try_join!(sending, read_response(recv, qpack, Some(method)))?;
    Ok(response)
}

async fn write_bytes_request<WS: AsyncWrite + Unpin, SR>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: &Qpack,
) -> Result<()> {
    let (fields, body) = {
        let message = req.message.0.lock().unwrap();
        let fields = message.fields();
        (fields, message.body())
    };
    let parts = headers::request_parts(fields.clone())?;
    if headers::content_length(&parts.headers)?.is_some_and(|length| length != body.len() as u64) {
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

async fn write_streaming_request<WS: AsyncWrite + Unpin, SR>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS, SR>,
    qpack: &Qpack,
) -> Result<()> {
    let mut body = req.message.0.lock().unwrap().body_stream().cancel_on_drop();
    let fields = req.message.0.lock().unwrap().fields();
    let parts = headers::request_parts(fields.clone())?;
    let length = headers::content_length(&parts.headers)?;
    let mut frame = Vec::new();
    frame.put_frame(&Frame::new(Headers {
        field_section: qpack.encode(ws.stream_id(), fields)?,
    })?);
    ws.write_all(&frame).await?;
    body::write_body(
        &mut body,
        &mut ws,
        match length {
            Some(content_length) => BodyMode::Length { content_length },
            None => BodyMode::Infinity,
        },
    )
    .await?;
    body.complete();
    Ok(())
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method input.
async fn read_response<RS: AsyncRead + Unpin + Send + 'static, RW: Send + 'static>(
    rs: H3ReadStream<RS, RW>,
    qpack: Arc<Qpack>,
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
        Ok(crate::common::Response::Streaming(response))
    }
}

#[cfg(test)]
mod tests;
