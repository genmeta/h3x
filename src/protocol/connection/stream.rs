//! HTTP message framing, body validation, and per-stream sending capability.

use std::sync::Arc;

use bytes::Bytes;
use futures::{SinkExt, future::AbortHandle};
use http::{Method, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use tokio::{
    io::AsyncReadExt,
    sync::{OwnedSemaphorePermit, oneshot, watch},
};

use super::{BoxSend, ConnectionState, stopped};
use crate::{
    Code, Error, StreamId, body,
    platform::MaybeSend,
    protocol::headers,
    qpack,
    wire::{self, ChunkReader, FrameReader, FrameType},
};

/// Content semantics and, when declared, the bytes still expected before EOF.
pub(super) enum MessageBody {
    NoContent,
    Unknown,
    Known { remaining: u64 },
}
impl MessageBody {
    pub(super) fn validate_size(&self, hint: SizeHint) -> Result<(), Error> {
        match self {
            Self::NoContent if hint.lower() == 0 => Ok(()),
            Self::Unknown => Ok(()),
            Self::Known { remaining } if hint.exact().is_none_or(|size| size == *remaining) => Ok(()),
            _ => Err(message_error("outgoing content length mismatch").into_invalid_message()),
        }
    }

    fn data(&mut self, len: u64) -> Result<(), Error> {
        match self {
            Self::NoContent => {
                return Err(message_error("DATA forbidden on a message without content"));
            }
            Self::Unknown => {}
            Self::Known { remaining } => {
                *remaining = remaining
                    .checked_sub(len)
                    .ok_or_else(|| message_error("DATA exceeds Content-Length"))?;
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), Error> {
        if matches!(self, Self::Known { remaining } if *remaining != 0) {
            return Err(message_error("content shorter than Content-Length"));
        }
        Ok(())
    }
}

pub(super) fn request_body(parts: &http::request::Parts) -> Result<MessageBody, Error> {
    let remaining = headers::content_length(&parts.headers)?;
    let no_content = parts.method == Method::TRACE;
    if no_content && remaining.is_some_and(|n| n != 0) {
        return Err(message_error("TRACE cannot carry content"));
    }
    Ok(if no_content {
        MessageBody::NoContent
    } else {
        remaining.map_or(MessageBody::Unknown, |remaining| MessageBody::Known {
            remaining,
        })
    })
}

fn response_body(
    method: &Method,
    parts: &http::response::Parts,
    sending: bool,
) -> Result<MessageBody, Error> {
    let remaining = headers::content_length(&parts.headers)?;
    if parts.status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(message_error("HTTP/3 cannot switch protocols with 101"));
    }
    if (parts.status.is_informational() || parts.status == StatusCode::NO_CONTENT)
        && remaining.is_some()
    {
        return Err(message_error("Content-Length forbidden on 1xx/204"));
    }
    if sending && parts.status.is_informational() {
        return Err(message_error("ResponseSender requires a final response"));
    }
    if *method == Method::CONNECT && parts.status.is_success() {
        return Err(Error::Unsupported {
            operation: "CONNECT tunnel",
        });
    }
    let no_content = *method == Method::HEAD
        || parts.status == StatusCode::NOT_MODIFIED
        || parts.status == StatusCode::NO_CONTENT
        || parts.status.is_informational();
    Ok(if no_content {
        MessageBody::NoContent
    } else {
        remaining.map_or(MessageBody::Unknown, |remaining| MessageBody::Known {
            remaining,
        })
    })
}

pub(super) fn message_error(message: &'static str) -> Error {
    Error::stream(Some(Code::H3_MESSAGE_ERROR), message)
}

fn unexpected() -> Error {
    Error::connection_protocol(
        Code::H3_FRAME_UNEXPECTED,
        "frame forbidden in this message phase",
    )
}

pub(super) struct ResetOnDrop {
    writer: Option<BoxSend>,
}
impl ResetOnDrop {
    pub(super) fn new(writer: BoxSend) -> Self {
        Self {
            writer: Some(writer),
        }
    }

    pub(super) fn writer(&mut self) -> &mut BoxSend {
        self.writer.as_mut().unwrap()
    }

    pub(super) fn reset(&mut self, code: Code) {
        if let Some(mut writer) = self.writer.take() {
            let _ = writer.reset(code);
        }
    }

    async fn finish(&mut self) -> Result<(), Error> {
        self.writer()
            .close()
            .await
            .map_err(wire::map_stream_error)?;
        self.writer.take();
        Ok(())
    }
}
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        self.reset(Code::H3_REQUEST_CANCELLED);
    }
}

/// Header and payload are separate Sink items; DATA retains its Bytes allocation.
pub(super) async fn write_frame(
    writer: &mut BoxSend,
    kind: u64,
    payload: Bytes,
) -> Result<(), Error> {
    let mut header = Vec::with_capacity(16);
    wire::encode_varint(kind, &mut header)?;
    wire::encode_varint(payload.len() as u64, &mut header)?;
    writer
        .feed(Bytes::from(header))
        .await
        .map_err(wire::map_stream_error)?;
    if !payload.is_empty() {
        writer.feed(payload).await.map_err(wire::map_stream_error)?;
    }
    writer.flush().await.map_err(wire::map_stream_error)
}

pub(super) async fn send_body(
    writer: &mut ResetOnDrop,
    body: UnsyncBoxBody<Bytes, Error>,
    mut message_body: MessageBody,
    qpack: &qpack::Qpack,
    id: StreamId,
) -> Result<(), Error> {
    let mut body = std::pin::pin!(body);
    let mut trailers_sent = false;
    let mut ready_steps = 0;
    while let Some(frame) = body.frame().await {
        yield_after_batch(&mut ready_steps).await;
        let frame = frame?;
        match frame.into_data() {
            Ok(mut data) => {
                if trailers_sent {
                    return Err(message_error("DATA after trailers"));
                }
                if data.is_empty() {
                    continue;
                }
                message_body.data(data.len() as u64)?;
                while !data.is_empty() {
                    yield_after_batch(&mut ready_steps).await;
                    let len = data.len().min(wire::MAX_DATA_CHUNK);
                    write_frame(writer.writer(), wire::DATA_FRAME_TYPE, data.split_to(len)).await?;
                }
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    if trailers_sent || matches!(message_body, MessageBody::NoContent) {
                        return Err(message_error("trailers forbidden in this message phase"));
                    }
                    message_body.finish()?;
                    let encoded = qpack.encode_trailers(id, trailers).await?;
                    write_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, encoded).await?;
                    trailers_sent = true;
                }
            }
        }
    }
    message_body.finish()?;
    writer.finish().await
}

pub(super) async fn send_upload(
    writer: &mut ResetOnDrop,
    upload: &mut body::writer::Upload,
    mut message_body: MessageBody,
    qpack: &qpack::Qpack,
    id: StreamId,
) -> Result<(), Error> {
    let mut consumed = 0u64;
    let mut command = None;
    let mut bytes = vec![0; wire::MAX_DATA_CHUNK];
    let mut ready_steps = 0;
    loop {
        yield_after_batch(&mut ready_steps).await;
        if command
            .as_ref()
            .is_some_and(|c: &body::writer::Control| c.through() == consumed)
        {
            match command.take().unwrap() {
                body::writer::Control::Flush { reply, .. } => {
                    let result = writer
                        .writer()
                        .flush()
                        .await
                        .map_err(wire::map_stream_error);
                    let _ = reply.send(result.clone());
                    result?;
                }
                body::writer::Control::Finish { trailers, .. } => {
                    message_body.finish()?;
                    if let Some(trailers) = trailers {
                        if matches!(message_body, MessageBody::NoContent) {
                            return Err(message_error("trailers forbidden"));
                        }
                        write_frame(
                            writer.writer(),
                            wire::HEADERS_FRAME_TYPE,
                            qpack.encode_trailers(id, trailers).await?,
                        )
                        .await?;
                    }
                    return writer.finish().await;
                }
            }
        }
        let limit = command.as_ref().map_or(wire::MAX_DATA_CHUNK, |c| {
            usize::try_from(c.through().saturating_sub(consumed))
                .unwrap_or(usize::MAX)
                .min(wire::MAX_DATA_CHUNK)
        });
        if limit == 0 {
            continue;
        }
        tokio::select! {
            biased;
            next = upload.control.recv(), if command.is_none() => { command = Some(next.ok_or(Error::BodyAborted)?); },
            count = upload.pipe.read(&mut bytes[..limit]) => {
                let count = count.map_err(Error::send_body)?;
                if count == 0 {
                    // Finish is queued before the pipe closes. A bare EOF is abandonment.
                    if command.is_none() { command = Some(upload.control.try_recv().map_err(|_| Error::BodyAborted)?); }
                    if command.as_ref().unwrap().through() != consumed { return Err(Error::BodyAborted); }
                    continue;
                }
                message_body.data(count as u64)?;
                consumed = consumed.checked_add(count as u64).ok_or_else(|| message_error("upload length overflow"))?;
                write_frame(writer.writer(), wire::DATA_FRAME_TYPE, Bytes::copy_from_slice(&bytes[..count])).await?;
            }
        }
    }
}

async fn yield_after_batch(steps: &mut u8) {
    *steps += 1;
    if *steps == 64 {
        *steps = 0;
        tokio::task::yield_now().await;
    }
}

/// The receive direction owns parsing, QPACK cancellation and its terminal state.
pub(super) struct MessageReader {
    frames: FrameReader,
    qpack: Arc<qpack::Qpack>,
    id: StreamId,
    state: Arc<ConnectionState>,
    finished: bool,
    response: bool,
    trailers: bool,
}
impl MessageReader {
    pub(super) fn new(
        reader: ChunkReader,
        qpack: Arc<qpack::Qpack>,
        id: StreamId,
        state: Arc<ConnectionState>,
    ) -> Self {
        Self {
            frames: FrameReader::new(reader),
            qpack,
            id,
            state,
            finished: false,
            response: false,
            trailers: false,
        }
    }

    async fn header(&mut self) -> Result<Option<wire::FrameHeader>, Error> {
        let Some(kind) = self.frames.next_type().await? else {
            return Ok(None);
        };
        #[cfg(feature = "webtransport")]
        if kind == wire::WEBTRANSPORT_BIDI_SIGNAL {
            return Err(Error::connection_protocol(
                Code::H3_FRAME_ERROR,
                "WT signal after HTTP frames",
            ));
        }
        self.frames.header_after_type(kind).await.map(Some)
    }

    async fn initial(&mut self, mut first: Option<u64>) -> Result<Bytes, Error> {
        loop {
            let header = match first.take() {
                Some(kind) => self.frames.header_after_type(kind).await?,
                None => self.header().await?.ok_or_else(|| {
                    Error::stream(Some(Code::H3_REQUEST_INCOMPLETE), "missing initial HEADERS")
                })?,
            };
            match header.frame_type {
                FrameType::Headers => {
                    return self
                        .frames
                        .read_payload(wire::MAX_BUFFERED_FRAME_PAYLOAD)
                        .await;
                }
                FrameType::Unknown(_) => self.frames.discard_payload().await?,
                FrameType::PushPromise if self.response => return Err(self.reject_push().await),
                _ => return Err(unexpected()),
            }
        }
    }

    async fn reject_push(&mut self) -> Error {
        match self.frames.read_payload_varint().await {
            Err(error) => error,
            Ok(_) => Error::connection_protocol(Code::H3_ID_ERROR, "no push ID authorized"),
        }
    }

    pub(super) async fn request(
        &mut self,
        first: u64,
    ) -> Result<(http::request::Parts, MessageBody), Error> {
        let result = async {
            let payload = self.initial(Some(first)).await?;
            let parts = self.qpack.decode_request(self.id, &payload).await?;
            headers::validate_request(&parts)?;
            let message_body = request_body(&parts)?;
            Ok((parts, message_body))
        }
        .await;
        self.check(result)
    }

    pub(super) async fn response(
        &mut self,
        method: &Method,
    ) -> Result<(http::response::Parts, MessageBody), Error> {
        self.response = true;
        let result = async {
            loop {
                let payload = self.initial(None).await?;
                let parts = self.qpack.decode_response(self.id, &payload).await?;
                let message_body = response_body(method, &parts, false)?;
                if parts.status.is_informational() {
                    continue;
                }
                return Ok((parts, message_body));
            }
        }
        .await;
        self.check(result)
    }

    fn check<V>(&self, result: Result<V, Error>) -> Result<V, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            self.state.terminate(error.clone());
        }
        result
    }

    async fn next_frame(
        &mut self,
        message_body: &mut MessageBody,
    ) -> Result<Option<Frame<Bytes>>, Error> {
        loop {
            if self.frames.remaining() != 0 {
                return Ok(self
                    .frames
                    .read_payload_chunk(wire::MAX_DATA_CHUNK)
                    .await?
                    .map(Frame::data));
            }
            let Some(header) = self.header().await? else {
                message_body.finish()?;
                self.finished = true;
                return Ok(None);
            };
            match header.frame_type {
                FrameType::Data => {
                    if self.trailers {
                        return Err(unexpected());
                    }
                    message_body.data(header.length)?;
                }
                FrameType::Headers => {
                    if self.trailers || matches!(message_body, MessageBody::NoContent) {
                        return Err(unexpected());
                    }
                    message_body.finish()?;
                    let payload = self
                        .frames
                        .read_payload(wire::MAX_BUFFERED_FRAME_PAYLOAD)
                        .await?;
                    let trailers = self.qpack.decode_trailers(self.id, &payload).await?;
                    self.trailers = true;
                    return Ok(Some(Frame::trailers(trailers)));
                }
                FrameType::Unknown(_) => self.frames.discard_payload().await?,
                FrameType::PushPromise if self.response => return Err(self.reject_push().await),
                _ => return Err(unexpected()),
            }
        }
    }

    pub(super) fn into_body(
        self,
        message_body: MessageBody,
        terminal: watch::Sender<Option<Error>>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> crate::ChunkBody {
        let frames = futures::stream::unfold(
            (self, message_body, terminal, permit),
            move |(mut reader, mut message_body, terminal, permit)| async move {
                let result = tokio::select! {
                    biased;
                    error = stopped(&terminal) => Err(error),
                    result = reader.next_frame(&mut message_body) => reader.check(result),
                };
                let frame = match result {
                    Ok(Some(frame)) => Ok(frame),
                    Ok(None) => return None,
                    Err(error) => {
                        reader.qpack.cancel_stream(reader.id);
                        let _ = reader
                            .frames
                            .stop(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
                        reader.finished = true;
                        Err(error)
                    }
                };
                Some((frame, (reader, message_body, terminal, permit)))
            },
        );
        crate::ChunkBody::new(http_body_util::StreamBody::new(frames))
    }
}
impl Drop for MessageReader {
    fn drop(&mut self) {
        if !self.finished {
            self.qpack.cancel_stream(self.id);
        }
    }
}

pub(super) enum Outgoing {
    Body(UnsyncBoxBody<Bytes, Error>),
    Upload(body::writer::Upload),
}

// Keep request headers separate: connection admission is rechecked before body tasks start.
pub(super) async fn send_request_headers(
    writer: &mut ResetOnDrop,
    qpack: &qpack::Qpack,
    id: StreamId,
    fields: Vec<qpack::Field>,
) -> Result<(), Error> {
    let encoded = qpack.encode_fields(id, fields).await?;
    write_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, encoded).await
}

pub(super) async fn send_response(
    writer: &mut ResetOnDrop,
    response: http::Response<UnsyncBoxBody<Bytes, Error>>,
    method: &Method,
    qpack: &qpack::Qpack,
    id: StreamId,
) -> Result<(), Error> {
    let (parts, body) = response.into_parts();
    let message_body = response_body(method, &parts, true)?;
    let encoded = qpack.encode_response(id, parts).await?;
    write_frame(writer.writer(), wire::HEADERS_FRAME_TYPE, encoded).await?;
    send_body(writer, body, message_body, qpack, id).await
}

/// The unique sending capability for an accepted request.
pub struct ResponseSender {
    pub(super) stream_id: StreamId,
    pub(super) method: http::Method,
    pub(super) response: Option<oneshot::Sender<http::Response<UnsyncBoxBody<Bytes, Error>>>>,
    pub(super) sent: oneshot::Receiver<Result<(), Error>>,
    pub(super) stop: Option<AbortHandle>,
}
impl std::fmt::Debug for ResponseSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseSender")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}
impl ResponseSender {
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub async fn send<B>(mut self, response: http::Response<B>) -> Result<(), Error>
    where
        B: Body<Data = Bytes> + MaybeSend + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let (parts, body) = response.into_parts();
        let message_body =
            response_body(&self.method, &parts, true).map_err(Error::into_invalid_message)?;
        message_body.validate_size(body.size_hint())?;
        let response = http::Response::from_parts(
            parts,
            body.map_err(|e| Error::Body {
                source: Arc::from(e.into()),
            })
            .boxed_unsync(),
        );
        self.response
            .take()
            .ok_or(Error::Cancelled)?
            .send(response)
            .map_err(|_| Error::OwnerStopped)?;
        let result = (&mut self.sent).await.unwrap_or(Err(Error::OwnerStopped));
        self.stop.take();
        result
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_runtime(&self) -> Option<Arc<crate::webtransport::Runtime>> {
        None
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn webtransport_keepalive(&self) -> crate::platform::KeepAlive {
        Arc::new(())
    }

    #[cfg(feature = "webtransport")]
    pub(crate) fn reject(self, _code: Code) {
        drop(self);
    }

    #[cfg(feature = "webtransport")]
    pub(crate) async fn start_webtransport_response(
        self,
        _response: http::Response<()>,
    ) -> Result<BoxSend, Error> {
        Err(Error::Unsupported {
            operation: "WebTransport upgrade",
        })
    }
}
impl Drop for ResponseSender {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_body_enforces_length_and_no_content() {
        let (parts, _) = http::Request::builder()
            .header(http::header::CONTENT_LENGTH, "10")
            .body(())
            .unwrap()
            .into_parts();
        let mut message_body = request_body(&parts).unwrap();
        message_body.data(6).unwrap();
        assert!(message_body.finish().is_err());
        assert!(message_body.data(5).is_err());
        message_body.data(4).unwrap();
        message_body.finish().unwrap();

        let (parts, _) = http::Response::builder()
            .header(http::header::CONTENT_LENGTH, "10")
            .body(())
            .unwrap()
            .into_parts();
        let message_body = response_body(&Method::HEAD, &parts, false).unwrap();
        message_body.finish().unwrap(); // HEAD may describe a body without transmitting it.
        assert!(matches!(message_body, MessageBody::NoContent));
        assert!(message_body.validate_size(SizeHint::with_exact(1)).is_err());
    }
}
