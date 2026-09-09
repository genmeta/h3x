//! HTTP message semantics and HEADERS / DATA / trailers processing.

use std::sync::Arc;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::{Frame, SizeHint};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};

use crate::{
    Code, Error, StreamId,
    protocol::headers::{self, message_error},
    qpack,
    transport::ResetOnDrop,
    wire::{self, ChunkReader, FrameReader, FrameType, write_frame},
};

/// Content semantics and, when declared, the bytes still expected before EOF.
#[derive(Clone, Copy)]
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
            Self::Known { remaining } if hint.exact().is_none_or(|size| size == *remaining) => {
                Ok(())
            }
            _ => Err(message_error("outgoing content length mismatch").into_invalid_message()),
        }
    }

    pub(super) fn data(&mut self, len: u64) -> Result<(), Error> {
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

    pub(super) fn finish(&self) -> Result<(), Error> {
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

pub(super) fn response_body(
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

fn unexpected() -> Error {
    Error::connection_protocol(
        Code::H3_FRAME_UNEXPECTED,
        "frame forbidden in this message phase",
    )
}

pub(super) async fn send_body(
    writer: &mut ResetOnDrop,
    body: &mut UnsyncBoxBody<Bytes, Error>,
    mut message_body: MessageBody,
    qpack: &qpack::Qpack,
    id: StreamId,
) -> Result<(), Error> {
    let mut trailers_sent = false;
    let mut ready_steps = 0;
    while let Some(frame) = body.frame().await {
        yield_after_batch(&mut ready_steps).await;
        let frame = frame?;
        match frame.into_data() {
            Ok(data) => {
                if trailers_sent {
                    return Err(message_error("DATA after trailers"));
                }
                if data.is_empty() {
                    continue;
                }
                send_data(writer, data, &mut message_body, &mut ready_steps).await?;
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    if trailers_sent || matches!(message_body, MessageBody::NoContent) {
                        return Err(message_error("trailers forbidden in this message phase"));
                    }
                    send_trailers(writer, trailers, &message_body, qpack, id).await?;
                    trailers_sent = true;
                }
            }
        }
    }
    message_body.finish()?;
    writer.finish().await.map_err(wire::map_stream_error)
}

pub(super) async fn send_trailers(
    writer: &mut ResetOnDrop,
    trailers: http::HeaderMap,
    message_body: &MessageBody,
    qpack: &qpack::Qpack,
    id: StreamId,
) -> Result<(), Error> {
    if matches!(message_body, MessageBody::NoContent) {
        return Err(message_error("trailers forbidden"));
    }
    message_body.finish()?;
    let fields = headers::regular_fields(trailers).map_err(Error::into_invalid_message)?;
    let encoded = qpack.encode_fields(id, fields).await?;
    write_frame(writer.writer(), wire::FrameType::Headers, encoded).await
}

async fn send_data(
    writer: &mut ResetOnDrop,
    mut data: Bytes,
    message_body: &mut MessageBody,
    ready_steps: &mut u8,
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }
    message_body.data(data.len() as u64)?;
    while !data.is_empty() {
        yield_after_batch(ready_steps).await;
        let len = data.len().min(wire::MAX_DATA_CHUNK);
        write_frame(writer.writer(), wire::FrameType::Data, data.split_to(len)).await?;
    }
    Ok(())
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
    finished: bool,
    response: bool,
    trailers: bool,
    on_finish: Option<Box<dyn FnOnce() + Send>>,
}
impl MessageReader {
    pub(super) fn new(reader: ChunkReader, qpack: Arc<qpack::Qpack>, id: StreamId) -> Self {
        Self {
            frames: FrameReader::new(reader),
            qpack,
            id,
            finished: false,
            response: false,
            trailers: false,
            on_finish: None,
        }
    }

    pub(super) fn on_finish(&mut self, callback: impl FnOnce() + Send + 'static) {
        self.on_finish = Some(Box::new(callback));
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
                    let wire::Frame::Headers(frame) = self
                        .frames
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?
                    else {
                        unreachable!()
                    };
                    return Ok(frame.field_section);
                }
                FrameType::Unknown(_) => self.frames.discard_payload().await?,
                FrameType::PushPromise if self.response => return Err(self.reject_push().await),
                _ => return Err(unexpected()),
            }
        }
    }

    async fn reject_push(&mut self) -> Error {
        match self
            .frames
            .read(|input| {
                qbase::varint::be_varint(input).map_err(|error| {
                    error.map(|_| {
                        Error::connection_protocol(Code::H3_FRAME_ERROR, "invalid push ID")
                    })
                })
            })
            .await
        {
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
            let fields = self.qpack.decode_fields(self.id, &payload).await?;
            let parts = headers::request_parts(fields)?;
            let message_body = request_body(&parts)?;
            Ok((parts, message_body))
        }
        .await;
        self.qpack.terminate_on_connection_error(result)
    }

    pub(super) async fn response(
        &mut self,
        method: &Method,
    ) -> Result<(http::response::Parts, MessageBody), Error> {
        self.response = true;
        let result = async {
            loop {
                let payload = self.initial(None).await?;
                let fields = self.qpack.decode_fields(self.id, &payload).await?;
                let parts = headers::response_parts(fields)?;
                let message_body = response_body(method, &parts, false)?;
                if parts.status.is_informational() {
                    continue;
                }
                return Ok((parts, message_body));
            }
        }
        .await;
        self.qpack.terminate_on_connection_error(result)
    }

    pub(super) async fn next_frame(
        &mut self,
        message_body: &mut MessageBody,
    ) -> Result<Option<Frame<Bytes>>, Error> {
        loop {
            if self.frames.remaining() != 0 {
                return self
                    .frames
                    .read(|input| wire::frame::be_payload_chunk(input, wire::MAX_DATA_CHUNK))
                    .await
                    .map(|data| Some(Frame::data(data)));
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
                    let wire::Frame::Data(frame) = self
                        .frames
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?
                    else {
                        unreachable!()
                    };
                    message_body.data(frame.length)?;
                }
                FrameType::Headers => {
                    if self.trailers || matches!(message_body, MessageBody::NoContent) {
                        return Err(unexpected());
                    }
                    message_body.finish()?;
                    let wire::Frame::Headers(frame) = self
                        .frames
                        .read(|input| crate::wire::frame::be_frame(input, header))
                        .await?
                    else {
                        unreachable!()
                    };
                    let payload = frame.field_section;
                    let fields = self.qpack.decode_fields(self.id, &payload).await?;
                    let trailers = headers::trailer_fields(fields)?;
                    self.trailers = true;
                    return Ok(Some(Frame::trailers(trailers)));
                }
                FrameType::Unknown(_) => self.frames.discard_payload().await?,
                FrameType::PushPromise if self.response => return Err(self.reject_push().await),
                _ => return Err(unexpected()),
            }
        }
    }

    pub(super) fn fail(&mut self, error: Error) -> Error {
        let _ = self
            .qpack
            .terminate_on_connection_error::<()>(Err(error.clone()));
        self.qpack.cancel_stream(self.id);
        self.frames
            .stop(error.code().unwrap_or(Code::H3_REQUEST_CANCELLED));
        self.finished = true;
        error
    }
}
impl Drop for MessageReader {
    fn drop(&mut self) {
        if !self.finished {
            self.qpack.cancel_stream(self.id);
            self.frames.stop(Code::H3_REQUEST_CANCELLED);
        }
        if let Some(callback) = self.on_finish.take() {
            callback();
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
