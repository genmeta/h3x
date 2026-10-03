use std::{
    future::{Future, poll_fn},
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::{BodyExt, StreamBody};
use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};

use super::{ArcH3Stream, H3Stream, StreamEventHandler};
use crate::{
    ArcQpack, ArcWndBuf, Body, BoxError, Error, ErrorCode, Trailers, TransportError,
    common::{
        request::{ReadRequest, Request},
        response::{ReadResponse, Response},
    },
    frame::{self, Frame, H3Frame},
};

/// Application-owned read direction, sharing state with the connection registry.
pub struct H3ReadStream<R: StopSending> {
    pub(super) state: ArcH3Stream<R>,
    handler: StreamEventHandler,
    id: u64,
}

impl<R: StopSending> H3ReadStream<R> {
    pub(crate) fn new(stream_id: u64, stream: R, handler: StreamEventHandler) -> Self {
        Self {
            id: stream_id,
            state: ArcH3Stream::new(stream),
            handler,
        }
    }

    fn fail(&self, error: Error) {
        let code = error.code.as_u64();
        if self.state.fail(error.clone(), |io| io.stop(code)) {
            (self.handler)(Err(error));
        }
    }

    fn error_handler(&self) -> impl FnOnce(Error) + Send + 'static
    where
        R: Send + 'static,
    {
        let state = self.state.clone();
        let events = self.handler.clone();
        move |error| {
            let code = error.code.as_u64();
            if state.fail(error.clone(), |io| io.stop(code)) {
                events(Err(error));
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let error = ErrorCode::try_from(error_code)
            .unwrap_or(ErrorCode::InternalError)
            .stream(format!("read stream stopped with code 0x{error_code:x}"));
        self.fail(error);
    }
}

impl<R: StopSending> StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + StopSending + TransportError + Unpin> AsyncRead for H3ReadStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // A zero-capacity read is not evidence of EOF.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let mut state = self.state.0.lock().unwrap();
        let stream = match state.as_mut() {
            Err(error) => return Poll::Ready(Err(error.clone().into())),
            Ok(H3Stream::Finished) => return Poll::Ready(Ok(())),
            Ok(stream) => stream,
        };
        let mut io = match mem::replace(stream, H3Stream::Transition) {
            H3Stream::Idle(io) | H3Stream::Polling(io, _) => io,
            H3Stream::Finished | H3Stream::Transition => unreachable!(),
        };
        match Pin::new(&mut io).poll_read(cx, buf) {
            Poll::Pending => {
                *stream = H3Stream::Polling(io, cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(value)) => {
                if buf.filled().len() == before {
                    *stream = H3Stream::Finished;
                    drop(io);
                    drop(state);
                    (self.handler)(Ok(()));
                } else {
                    *stream = H3Stream::Idle(io);
                }
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) =>
            {
                *stream = H3Stream::Idle(io);
                Poll::Ready(Err(error))
            }
            Poll::Ready(Err(error)) => {
                let error = R::map_error(error);
                *state = Err(error.clone());
                drop(io);
                drop(state);
                (self.handler)(Err(error.clone()));
                Poll::Ready(Err(error.into()))
            }
        }
    }
}

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        let unfinished = matches!(
            self.state.0.lock().unwrap().as_ref(),
            Ok(H3Stream::Idle(_) | H3Stream::Polling(_, _))
        );
        // Invoke cancellation after releasing the state lock; callbacks re-enter the registry.
        if unfinished {
            self.stop(ErrorCode::RequestCancelled.as_u64());
        }
    }
}

pub(crate) enum NextFrame {
    Data(Frame<frame::Data>),
    Trailer(Frame<frame::Headers>),
}

impl<R: AsyncRead + StopSending + TransportError + Unpin> H3ReadStream<R> {
    async fn decode(
        &self,
        qpack: &ArcQpack,
        payload: bytes::Bytes,
    ) -> crate::Result<Vec<crate::qpack::Field>> {
        let decoding = qpack.decode(self.stream_id(), payload);
        tokio::pin!(decoding);

        poll_fn(|cx| {
            let state = self.state.0.lock().unwrap();
            match state.as_ref() {
                Ok(stream) if !stream.is_finished() => decoding.as_mut().poll(cx),
                Ok(_) => Poll::Ready(Err(
                    ErrorCode::RequestCancelled.stream("stream is terminated")
                )),
                Err(error) => Poll::Ready(Err(error.clone())),
            }
        })
        .await
    }

    async fn read_frame(&mut self) -> crate::Result<Option<H3Frame>> {
        let Some(ty) = frame::be_frame_type(self).await.map_err(R::map_error)? else {
            return Ok(None);
        };
        let length = frame::be_frame_length(self).await.map_err(R::map_error)?;
        frame::be_frame_payload(self, ty, length)
            .await
            .map(Some)
            .map_err(R::map_error)
    }

    pub(crate) async fn read_headers_frame(
        &mut self,
    ) -> crate::Result<Option<Frame<frame::Headers>>> {
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(frame)),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64())
                        .await
                        .map_err(R::map_error)?;
                }
                Some(_) => {
                    return Err(ErrorCode::FrameUnexpected
                        .connection("expected HEADERS before message body"));
                }
                None => return Ok(None),
            }
        }
    }

    pub(crate) async fn read_next_frame(
        &mut self,
        trailers: bool,
    ) -> crate::Result<Option<NextFrame>> {
        if trailers {
            loop {
                match frame::be_frame_type(self).await.map_err(R::map_error)? {
                    Some(frame::FrameType::Unknown(_)) => {
                        let length = frame::be_frame_length(self).await.map_err(R::map_error)?;
                        frame::skip_payload(self, length.into_u64())
                            .await
                            .map_err(R::map_error)?;
                    }
                    Some(_) => {
                        return Err(
                            ErrorCode::FrameUnexpected.connection("frame received after trailers")
                        );
                    }
                    None => return Ok(None),
                }
            }
        }
        loop {
            match self.read_frame().await? {
                Some(H3Frame::Headers(frame)) => return Ok(Some(NextFrame::Trailer(frame))),
                Some(H3Frame::Data(frame)) => return Ok(Some(NextFrame::Data(frame))),
                Some(H3Frame::Unknown { length, .. }) => {
                    frame::skip_payload(self, length.into_u64())
                        .await
                        .map_err(R::map_error)?;
                }
                Some(_) => {
                    return Err(ErrorCode::FrameUnexpected
                        .connection("frame is not allowed on a request stream"));
                }
                None => return Ok(None),
            }
        }
    }
}

impl<R> ReadRequest for H3ReadStream<R>
where
    R: AsyncRead + StopSending + TransportError + Unpin + Send + 'static,
{
    async fn read_request(self, qpack: ArcQpack) -> crate::Result<http::Request<crate::Body>> {
        let mut reader = self;
        let mut body = crate::ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        body.on_error(reader.error_handler());
        let consumer = body.clone();
        let request = async {
            let frame = reader.read_headers_frame().await?.ok_or_else(|| {
                ErrorCode::RequestIncomplete.stream("stream ended before request HEADERS")
            })?;
            let fields = reader.decode(&qpack, frame.payload.field_section).await?;
            Request::from_fields(fields, consumer).map_err(Error::stream)
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            reader.fail(failure.clone());
            qpack.error().unwrap_or(failure)
        })?;
        let message_trailers = request.trailers.clone();

        let (consumer_lifetime, consumer_dropped) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let receiving = async {
                let mut trailers = false;
                while let Some(frame) = reader.read_next_frame(trailers).await? {
                    match frame {
                        NextFrame::Data(frame) => {
                            let mut payload = (&mut reader).take(frame.length.into_u64());
                            let mut chunk = bytes::BytesMut::new();
                            while payload.limit() > 0 {
                                // Keep unused slab capacity across short transport reads.
                                // Otherwise a one-byte read could retain an entire 8 KiB
                                // allocation for every queued byte.
                                if chunk.capacity() == 0 {
                                    chunk
                                        .reserve(payload.limit().min(frame::MAX_DATA_CHUNK as u64)
                                            as usize);
                                }
                                if payload.read_buf(&mut chunk).await.map_err(R::map_error)? == 0 {
                                    break;
                                }
                                body.write_bytes(chunk.split().freeze())
                                    .await
                                    .map_err(Error::from)
                                    .map_err(Error::stream)?;
                            }
                            if payload.limit() != 0 {
                                return Err(ErrorCode::FrameError.connection(
                                    "DATA payload ended before the declared frame length",
                                ));
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            let fields = reader.decode(&qpack, frame.payload.field_section).await?;
                            message_trailers
                                .extend_fields(fields)
                                .map_err(Error::stream)?;
                            trailers = true;
                        }
                    }
                }
                body.shutdown()
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                Ok(())
            };
            let result: crate::Result<()> = tokio::select! {
                biased;
                _ = consumer_dropped => {
                    // Abandon only reception so an early response can still be sent.
                    reader.stop(ErrorCode::NoError.as_u64());
                    return;
                }
                result = receiving => result,
            };
            if let Err(failure) = result {
                let failure = if failure.is_connection() {
                    qpack.on_connection_error(failure)
                } else {
                    failure.stream()
                };
                body.error(failure);
            }
        });
        Ok(http::Request::from_parts(
            request.head,
            incoming_body(request.body, request.trailers, consumer_lifetime),
        ))
    }
}

impl<R> ReadResponse for H3ReadStream<R>
where
    R: AsyncRead + StopSending + TransportError + Unpin + Send + 'static,
{
    async fn read_response(
        self,
        request_method: http::Method,
        qpack: ArcQpack,
    ) -> crate::Result<http::Response<crate::Body>> {
        let mut reader = self;
        let mut body = crate::ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        body.on_error(reader.error_handler());
        let consumer = body.clone();
        let response = async {
            loop {
                let frame = reader.read_headers_frame().await?.ok_or_else(|| {
                    ErrorCode::RequestIncomplete
                        .stream("stream ended before final response HEADERS")
                })?;
                let fields = reader.decode(&qpack, frame.payload.field_section).await?;
                let response =
                    Response::from_fields(fields, consumer.clone()).map_err(Error::stream)?;
                if response.status().is_informational() {
                    tokio::task::yield_now().await;
                    continue;
                }
                return Ok::<_, Error>(response);
            }
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            reader.fail(failure.clone());
            qpack.error().unwrap_or(failure)
        })?;

        let body_allowed = request_method != http::Method::HEAD
            && response.status() != http::StatusCode::NO_CONTENT
            && response.status() != http::StatusCode::NOT_MODIFIED;
        let message_trailers = response.trailers.clone();
        let (consumer_lifetime, consumer_dropped) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let receiving = async {
                let mut trailers = false;
                while let Some(frame) = reader.read_next_frame(trailers).await? {
                    match frame {
                        NextFrame::Data(frame) => {
                            if !body_allowed {
                                return Err(ErrorCode::MessageError
                                    .stream("DATA is not allowed for this response"));
                            }
                            let mut payload = (&mut reader).take(frame.length.into_u64());
                            let mut chunk = bytes::BytesMut::new();
                            while payload.limit() > 0 {
                                // Keep unused slab capacity across short transport reads.
                                // Otherwise a one-byte read could retain an entire 8 KiB
                                // allocation for every queued byte.
                                if chunk.capacity() == 0 {
                                    chunk
                                        .reserve(payload.limit().min(frame::MAX_DATA_CHUNK as u64)
                                            as usize);
                                }
                                if payload.read_buf(&mut chunk).await.map_err(R::map_error)? == 0 {
                                    break;
                                }
                                body.write_bytes(chunk.split().freeze())
                                    .await
                                    .map_err(Error::from)
                                    .map_err(Error::stream)?;
                            }
                            if payload.limit() != 0 {
                                return Err(ErrorCode::FrameError.connection(
                                    "DATA payload ended before the declared frame length",
                                ));
                            }
                        }
                        NextFrame::Trailer(frame) => {
                            if !body_allowed {
                                return Err(ErrorCode::MessageError
                                    .stream("trailers are not allowed for this response"));
                            }
                            let fields = reader.decode(&qpack, frame.payload.field_section).await?;
                            message_trailers
                                .extend_fields(fields)
                                .map_err(Error::stream)?;
                            trailers = true;
                        }
                    }
                }
                body.shutdown()
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                Ok(())
            };
            let result: crate::Result<()> = tokio::select! {
                biased;
                _ = consumer_dropped => {
                    // Abandon only reception so an early response can still be sent.
                    reader.stop(ErrorCode::NoError.as_u64());
                    return;
                }
                result = receiving => result,
            };
            if let Err(failure) = result {
                let failure = if failure.is_connection() {
                    qpack.on_connection_error(failure)
                } else {
                    failure.stream()
                };
                body.error(failure);
            }
        });
        Ok(http::Response::from_parts(
            response.head,
            incoming_body(response.body, response.trailers, consumer_lifetime),
        ))
    }
}

fn incoming_body(
    window: ArcWndBuf,
    trailers: Trailers,
    consumer_lifetime: tokio::sync::oneshot::Sender<()>,
) -> Body {
    let frames = async_stream::try_stream! {
        // Capture the sender in the Body even before its first poll. Drop notifies
        // the receive task; WndBuf itself remains a neutral byte buffer.
        let _consumer_lifetime = consumer_lifetime;
        loop {
            let bytes = window.read_chunk(crate::frame::MAX_DATA_CHUNK)
                .await.map_err(Error::from_stream_io)?;
            if bytes.is_empty() { break; }
            yield http_body::Frame::data(bytes);
        }

        let fields = trailers.headers();
        if !fields.is_empty() { yield http_body::Frame::trailers(fields); }
    };
    StreamBody::new(frames)
        .map_err(|error: Error| -> BoxError { Box::new(error) })
        .boxed_unsync()
}

#[cfg(test)]
#[path = "../../tests/unit/stream/read.rs"]
mod tests;
