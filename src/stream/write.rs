use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use qrecovery::send::CancelStream;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{ArcH3Stream, H3Stream, StreamEventHandler};
use crate::{
    ArcQpack, Error, ErrorCode, TransportError,
    common::{
        request::{Request, WriteRequest},
        response::{Response, WriteResponse},
    },
    frame::{self, Data, Frame, Write as _},
    qpack::Field,
};

/// Application-owned write direction, sharing state with the connection registry.
pub struct H3WriteStream<W: CancelStream> {
    pub(super) state: ArcH3Stream<W>,
    events: StreamEventHandler,
    id: u64,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub(crate) fn new(stream_id: u64, stream: W, events: StreamEventHandler) -> Self {
        Self {
            state: ArcH3Stream::new(stream),
            id: stream_id,
            events,
        }
    }

    fn finish(&self) {
        if self.state.finish() {
            (self.events)(Ok(()));
        }
    }

    fn fail(&self, error: Error) {
        let code = error.code.as_u64();
        if self.state.fail(error.clone(), |io| io.cancel(code)) {
            (self.events)(Err(error));
        }
    }

    fn error_handler(&self) -> impl FnOnce(Error) + Send + 'static
    where
        W: Send + 'static,
    {
        let state = self.state.clone();
        let events = self.events.clone();
        move |error| {
            let code = error.code.as_u64();
            if state.fail(error.clone(), |io| io.cancel(code)) {
                events(Err(error));
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        let error = ErrorCode::try_from(error_code)
            .unwrap_or(ErrorCode::InternalError)
            .stream(format!("write stream cancelled with code 0x{error_code:x}"));
        self.fail(error);
    }
}

impl<W: CancelStream> CancelStream for H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        qrecovery::send::CancelStream::cancel(&mut &*self, error_code);
    }
}

impl<W: AsyncWrite + CancelStream + TransportError + Unpin> AsyncWrite for H3WriteStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state.0.lock().unwrap();
        let stream = match state.as_mut() {
            Err(error) => return Poll::Ready(Err(error.clone().into())),
            Ok(H3Stream::Finished) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Ok(stream) => stream,
        };
        let mut io = match mem::replace(stream, H3Stream::Transition) {
            H3Stream::Idle(io) | H3Stream::Polling(io, _) => io,
            H3Stream::Finished | H3Stream::Transition => unreachable!(),
        };
        match Pin::new(&mut io).poll_write(cx, buf) {
            Poll::Pending => {
                *stream = H3Stream::Polling(io, cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(value)) => {
                *stream = H3Stream::Idle(io);
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
                let error = W::map_error(error);
                *state = Err(error.clone());
                drop(io);
                drop(state);
                (self.events)(Err(error.clone()));
                Poll::Ready(Err(error.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
        match Pin::new(&mut io).poll_flush(cx) {
            Poll::Pending => {
                *stream = H3Stream::Polling(io, cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(value)) => {
                *stream = H3Stream::Idle(io);
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
                let error = W::map_error(error);
                *state = Err(error.clone());
                drop(io);
                drop(state);
                (self.events)(Err(error.clone()));
                Poll::Ready(Err(error.into()))
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
        match Pin::new(&mut io).poll_shutdown(cx) {
            Poll::Pending => {
                *stream = H3Stream::Polling(io, cx.waker().clone());
                Poll::Pending
            }
            Poll::Ready(Ok(value)) => {
                *stream = H3Stream::Finished;
                drop(io);
                drop(state);
                (self.events)(Ok(()));
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
                let error = W::map_error(error);
                *state = Err(error.clone());
                drop(io);
                drop(state);
                (self.events)(Err(error.clone()));
                Poll::Ready(Err(error.into()))
            }
        }
    }
}

impl<W: CancelStream> Drop for H3WriteStream<W> {
    fn drop(&mut self) {
        self.finish();
    }
}

impl<W> WriteRequest for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
{
    async fn write_request(
        mut self,
        request: Request<crate::W>,
        qpack: ArcQpack,
    ) -> crate::Result<()> {
        let mut fields = Vec::with_capacity(request.head.headers.len() + 5);
        for (name, value) in request.pseudo_headers() {
            if let Some(value) = value {
                fields.push(Field {
                    name: Bytes::from_static(name),
                    value: Bytes::copy_from_slice(value.as_bytes()),
                    never_index: false,
                });
            }
        }
        fields.extend(request.head.headers.iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: value.is_sensitive(),
        }));
        let trailers = request.trailers.clone();
        let body = request.body;
        body.on_error(self.error_handler());
        let producer = body.clone();
        let result: crate::Result<()> = async {
            let field_section = qpack.encode(self.stream_id(), fields)?;
            let headers = Frame::new(frame::Headers { field_section }).map_err(Error::stream)?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await.map_err(W::map_error)?;

            loop {
                let chunk = body
                    .read_chunk(frame::MAX_DATA_CHUNK)
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                if chunk.is_empty() {
                    break;
                }
                bytes.clear();
                bytes.put_frame(&Frame::new(Data(chunk.len())).map_err(Error::stream)?);
                self.write_all(&bytes).await.map_err(W::map_error)?;
                self.write_all(&chunk).await.map_err(W::map_error)?;
            }
            let trailer_fields = trailers.fields();
            if !trailer_fields.is_empty() {
                bytes.clear();
                let field_section = qpack.encode(self.stream_id(), trailer_fields)?;
                bytes.put_frame(
                    &Frame::new(frame::Headers { field_section }).map_err(Error::stream)?,
                );
                self.write_all(&bytes).await.map_err(W::map_error)?;
            }
            self.shutdown().await.map_err(W::map_error)?;
            Ok::<_, Error>(())
        }
        .await;
        result.map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            self.fail(failure.clone());
            producer.error(failure.clone());
            qpack.error().unwrap_or(failure)
        })
    }
}

impl<W> WriteResponse for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
{
    async fn write_response(
        mut self,
        response: Response<crate::W>,
        request_method: http::Method,
        qpack: ArcQpack,
    ) -> crate::Result<()> {
        let send_body = request_method != http::Method::HEAD
            && response.head.status != http::StatusCode::NO_CONTENT
            && response.head.status != http::StatusCode::NOT_MODIFIED;
        let mut fields = Vec::with_capacity(response.head.headers.len() + 1);
        for (name, value) in response.pseudo_headers() {
            if let Some(value) = value {
                fields.push(Field {
                    name: Bytes::from_static(name),
                    value: Bytes::copy_from_slice(value.as_bytes()),
                    never_index: false,
                });
            }
        }
        fields.extend(response.head.headers.iter().map(|(name, value)| Field {
            name: Bytes::copy_from_slice(name.as_str().as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
            never_index: value.is_sensitive(),
        }));
        let trailers = response.trailers.clone();
        let mut body = response.body;
        body.on_error(self.error_handler());
        let producer = body.clone();
        async {
            if !send_body {
                body.shutdown()
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
            }
            let field_section = qpack.encode(self.stream_id(), fields)?;
            let headers = Frame::new(frame::Headers { field_section }).map_err(Error::stream)?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await.map_err(W::map_error)?;

            if send_body {
                loop {
                    let chunk = body
                        .read_chunk(frame::MAX_DATA_CHUNK)
                        .await
                        .map_err(Error::from)
                        .map_err(Error::stream)?;
                    if chunk.is_empty() {
                        break;
                    }
                    bytes.clear();
                    bytes.put_frame(&Frame::new(Data(chunk.len())).map_err(Error::stream)?);
                    self.write_all(&bytes).await.map_err(W::map_error)?;
                    self.write_all(&chunk).await.map_err(W::map_error)?;
                }
            }
            if send_body {
                let trailer_fields = trailers.fields();
                if !trailer_fields.is_empty() {
                    bytes.clear();
                    let field_section = qpack.encode(self.stream_id(), trailer_fields)?;
                    bytes.put_frame(
                        &Frame::new(frame::Headers { field_section }).map_err(Error::stream)?,
                    );
                    self.write_all(&bytes).await.map_err(W::map_error)?;
                }
            }
            self.shutdown().await.map_err(W::map_error)?;
            Ok::<_, Error>(())
        }
        .await
        .map_err(|failure| {
            let failure = if failure.is_connection() {
                qpack.on_connection_error(failure)
            } else {
                failure.stream()
            };
            self.fail(failure.clone());
            producer.error(failure.clone());
            qpack.error().unwrap_or(failure)
        })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/stream/write.rs"]
mod tests;
