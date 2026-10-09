use std::{
    io, mem,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::BodyExt;
use qrecovery::send::CancelStream;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{ArcH3Stream, H3Stream, StreamEventHandler};
use crate::{
    ArcQpack, ArcWndBuf, Body, Error, ErrorCode, Result, Trailers, TransportError,
    common::{
        Write,
        request::{Request, WriteRequest},
        response::{Response, WriteResponse},
    },
    frame::{self, Data, Frame, Write as _},
    qpack::Field,
};

const SEND_WINDOW_BYTES: usize = 64 * 1024;

/// Application-owned write direction, sharing state with the connection registry.
/// `flush()` forwards to the transport and waits for peer acknowledgement.
/// Message writers send HEADERS and DATA without flushing each frame, then
/// finish with `shutdown()` to send FIN and wait for acknowledgement.
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
        let unfinished = matches!(
            self.state.0.lock().unwrap().as_ref(),
            Ok(H3Stream::Idle(_) | H3Stream::Polling(_, _))
        );
        // Invoke cancellation after releasing the state lock; callbacks re-enter the registry.
        if unfinished {
            self.cancel(ErrorCode::RequestCancelled.as_u64());
        }
    }
}

impl<W, B> WriteRequest<B> for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
    B: http_body::Body<Data = bytes::Bytes> + Send,
    B::Error: Into<crate::BoxError>,
{
    async fn write_request(mut self, request: http::Request<B>, qpack: ArcQpack) -> Result<()> {
        let (head, source) = request.into_parts();
        let request = Request::<Write>::from(http::Request::from_parts(
            head,
            ArcWndBuf::new(SEND_WINDOW_BYTES),
        ));
        let fields = request.fields();
        let window = request.body;
        let trailers = request.trailers;
        window.on_error(self.error_handler());

        let sending = self.write_frames(fields, &window, &trailers, &qpack);
        let forwarding = forward_body(source, window.clone(), trailers.clone());
        // These futures share the caller's task; failure drops the other future.
        match tokio::try_join!(biased; sending, forwarding) {
            Ok(_) => Ok(()),
            Err(error) => {
                let error = if error.is_connection() {
                    qpack.on_connection_error(error)
                } else {
                    error.stream()
                };
                self.fail(error.clone());
                window.error(error.clone());
                Err(qpack.error().unwrap_or(error))
            }
        }
    }
}

impl<W> WriteRequest<ArcWndBuf> for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
{
    fn write_request(
        mut self,
        request: http::Request<ArcWndBuf>,
        qpack: ArcQpack,
    ) -> impl Future<Output = Result<()>> + Send {
        let request = Request::<Write>::from(request);
        let fields = request.fields();
        let window = request.body;
        let trailers = request.trailers;
        // Bind cancellation before the future is first polled, so a caller can
        // reset the window immediately without losing its requested error code.
        window.on_error(self.error_handler());
        async move {
            match self.write_frames(fields, &window, &trailers, &qpack).await {
                Ok(()) => Ok(()),
                Err(error) => {
                    let error = if error.is_connection() {
                        qpack.on_connection_error(error)
                    } else {
                        error.stream()
                    };
                    self.fail(error.clone());
                    window.error(error.clone());
                    Err(qpack.error().unwrap_or(error))
                }
            }
        }
    }
}

impl<W> WriteResponse for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
{
    async fn write_response(
        mut self,
        response: http::Response<Body>,
        method: http::Method,
        qpack: ArcQpack,
    ) -> Result<()> {
        let (head, source) = response.into_parts();
        let send_body = method != http::Method::HEAD
            && head.status != http::StatusCode::NO_CONTENT
            && head.status != http::StatusCode::NOT_MODIFIED;
        let source = if send_body {
            source
        } else {
            // Discard forbidden content without ever polling the application body.
            drop(source);
            Body::default()
        };
        let response = Response::<Write>::from(http::Response::from_parts(
            head,
            ArcWndBuf::new(SEND_WINDOW_BYTES),
        ));
        let fields = response.fields();
        let window = response.body;
        let trailers = response.trailers;
        window.on_error(self.error_handler());

        let sending = self.write_frames(fields, &window, &trailers, &qpack);
        let forwarding = forward_body(source, window.clone(), trailers.clone());
        // These futures share the caller's task; failure drops the other future.
        match tokio::try_join!(biased; sending, forwarding) {
            Ok(_) => Ok(()),
            Err(error) => {
                let error = if error.is_connection() {
                    qpack.on_connection_error(error)
                } else {
                    error.stream()
                };
                self.fail(error.clone());
                window.error(error.clone());
                Err(qpack.error().unwrap_or(error))
            }
        }
    }
}

impl<W> H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + TransportError + Unpin + Send + 'static,
{
    async fn write_frames(
        &mut self,
        fields: Vec<Field>,
        window: &ArcWndBuf,
        trailers: &Trailers,
        qpack: &ArcQpack,
    ) -> Result<()> {
        let field_section = qpack.encode(self.stream_id(), fields)?;
        let headers = Frame::new(frame::Headers { field_section }).map_err(Error::stream)?;
        let mut encoded = Vec::new();
        encoded.put_frame(&headers);
        self.write_all(&encoded).await.map_err(W::map_error)?;

        loop {
            let chunk = window
                .read_chunk(frame::MAX_DATA_CHUNK)
                .await
                .map_err(Error::from_stream_io)?;
            if chunk.is_empty() {
                break;
            }
            encoded.clear();
            encoded.put_frame(&Frame::new(Data(chunk.len())).map_err(Error::stream)?);
            self.write_all(&encoded).await.map_err(W::map_error)?;
            self.write_all(&chunk).await.map_err(W::map_error)?;
        }

        // The producer installs trailers before publishing window EOF.
        let fields = trailers.fields();
        if !fields.is_empty() {
            let field_section = qpack.encode(self.stream_id(), fields)?;
            let headers = Frame::new(frame::Headers { field_section }).map_err(Error::stream)?;
            encoded.clear();
            encoded.put_frame(&headers);
            self.write_all(&encoded).await.map_err(W::map_error)?;
        }
        self.shutdown().await.map_err(W::map_error)
    }
}

async fn forward_body<B>(source: B, mut window: ArcWndBuf, trailers: Trailers) -> Result<()>
where
    B: http_body::Body<Data = bytes::Bytes>,
    B::Error: Into<crate::BoxError>,
{
    let mut source = std::pin::pin!(source);
    let mut has_trailers = false;
    loop {
        let frame = match source.frame().await {
            Some(frame) => frame.map_err(|source| {
                let error = ErrorCode::RequestCancelled
                    .stream("outgoing body failed")
                    .with_source(source.into());
                window.error(error.clone());
                error
            })?,
            None => break,
        };
        if has_trailers {
            let error = ErrorCode::MessageError.stream("body frame after trailers");
            window.error(error.clone());
            return Err(error);
        }
        match frame.into_data() {
            Ok(data) => window
                .write_bytes(data)
                .await
                .map_err(Error::from_stream_io)?,
            Err(frame) => {
                if let Ok(fields) = frame.into_trailers() {
                    has_trailers = true;
                    for (name, value) in &fields {
                        trailers.append(name.clone(), value.clone());
                    }
                }
            }
        }
    }
    // Publish EOF only after all trailer fields have been installed.
    window.shutdown().await.map_err(Error::from_stream_io)
}

#[cfg(test)]
#[path = "../../tests/unit/stream/write.rs"]
mod tests;
