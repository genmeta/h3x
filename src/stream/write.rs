use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use qrecovery::send::CancelStream;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ArcH3Stream, StreamEvent, StreamEventHandler};
use crate::{
    ArcQpack, Error, TransportError,
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
            (self.events)(StreamEvent::Finished);
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
            if state.terminate(|io| io.cancel(code)) {
                events(StreamEvent::Aborted { code });
            }
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        if self.state.terminate(|io| io.cancel(error_code)) {
            (self.events)(StreamEvent::Aborted { code: error_code });
        }
    }
}

impl<W: CancelStream> CancelStream for H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        qrecovery::send::CancelStream::cancel(&mut &*self, error_code);
    }
}

impl<W: AsyncWrite + CancelStream + TransportError + Unpin> H3WriteStream<W> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        match self.state.poll_io(cx, poll) {
            Poll::Ready(Ok(value)) => {
                if finish {
                    self.finish();
                }
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Err(error)) => {
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    return Poll::Ready(Err(error));
                }
                let error = W::map_error(error);
                if self.state.finish() {
                    if error.is_connection() {
                        (self.events)(StreamEvent::Finished);
                    } else {
                        (self.events)(StreamEvent::Aborted {
                            code: error.code.as_u64(),
                        });
                    }
                }
                Poll::Ready(Err(error.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<W: AsyncWrite + CancelStream + TransportError + Unpin> AsyncWrite for H3WriteStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, true, |send, cx| send.poll_shutdown(cx))
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
        let mut body = request.body;
        body.on_error(self.error_handler());
        let producer = body.clone();
        let result: crate::Result<()> = async {
            let field_section = qpack.encode(self.stream_id(), fields)?;
            let headers = Frame::new(frame::Headers { field_section }).map_err(Error::stream)?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await.map_err(W::map_error)?;

            let mut buf = vec![0; frame::MAX_DATA_CHUNK];
            loop {
                let count = body
                    .read(&mut buf)
                    .await
                    .map_err(Error::from)
                    .map_err(Error::stream)?;
                if count == 0 {
                    break;
                }
                bytes.clear();
                bytes.put_frame(&Frame::new(Data(count)).map_err(Error::stream)?);
                self.write_all(&bytes).await.map_err(W::map_error)?;
                self.write_all(&buf[..count]).await.map_err(W::map_error)?;
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
            self.cancel(failure.code.as_u64());
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
                let mut buf = vec![0; frame::MAX_DATA_CHUNK];
                loop {
                    let count = body
                        .read(&mut buf)
                        .await
                        .map_err(Error::from)
                        .map_err(Error::stream)?;
                    if count == 0 {
                        break;
                    }
                    bytes.clear();
                    bytes.put_frame(&Frame::new(Data(count)).map_err(Error::stream)?);
                    self.write_all(&bytes).await.map_err(W::map_error)?;
                    self.write_all(&buf[..count]).await.map_err(W::map_error)?;
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
            self.cancel(failure.code.as_u64());
            producer.error(failure.clone());
            qpack.error().unwrap_or(failure)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;
    use crate::ErrorCode;

    #[derive(Clone, Default)]
    struct Io {
        bytes: Arc<Mutex<Vec<u8>>>,
        cancels: Arc<Mutex<Vec<u64>>>,
        shutdowns: Arc<AtomicUsize>,
    }

    impl AsyncWrite for Io {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    impl CancelStream for Io {
        fn cancel(&mut self, code: u64) {
            self.cancels.lock().unwrap().push(code);
        }
    }

    impl TransportError for Io {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }

    fn events() -> StreamEventHandler {
        Arc::new(|_| {})
    }

    struct FailingIo(Error);

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(self.0.clone().into()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(self.0.clone().into()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(self.0.clone().into()))
        }
    }

    impl CancelStream for FailingIo {
        fn cancel(&mut self, _: u64) {}
    }

    impl TransportError for FailingIo {
        fn map_error(error: io::Error) -> Error {
            Error::from_stream_io(error)
        }
    }

    #[tokio::test]
    async fn terminal_write_errors_report_their_scope() {
        for (error, expected) in [
            (
                ErrorCode::RequestCancelled.stream("stream stopped"),
                StreamEvent::Aborted {
                    code: ErrorCode::RequestCancelled.as_u64(),
                },
            ),
            (
                ErrorCode::InternalError.connection("connection failed"),
                StreamEvent::Finished,
            ),
        ] {
            let reported = Arc::new(Mutex::new(Vec::new()));
            let captured = reported.clone();
            let mut stream = H3WriteStream::new(
                4,
                FailingIo(error.clone()),
                Arc::new(move |event| captured.lock().unwrap().push(event)),
            );
            let returned = Error::from_stream_io(stream.write_all(b"x").await.unwrap_err());
            assert_eq!(returned, error);
            assert_eq!(reported.lock().unwrap().as_slice(), [expected]);
        }
    }

    #[tokio::test]
    async fn write_shutdown_notifies_finish_once() {
        let io = Io::default();
        let bytes = io.bytes.clone();
        let cancels = io.cancels.clone();
        let shutdowns = io.shutdowns.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3WriteStream::new(
            4,
            io,
            Arc::new(move |event| {
                if matches!(event, StreamEvent::Finished) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        let _registered = stream.state.clone();
        assert_eq!(stream.stream_id(), 4);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        AsyncWriteExt::shutdown(&mut stream).await.unwrap();
        assert_eq!(&*bytes.lock().unwrap(), b"hello");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(7);
        assert!(cancels.lock().unwrap().is_empty());
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reject_and_explicit_cancel_report_expected_codes() {
        fn reject<W: CancelStream>(stream: &H3WriteStream<W>) -> bool {
            stream
                .state
                .goaway(|io| io.cancel(ErrorCode::RequestRejected.as_u64()))
        }

        let io = Io::default();
        let cancels = io.cancels.clone();
        let mut stream = H3WriteStream::new(8, io, events());
        assert!(reject(&stream));
        assert!(!reject(&stream));
        assert_eq!(
            &*cancels.lock().unwrap(),
            &[ErrorCode::RequestRejected.as_u64()]
        );
        assert_eq!(
            stream.write_all(b"x").await.unwrap_err().kind(),
            io::ErrorKind::Other
        );

        let io = Io::default();
        let cancels = io.cancels.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let stream = H3WriteStream::new(
            12,
            io,
            Arc::new(move |event| {
                if matches!(event, StreamEvent::Finished | StreamEvent::Aborted { .. }) {
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        (&stream).cancel(9);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(10);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
    }

    #[tokio::test]
    async fn message_writers_shutdown_the_underlying_send_stream() {
        let mut request_body = crate::ArcWndBuf::new(1);
        request_body.shutdown().await.unwrap();
        let request: Request<crate::W> = http::Request::builder()
            .method(http::Method::GET)
            .uri("https://example.com/")
            .body(request_body)
            .unwrap()
            .into();
        let request_io = Io::default();
        let request_shutdowns = request_io.shutdowns.clone();
        let request_completed = Arc::new(AtomicUsize::new(0));
        let completed = request_completed.clone();
        let shutdowns = request_shutdowns.clone();
        let request_stream = H3WriteStream::new(
            0,
            request_io,
            Arc::new(move |event| {
                if matches!(event, StreamEvent::Finished) {
                    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        request_stream
            .write_request(request, crate::qpack::tests::qpack())
            .await
            .unwrap();
        assert_eq!(request_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(request_completed.load(Ordering::SeqCst), 1);

        let mut response_body = crate::ArcWndBuf::new(1);
        response_body.shutdown().await.unwrap();
        let response: Response<crate::W> = http::Response::new(response_body).into();
        let response_io = Io::default();
        let response_shutdowns = response_io.shutdowns.clone();
        let response_completed = Arc::new(AtomicUsize::new(0));
        let completed = response_completed.clone();
        let shutdowns = response_shutdowns.clone();
        let response_stream = H3WriteStream::new(
            0,
            response_io,
            Arc::new(move |event| {
                if matches!(event, StreamEvent::Finished) {
                    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        response_stream
            .write_response(response, http::Method::GET, crate::qpack::tests::qpack())
            .await
            .unwrap();
        assert_eq!(response_shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(response_completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn body_cancellation_aborts_request_and_response_writers() {
        let request_body = crate::ArcWndBuf::new(1);
        let request_producer = request_body.clone();
        let request: Request<crate::W> = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://example.com/upload")
            .body(request_body)
            .unwrap()
            .into();
        let request_io = Io::default();
        let request_cancels = request_io.cancels.clone();
        let request_writer = tokio::spawn(
            H3WriteStream::new(0, request_io, events())
                .write_request(request, crate::qpack::tests::qpack()),
        );
        tokio::task::yield_now().await;
        request_producer.cancel(ErrorCode::RequestCancelled.as_u64());
        assert_eq!(
            request_writer.await.unwrap().unwrap_err().code,
            ErrorCode::RequestCancelled
        );
        assert_eq!(
            &*request_cancels.lock().unwrap(),
            &[ErrorCode::RequestCancelled.as_u64()]
        );

        let response_body = crate::ArcWndBuf::new(1);
        let response_producer = response_body.clone();
        let response: Response<crate::W> = http::Response::new(response_body).into();
        let response_io = Io::default();
        let response_cancels = response_io.cancels.clone();
        let response_writer =
            tokio::spawn(H3WriteStream::new(0, response_io, events()).write_response(
                response,
                http::Method::GET,
                crate::qpack::tests::qpack(),
            ));
        tokio::task::yield_now().await;
        response_producer.cancel(ErrorCode::RequestCancelled.as_u64());
        assert_eq!(
            response_writer.await.unwrap().unwrap_err().code,
            ErrorCode::RequestCancelled
        );
        assert_eq!(
            &*response_cancels.lock().unwrap(),
            &[ErrorCode::RequestCancelled.as_u64()]
        );
    }

    #[tokio::test]
    async fn qpack_failure_reaches_request_and_response_producers() {
        let qpack = crate::qpack::tests::qpack();
        qpack.on_connection_error(ErrorCode::InternalError.connection("qpack failed"));

        let request_body = crate::ArcWndBuf::new(1);
        let mut request_producer = request_body.clone();
        let request: Request<crate::W> = http::Request::builder()
            .uri("https://example.com/")
            .body(request_body)
            .unwrap()
            .into();
        let mut request_stream = H3WriteStream::new(0, Io::default(), events());
        request_stream.cancel(ErrorCode::NoError.as_u64());
        let error = request_stream
            .write_request(request, qpack.clone())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(
            Error::from(request_producer.write_all(b"x").await.unwrap_err()).code,
            ErrorCode::InternalError
        );

        let response_body = crate::ArcWndBuf::new(1);
        let mut response_producer = response_body.clone();
        let response: Response<crate::W> = http::Response::new(response_body).into();
        let error = H3WriteStream::new(0, Io::default(), events())
            .write_response(response, http::Method::GET, qpack)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(
            Error::from(response_producer.write_all(b"x").await.unwrap_err()).code,
            ErrorCode::InternalError
        );
    }
}
