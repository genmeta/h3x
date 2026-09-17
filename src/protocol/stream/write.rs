use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::send::CancelStream;
use tokio::{io::AsyncWrite, sync::Notify};

use super::{Goaway, H3Stream};
use crate::ErrorCode;

/// Application-owned write direction, observed weakly by the connection.
pub struct H3WriteStream<W: CancelStream> {
    id: u64,
    pub(super) state: Arc<Mutex<Result<H3Stream<W>, Goaway>>>,
    finished: Arc<Notify>,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self::new_observed(stream_id, stream, Arc::default())
    }

    pub(super) fn new_observed(stream_id: u64, stream: W, finished: Arc<Notify>) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
            finished,
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.cancel(error_code));
        let finished = !was_finished && super::is_finished(&state);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        if finished {
            self.finished.notify_waiters();
        }
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> H3WriteStream<W> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        let mut inner = self.state.lock().unwrap();
        let was_finished = super::is_finished(&inner);
        let result = super::poll_io(&mut *inner, cx, poll);
        if finish && matches!(result, Poll::Ready(Ok(_))) {
            super::finish(&mut *inner);
        }
        let finished = !was_finished && super::is_finished(&inner);
        drop(inner);
        if finished {
            self.finished.notify_waiters();
        }
        result
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> AsyncWrite for H3WriteStream<W> {
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
        (&*self).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::{
        ArcQpack, Settings,
        common::{request::WriteRequest as _, response::WriteResponse as _},
    };

    #[derive(Default)]
    struct Output(Vec<u8>);

    impl CancelStream for Output {
        fn cancel(&mut self, _: u64) {}
    }

    impl AsyncWrite for Output {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn qpack() -> ArcQpack {
        ArcQpack::new(&Settings::new(65536, 0, 0).unwrap()).unwrap()
    }

    fn bytes(ws: &H3WriteStream<Output>) -> Vec<u8> {
        match ws.state.lock().unwrap().as_ref().unwrap() {
            H3Stream::Idle(io) | H3Stream::Finished(io) | H3Stream::Polling(io, _) => io.0.clone(),
            H3Stream::Transition => unreachable!(),
        }
    }

    #[tokio::test]
    async fn streaming_http_and_connect_share_body_completion() {
        for (method, uri) in [
            (http::Method::POST, "https://example.com/"),
            (http::Method::CONNECT, "example.com:443"),
        ] {
            let mut producer = crate::ArcWndBuf::new(1024);
            producer.write_all(b"abc").await.unwrap();
            producer.shutdown().await.unwrap();
            let request = http::Request::builder()
                .method(method)
                .uri(uri)
                .body(producer)
                .unwrap()
                .into();
            let mut ws = H3WriteStream::new(0, Output::default());
            let mode = ws.write_request_head(&request, &qpack()).await.unwrap();
            ws.flush().await.unwrap();
            let head = bytes(&ws);
            ws.write_request_streaming_body(&request, mode)
                .await
                .unwrap();
            let output = bytes(&ws);
            assert_eq!(&output[..head.len()], head.as_slice());
            assert_eq!(&output[head.len()..], b"\x00\x03abc");
            assert!(matches!(
                ws.state.lock().unwrap().as_ref().unwrap(),
                H3Stream::Finished(_)
            ));
        }
    }

    #[tokio::test]
    async fn unified_headers_support_streaming_connect() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(crate::ArcWndBuf::new(1024))
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        let mode = ws.write_request_head(&request, &qpack()).await.unwrap();
        assert_eq!(mode, crate::common::body::ContentType::Connect);
        assert!(!bytes(&ws).is_empty());

        let response = http::Response::builder()
            .status(200)
            .body(crate::ArcWndBuf::new(1024))
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        let mode = ws
            .write_response_head(&response, &qpack(), &http::Method::CONNECT)
            .await
            .unwrap();
        assert_eq!(mode, crate::common::body::ContentType::Connect);
        assert!(!bytes(&ws).is_empty());
    }

    #[tokio::test]
    async fn buffered_connect_still_writes_no_headers() {
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(Bytes::new())
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        let error = ws.write_request_head(&request, &qpack()).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
        assert!(bytes(&ws).is_empty());
    }

    #[tokio::test]
    async fn invalid_buffered_request_writes_no_headers() {
        let request = http::Request::builder()
            .uri("https://example.com/")
            .header("content-length", "4")
            .body(Bytes::from_static(b"abc"))
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        let error = ws.write_request_head(&request, &qpack()).await.unwrap_err();
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
        assert!(bytes(&ws).is_empty());
    }

    #[tokio::test]
    async fn forbidden_response_body_writes_no_headers() {
        let response = http::Response::builder()
            .status(204)
            .body(Bytes::from_static(b"abc"))
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        let error = ws
            .write_response_head(&response, &qpack(), &http::Method::GET)
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
        assert!(bytes(&ws).is_empty());
    }

    #[tokio::test]
    async fn buffered_request_sends_headers_then_data() {
        let request = http::Request::builder()
            .uri("https://example.com/")
            .header("content-length", "3")
            .body(Bytes::from_static(b"abc"))
            .unwrap()
            .into();
        let mut ws = H3WriteStream::new(0, Output::default());
        ws.write_request_head(&request, &qpack()).await.unwrap();
        let head = bytes(&ws);
        assert_eq!(head[0], 1); // HEADERS
        ws.write_request_bytes_body(&request).await.unwrap();
        ws.shutdown().await.unwrap();
        let output = bytes(&ws);
        assert_eq!(&output[..head.len()], head.as_slice());
        assert_eq!(&output[head.len()..], b"\x00\x03abc"); // DATA
    }
}
