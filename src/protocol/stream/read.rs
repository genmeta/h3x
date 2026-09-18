use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::recv::StopSending;
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Notify,
};

use super::{Goaway, H3Stream};
use crate::{
    ArcQpack, Error, ErrorCode,
    common::{self, head},
};

/// Application-owned read direction, observed weakly by the connection.
pub struct H3ReadStream<R: StopSending> {
    pub(super) state: Arc<Mutex<Result<H3Stream<R>, Goaway>>>,
    id: u64,
    finished: Arc<Notify>,
}

impl<R: StopSending> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self::new_observed(stream_id, stream, Arc::default())
    }

    pub(super) fn new_observed(stream_id: u64, stream: R, finished: Arc<Notify>) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
            finished,
        }
    }

    pub(crate) fn close(&self, error: Error) {
        let code = error.code.as_u64();
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.stop(code));
        let finished = !was_finished && super::is_finished(&state);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        if finished {
            self.finished.notify_waiters();
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.stop(error_code));
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

impl<R: StopSending> StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + StopSending + Unpin> AsyncRead for H3ReadStream<R> {
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
        let mut inner = self.state.lock().unwrap();
        let was_finished = super::is_finished(&inner);
        let result = super::poll_io(&mut *inner, cx, |recv, cx| recv.poll_read(cx, buf));
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
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

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        self.close(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
    }
}

impl<R: AsyncRead + StopSending + Unpin + Send + 'static> H3ReadStream<R> {
    /// Read an HTTP request using the receive stream's ID and shared QPACK state.
    pub async fn read_request(self, qpack: ArcQpack) -> crate::Result<crate::IncomingRequest> {
        crate::common::request::ReadRequest::read_request(self, qpack).await
    }

    /// Start body reception after read_request_head has consumed HEADERS.
    /// `rs` and `qpack` must belong to the request whose metadata is supplied here.
    pub fn read_request_body(
        self,
        request: http::Request<()>,
        qpack: ArcQpack,
    ) -> crate::Result<crate::IncomingRequest> {
        let (parts, ()) = request.into_parts();
        let head = head::RequestHead::from(parts);
        crate::common::request::ReadRequest::read_request_body(self, head, qpack)
    }

    /// Read only initial HEADERS, leaving the receive direction with the caller.
    /// No body task is started and no bytes beyond the field section are prefetched.
    /// After success pass the same stream to read_request_body.
    /// If this future is cancelled, discard the stream: a partial header may be consumed.
    pub async fn read_request_head(
        &mut self,
        qpack: &ArcQpack,
    ) -> crate::Result<http::Request<()>> {
        let head = common::request::read_head(self, qpack).await?;
        let parts = http::request::Parts::from(head);
        Ok(http::Request::from_parts(parts, ()))
    }
}
