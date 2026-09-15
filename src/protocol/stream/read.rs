use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use super::{StreamState, StreamStatus};
use crate::Error;

/// Application-owned read direction, observed weakly by the connection.
pub struct H3ReadStream<R> {
    id: u64,
    pub(super) state: Arc<Mutex<StreamState<R>>>,
}

impl<R> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(StreamState::new(stream))),
        }
    }

    pub(crate) fn close(&self, error: Error) {
        let wakers = self.state.lock().unwrap().close(error, |_| {});
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: qrecovery::recv::StopSending> qrecovery::recv::StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let wakers = self
            .state
            .lock()
            .unwrap()
            .close(Error::H3_REQUEST_CANCELLED, |io| io.stop(error_code));
        for waker in wakers.into_iter().flatten() {
            waker.wake();
        }
    }
}

impl<R: qrecovery::recv::StopSending> qrecovery::recv::StopSending for H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for H3ReadStream<R> {
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
        if matches!(inner.status, StreamStatus::Finished) {
            return Poll::Ready(Ok(()));
        }
        let result = inner.poll_io(cx, |recv, cx| recv.poll_read(cx, buf));
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            inner.status = StreamStatus::Finished;
        }
        let waker = if inner.is_finished() {
            inner.finished_waker.take()
        } else {
            None
        };
        drop(inner);
        if let Some(waker) = waker {
            waker.wake();
        }
        result
    }
}

impl<R> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        self.close(Error::H3_REQUEST_CANCELLED);
    }
}
