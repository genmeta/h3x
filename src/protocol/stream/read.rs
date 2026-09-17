use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::recv::StopSending;
use tokio::io::{AsyncRead, ReadBuf};

use super::{Goaway, H3Stream};
use crate::{Error, ErrorCode};

/// Application-owned read direction, observed weakly by the connection.
pub struct H3ReadStream<R: StopSending> {
    id: u64,
    pub(super) state: Arc<Mutex<Result<H3Stream<R>, Goaway>>>,
}

impl<R: StopSending> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
        }
    }

    pub(crate) fn close(&self, error: Error) {
        let code = error.code.as_u64();
        let mut state = self.state.lock().unwrap();
        let waker = super::terminate(&mut state, |io| io.stop(code));
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<R: StopSending> StopSending for &H3ReadStream<R> {
    fn stop(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let waker = super::terminate(&mut state, |io| io.stop(error_code));
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
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
        let result = super::poll_io(&mut *inner, cx, |recv, cx| recv.poll_read(cx, buf));
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            super::finish(&mut *inner);
        }
        drop(inner);
        result
    }
}

impl<R: StopSending> Drop for H3ReadStream<R> {
    fn drop(&mut self) {
        self.close(ErrorCode::H3_REQUEST_CANCELLED.reason("request cancelled"));
    }
}
