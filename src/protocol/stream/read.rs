use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, ReadBuf};

use super::{StreamState, bi::BiStream};
use crate::Error;
#[cfg(test)]
use crate::protocol::frame::Goaway;

/// Read handle for a stream owned by the connection.
/// `W` is the paired transport writer; standalone readers use `()`.
pub struct H3ReadStream<R, W = ()> {
    pub(super) stream: Arc<BiStream<R, W>>,
}

impl<R> H3ReadStream<R> {
    pub fn new(stream_id: u64, stream: R) -> Self {
        Self {
            stream: Arc::new(BiStream::new(
                stream_id,
                StreamState::Idle(stream),
                StreamState::Closed(Error::H3_NO_ERROR),
            )),
        }
    }
}

impl<R, W> H3ReadStream<R, W> {
    pub fn stream_id(&self) -> u64 {
        self.stream.id
    }
}

impl<R: AsyncRead + Unpin, W> AsyncRead for H3ReadStream<R, W> {
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
        let mut state = self.stream.recv.lock().unwrap();
        if matches!(*state, StreamState::Finished) {
            return Poll::Ready(Ok(()));
        }
        let result = state.poll_io(cx, |recv, cx| recv.poll_read(cx, buf));
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() == before {
            state.terminate(StreamState::Finished);
        }
        result
    }
}

impl<R, W> Drop for H3ReadStream<R, W> {
    fn drop(&mut self) {
        self.stream
            .terminate_read(StreamState::Closed(Error::H3_REQUEST_CANCELLED));
    }
}

#[cfg(test)]
impl<R, W> H3ReadStream<R, W> {
    pub(crate) fn recv_goaway(&mut self, goaway: Goaway) {
        self.stream.terminate_read(StreamState::Goaway(goaway));
    }
}
