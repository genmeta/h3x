use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use qrecovery::send::CancelStream;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Goaway, H3Stream};
use crate::{
    ArcQpack, Error, ErrorCode, Result,
    common::message::{Message, PesudoHeaders, WriteMessage},
    frame::{self, Data, Frame, Write as _},
};

/// Application-owned write direction, sharing state with its registered handle.
pub struct H3WriteStream<W: CancelStream> {
    finish_cb: Box<dyn Fn() + Send + Sync>,
    id: u64,
    pub(super) state: Arc<Mutex<std::result::Result<H3Stream<W>, Goaway>>>,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
            finish_cb: Box::new(|| {}),
        }
    }

    /// Registry handle: completion is reported by the application handle only.
    pub(super) fn registered(&self) -> Self {
        Self {
            id: self.id,
            state: self.state.clone(),
            finish_cb: Box::new(|| {}),
        }
    }

    pub(super) fn on_finish(&mut self, callback: impl Fn() + Send + Sync + 'static) {
        self.finish_cb = Box::new(callback);
    }

    pub(crate) fn shutdown(&self) {
        (self.finish_cb)();
    }

    pub(super) fn reject(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let changed = !super::is_finished(&state);
        let waker = super::goaway(&mut state, |io| {
            io.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64())
        });
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        changed
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
            H3WriteStream::shutdown(self);
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
            H3WriteStream::shutdown(self);
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

impl<W, P> WriteMessage<P> for H3WriteStream<W>
where
    W: AsyncWrite + CancelStream + Unpin,
    P: PesudoHeaders + Into<Message>,
{
    async fn write_message(mut self, message: P, qpack: ArcQpack) -> Result<()> {
        let Message { head, body } = message.into();
        let mut body = body;
        let producer = body.clone();
        let sending = async {
            let headers = head.encode_headers(self.stream_id(), &qpack)?;
            let mut bytes = Vec::new();
            bytes.put_frame(&headers);
            self.write_all(&bytes).await?;
            let mut buf = vec![0; frame::MAX_DATA_CHUNK];
            loop {
                let count = body.read(&mut buf).await?;
                if count == 0 {
                    break;
                }
                bytes.clear();
                bytes.put_frame(&Frame::new(Data(count))?);
                self.write_all(&bytes).await?;
                self.write_all(&buf[..count]).await?;
            }
            AsyncWriteExt::shutdown(&mut self).await?;
            Ok::<_, Error>(())
        };
        let result = sending.await.inspect_err(|error| {
            (&self).cancel(error.code.as_u64());
            producer.on_error(error.clone());
            qpack.on_error(self.stream_id(), error.clone());
        });
        H3WriteStream::shutdown(&self);
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;

    #[derive(Clone, Default)]
    struct Io {
        bytes: Arc<Mutex<Vec<u8>>>,
        cancels: Arc<Mutex<Vec<u64>>>,
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
            Poll::Ready(Ok(()))
        }
    }

    impl CancelStream for Io {
        fn cancel(&mut self, code: u64) {
            self.cancels.lock().unwrap().push(code);
        }
    }

    #[tokio::test]
    async fn write_flush_shutdown_and_cancel_transition_once() {
        let io = Io::default();
        let bytes = io.bytes.clone();
        let cancels = io.cancels.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3WriteStream::new(4, io);
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        let _registered = stream.registered();
        assert_eq!(stream.stream_id(), 4);
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        AsyncWriteExt::shutdown(&mut stream).await.unwrap();
        assert_eq!(&*bytes.lock().unwrap(), b"hello");
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(7);
        assert!(cancels.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reject_and_explicit_cancel_report_expected_codes() {
        let io = Io::default();
        let cancels = io.cancels.clone();
        let mut stream = H3WriteStream::new(8, io);
        assert!(stream.reject());
        assert!(!stream.reject());
        assert_eq!(
            &*cancels.lock().unwrap(),
            &[ErrorCode::H3_REQUEST_REJECTED.as_u64()]
        );
        assert_eq!(
            stream.write_all(b"x").await.unwrap_err().kind(),
            io::ErrorKind::Other
        );

        let io = Io::default();
        let cancels = io.cancels.clone();
        let completed = Arc::new(AtomicUsize::new(0));
        let count = completed.clone();
        let mut stream = H3WriteStream::new(12, io);
        stream.on_finish(move || {
            count.fetch_add(1, Ordering::SeqCst);
        });
        (&stream).cancel(9);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
        assert_eq!(completed.load(Ordering::SeqCst), 1);
        (&stream).cancel(10);
        assert_eq!(&*cancels.lock().unwrap(), &[9]);
    }
}
