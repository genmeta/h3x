use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A bounded FIFO with one pending reader and one pending writer.
#[derive(Debug)]
pub(crate) struct WndBuf {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    len: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    fin: bool,
}

impl WndBuf {
    /// Panics if `capacity` is zero.
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "window capacity must be nonzero");
        Self {
            buf: vec![0; capacity],
            head: 0,
            tail: 0,
            len: 0,
            read_waker: None,
            write_waker: None,
            fin: false,
        }
    }
}

impl AsyncRead for WndBuf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.len == 0 {
            if self.fin {
                return Poll::Ready(Ok(()));
            }
            self.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let len = buf.remaining().min(self.len);
        let first = len.min(self.buf.len() - self.head);
        buf.put_slice(&self.buf[self.head..self.head + first]);
        buf.put_slice(&self.buf[..len - first]);
        self.head = (self.head + len) % self.buf.len();
        self.len -= len;
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for WndBuf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.fin {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let len = buf.len().min(self.buf.len() - self.len);
        if len == 0 {
            self.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let tail = self.tail;
        let first = len.min(self.buf.len() - tail);
        self.buf[tail..tail + first].copy_from_slice(&buf[..first]);
        self.buf[..len - first].copy_from_slice(&buf[first..len]);
        self.tail = (tail + len) % self.buf.len();
        self.len += len;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(len))
    }

    // Writes are immediately available to the reader.
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.fin = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        if let Some(waker) = self.write_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

/// Shared window; the first error terminates both reading and writing.
#[derive(Debug)]
pub struct ArcWndBuf(Arc<Mutex<crate::Result<WndBuf>>>, bool);

impl Clone for ArcWndBuf {
    fn clone(&self) -> Self {
        Self(self.0.clone(), false)
    }
}

impl Drop for ArcWndBuf {
    fn drop(&mut self) {
        if self.1 {
            self.set_error(crate::Error::H3_REQUEST_CANCELLED);
        }
    }
}

impl ArcWndBuf {
    /// Give this handle responsibility for cancelling unfinished body I/O.
    pub(crate) fn cancel_on_drop(mut self) -> Self {
        self.1 = true;
        self
    }

    pub(crate) fn complete(&mut self) {
        self.1 = false;
    }

    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(Ok(WndBuf::new(capacity)))), false)
    }

    pub fn set_error(&self, error: crate::Error) {
        let (reader, writer) = {
            let mut state = self.0.lock().unwrap();
            let Ok(window) = &mut *state else {
                return;
            };
            let wakers = (window.read_waker.take(), window.write_waker.take());
            *state = Err(error);
            wakers
        };
        if let Some(waker) = reader {
            waker.wake();
        }
        if let Some(waker) = writer {
            waker.wake();
        }
    }

    // Wake the receive pump even when it is waiting on network I/O rather than this window.
    pub(crate) fn poll_error(&self, cx: &Context<'_>) -> crate::Result<()> {
        match &mut *self.0.lock().unwrap() {
            Ok(window) => {
                window.write_waker = Some(cx.waker().clone());
                Ok(())
            }
            Err(error) => Err(*error),
        }
    }

    fn poll_io<T>(
        &self,
        poll: impl FnOnce(Pin<&mut WndBuf>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match &mut *self.0.lock().unwrap() {
            Ok(window) => poll(Pin::new(window)),
            Err(error) => Poll::Ready(Err((*error).into())),
        }
    }
}

impl AsyncRead for ArcWndBuf {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_io(|window| window.poll_read(cx, buf))
    }
}

impl AsyncWrite for ArcWndBuf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_io(|window| window.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(|window| window.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_io(|window| window.poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::Wake,
    };

    use super::*;

    trait TestRead: AsyncRead + Unpin {
        fn read_for_test(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut buf = ReadBuf::new(buf);
            self.poll_read(cx, &mut buf).map_ok(|()| buf.filled().len())
        }
    }

    impl<T: AsyncRead + Unpin> TestRead for T {}

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn bounded_fifo_and_wakeups() {
        let old = Arc::new(WakeCount::default());
        let latest = Arc::new(WakeCount::default());
        let old_waker = Waker::from(old.clone());
        let latest_waker = Waker::from(latest.clone());
        let mut old_cx = Context::from_waker(&old_waker);
        let mut cx = Context::from_waker(&latest_waker);
        let mut window = WndBuf::new(3);
        let mut window = Pin::new(&mut window);
        let mut output = [0; 8];

        assert!(
            window
                .as_mut()
                .read_for_test(&mut old_cx, &mut output)
                .is_pending()
        );
        assert!(
            window
                .as_mut()
                .read_for_test(&mut cx, &mut output)
                .is_pending()
        );
        assert!(matches!(
            window.as_mut().poll_write(&mut cx, b"abcd"),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        assert!(window.as_mut().poll_write(&mut old_cx, b"d").is_pending());
        assert!(window.as_mut().poll_write(&mut cx, b"d").is_pending());
        assert!(matches!(
            window.as_mut().read_for_test(&mut cx, &mut output[..2]),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(&output[..2], b"ab");
        assert_eq!(old.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 2);
        assert!(matches!(
            window.as_mut().poll_write(&mut cx, b"def"),
            Poll::Ready(Ok(2))
        ));
        assert!(window.as_mut().poll_write(&mut cx, b"f").is_pending());
        assert!(matches!(
            window.as_mut().poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            window.as_mut().poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(latest.0.load(Ordering::SeqCst), 3);
        assert!(
            matches!(window.as_mut().poll_write(&mut cx, b"f"), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe)
        );
        let mut n = 0;
        while n < 3 {
            let Poll::Ready(Ok(read)) = window.as_mut().read_for_test(&mut cx, &mut output[n..])
            else {
                panic!("buffered data must remain readable");
            };
            assert!(read > 0);
            n += read;
        }
        assert_eq!(&output[..n], b"cde");
        assert!(matches!(
            window.as_mut().read_for_test(&mut cx, &mut output),
            Poll::Ready(Ok(0))
        ));

        let mut empty = WndBuf::new(1);
        assert!(
            Pin::new(&mut empty)
                .read_for_test(&mut cx, &mut output)
                .is_pending()
        );
        assert!(matches!(
            Pin::new(&mut empty).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(latest.0.load(Ordering::SeqCst), 4);
        assert!(matches!(
            Pin::new(&mut empty).read_for_test(&mut cx, &mut output),
            Poll::Ready(Ok(0))
        ));
    }

    #[test]
    fn wraps_without_changing_storage() {
        let mut window = WndBuf::new(3);
        let ptr = window.buf.as_ptr();
        let capacity = window.buf.capacity();
        let mut cx = Context::from_waker(Waker::noop());
        let mut output = [0; 2];
        for _ in 0..10 {
            assert!(matches!(
                Pin::new(&mut window).poll_write(&mut cx, b"ab"),
                Poll::Ready(Ok(2))
            ));
            assert!(matches!(
                Pin::new(&mut window).read_for_test(&mut cx, &mut output),
                Poll::Ready(Ok(2))
            ));
            assert_eq!(&output, b"ab");
            assert!(
                Pin::new(&mut window)
                    .read_for_test(&mut cx, &mut output)
                    .is_pending()
            );
            assert_eq!(window.buf.len(), 3);
            assert_eq!(window.buf.capacity(), capacity);
            assert_eq!(window.buf.as_ptr(), ptr);
        }
    }

    #[test]
    fn shared_error_wakes_reader_and_writer() {
        for full in [false, true] {
            let mut reader = ArcWndBuf::new(1);
            let mut writer = reader.clone();
            let wakes = Arc::new(WakeCount::default());
            let waker = Waker::from(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            let mut output = [0];
            if full {
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, b"a"),
                    Poll::Ready(Ok(1))
                ));
                assert!(matches!(
                    Pin::new(&mut reader).read_for_test(&mut cx, &mut output),
                    Poll::Ready(Ok(1))
                ));
                assert_eq!(output, *b"a");
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, b"b"),
                    Poll::Ready(Ok(1))
                ));
                assert!(Pin::new(&mut writer).poll_write(&mut cx, b"c").is_pending());
            } else {
                assert!(
                    Pin::new(&mut reader)
                        .read_for_test(&mut cx, &mut output)
                        .is_pending()
                );
            }
            reader.set_error(crate::Error::H3_REQUEST_CANCELLED);
            writer.set_error(crate::Error::H3_INTERNAL_ERROR);
            assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
            let results = [
                Pin::new(&mut reader)
                    .read_for_test(&mut cx, &mut output)
                    .map_ok(|_| ()),
                Pin::new(&mut writer)
                    .poll_write(&mut cx, b"c")
                    .map_ok(|_| ()),
                Pin::new(&mut writer).poll_flush(&mut cx),
                Pin::new(&mut writer).poll_shutdown(&mut cx),
            ];
            for result in results {
                let Poll::Ready(Err(error)) = result else {
                    panic!("expected error")
                };
                assert_eq!(
                    crate::Error::from(error),
                    crate::Error::H3_REQUEST_CANCELLED
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "window capacity must be nonzero")]
    fn zero_capacity_is_rejected() {
        WndBuf::new(0);
    }

    #[tokio::test]
    async fn body_cancellation_belongs_only_to_the_operation_handle() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut body = ArcWndBuf::new(1);
        let owner = body.clone().cancel_on_drop();
        drop(owner.clone()); // Cloning does not copy cancellation responsibility.
        body.write_all(b"x").await.unwrap();
        drop(owner);
        assert_eq!(
            crate::Error::from(body.read(&mut [0; 1]).await.unwrap_err()),
            crate::Error::H3_REQUEST_CANCELLED
        );
        let mut body = ArcWndBuf::new(1);
        let mut owner = body.clone().cancel_on_drop();
        body.write_all(b"y").await.unwrap();
        owner.complete();
        drop(owner);
        let mut bytes = [0];
        body.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, *b"y");
    }
}
