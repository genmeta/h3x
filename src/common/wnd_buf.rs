use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Error;

/// A bounded FIFO with one pending reader and one pending writer.
#[derive(Debug)]
pub(crate) struct WndBuf {
    buf: Vec<u8>,
    head: usize,
    tail: usize,
    len: usize,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    error_waker: Option<Waker>,
    fin: bool,
}

impl WndBuf {
    /// Panics if `capacity` is zero.
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "window capacity must be nonzero");
        Self {
            buf: vec![0; capacity],
            head: 0,
            tail: 0,
            len: 0,
            read_waker: None,
            write_waker: None,
            error_waker: None,
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
        if len > 0
            && let Some(waker) = self.write_waker.take()
        {
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
#[derive(Debug, Clone)]
pub struct ArcWndBuf {
    shared: Arc<Mutex<crate::Result<WndBuf>>>,
}

impl ArcWndBuf {
    pub fn new(capacity: usize) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Ok(WndBuf::with_capacity(capacity)))),
        }
    }

    pub(crate) fn on_error(&self, error: Error) {
        let mut state = self.shared.lock().unwrap();
        if let Ok(window) = &mut *state {
            if let Some(waker) = window.read_waker.take() {
                waker.wake();
            }
            if let Some(waker) = window.write_waker.take() {
                waker.wake();
            }
            if let Some(waker) = window.error_waker.take() {
                waker.wake();
            }
            *state = Err(error);
        }
    }

    /// One background pump waits for errors on each body window.
    /// Keep its notification separate from application read/write readiness.
    pub(crate) async fn wait_error(&self) -> Error {
        std::future::poll_fn(|cx| match &mut *self.shared.lock().unwrap() {
            Err(error) => Poll::Ready(error.clone()),
            Ok(window) => {
                window.error_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    fn poll_io<T>(
        &self,
        poll: impl FnOnce(Pin<&mut WndBuf>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match &mut *self.shared.lock().unwrap() {
            Ok(window) => poll(Pin::new(window)),
            Err(error) => Poll::Ready(Err(error.clone().into())),
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
