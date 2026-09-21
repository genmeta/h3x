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
#[derive(Clone)]
pub struct ArcWndBuf {
    shared: Arc<Mutex<Shared>>,
}

struct Shared {
    window: crate::Result<WndBuf>,
    on_error: Option<Box<dyn FnOnce(Error) + Send>>,
}

impl std::fmt::Debug for ArcWndBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcWndBuf").finish_non_exhaustive()
    }
}

impl ArcWndBuf {
    pub fn new(capacity: usize) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared {
                window: Ok(WndBuf::with_capacity(capacity)),
                on_error: None,
            })),
        }
    }

    pub(crate) fn on_error(&self, error: Error) {
        let mut state = self.shared.lock().unwrap();
        if let Ok(window) = &mut state.window {
            if let Some(waker) = window.read_waker.take() {
                waker.wake();
            }
            if let Some(waker) = window.write_waker.take() {
                waker.wake();
            }
            state.window = Err(error.clone());
            let callback = state.on_error.take();
            drop(state);
            if let Some(callback) = callback {
                callback(error);
            }
        }
    }

    pub(crate) fn on_error_callback(&self, callback: impl FnOnce(Error) + Send + 'static) {
        let mut state = self.shared.lock().unwrap();
        if let Err(error) = &state.window {
            let error = error.clone();
            drop(state);
            callback(error);
        } else {
            state.on_error = Some(Box::new(callback));
        }
    }

    pub(crate) fn cancel(&self, code: u64) {
        self.on_error(
            crate::ErrorCode::try_from(code)
                .unwrap_or(crate::ErrorCode::InternalError)
                .reason("body cancelled"),
        );
    }

    fn poll_io<T>(
        &self,
        poll: impl FnOnce(Pin<&mut WndBuf>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match &mut self.shared.lock().unwrap().window {
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

impl qrecovery::recv::StopSending for &ArcWndBuf {
    fn stop(&mut self, error_code: u64) {
        ArcWndBuf::cancel(self, error_code);
    }
}

impl qrecovery::recv::StopSending for ArcWndBuf {
    fn stop(&mut self, error_code: u64) {
        ArcWndBuf::cancel(self, error_code);
    }
}

impl qrecovery::send::CancelStream for &ArcWndBuf {
    fn cancel(&mut self, error_code: u64) {
        ArcWndBuf::cancel(self, error_code);
    }
}

impl qrecovery::send::CancelStream for ArcWndBuf {
    fn cancel(&mut self, error_code: u64) {
        ArcWndBuf::cancel(self, error_code);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::ErrorCode;

    #[test]
    fn error_callback_observes_the_first_error_once() {
        let window = ArcWndBuf::new(1);
        let calls = Arc::new(AtomicUsize::new(0));
        window.on_error_callback({
            let calls = calls.clone();
            move |error| {
                assert_eq!(error.code, ErrorCode::RequestCancelled);
                calls.fetch_add(1, Ordering::SeqCst);
            }
        });
        window.cancel(ErrorCode::RequestCancelled.as_u64());
        window.cancel(ErrorCode::InternalError.as_u64());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn callback_registered_after_failure_runs_immediately() {
        let window = ArcWndBuf::new(1);
        window.cancel(ErrorCode::RequestCancelled.as_u64());
        let calls = Arc::new(AtomicUsize::new(0));
        window.on_error_callback({
            let calls = calls.clone();
            move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
