use std::{
    collections::VecDeque,
    future::poll_fn,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::Error;

/// A bounded FIFO with one pending reader and one pending writer.
#[derive(Debug)]
pub(crate) struct WndBuf {
    chunks: VecDeque<Bytes>,
    // Coalesce borrowed AsyncWrite calls until the consumer takes ownership.
    pending: BytesMut,
    capacity: usize,
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
            chunks: VecDeque::new(),
            pending: BytesMut::new(),
            capacity,
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
        let mut remaining = len;
        while remaining > 0 {
            if let Some(chunk) = self.chunks.front_mut() {
                let count = remaining.min(chunk.len());
                buf.put_slice(&chunk[..count]);
                chunk.advance(count);
                remaining -= count;
                if chunk.is_empty() {
                    self.chunks.pop_front();
                }
            } else {
                buf.put_slice(&self.pending[..remaining]);
                self.pending.advance(remaining);
                break;
            }
        }
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
        let len = buf.len().min(self.capacity.saturating_sub(self.len));
        if len == 0 {
            self.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        self.pending.extend_from_slice(&buf[..len]);
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

type ErrorCb = Arc<Mutex<Option<Box<dyn FnOnce(Error) + Send>>>>;
/// Shared window; the first error terminates both reading and writing.
#[derive(Clone)]
pub struct ArcWndBuf {
    window: Arc<Mutex<crate::Result<WndBuf>>>,
    error_cb: ErrorCb,
}

impl std::fmt::Debug for ArcWndBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcWndBuf").finish_non_exhaustive()
    }
}

impl ArcWndBuf {
    pub fn new(capacity: usize) -> Self {
        Self::with_initial(capacity, Bytes::new())
    }

    /// Start with owned bytes without copying or waiting for a consumer.
    /// Initial bytes may exceed capacity; further writes wait until the queued
    /// bytes fall below capacity. Capacity bounds subsequent streaming writes.
    pub fn with_initial(capacity: usize, initial: Bytes) -> Self {
        let mut window = WndBuf::with_capacity(capacity);
        if !initial.is_empty() {
            window.len = initial.len();
            window.chunks.push_back(initial);
        }
        Self {
            window: Arc::new(Mutex::new(Ok(window))),
            error_cb: Arc::new(Mutex::new(None)),
        }
    }

    /// Read up to `limit` bytes by transferring a shared chunk, without copying
    /// its payload. Empty bytes mean EOF, after all queued data has been read.
    /// Like AsyncRead, this window supports only one pending consumer.
    /// Panics if `limit` is zero.
    pub fn poll_read_chunk(&self, cx: &mut Context<'_>, limit: usize) -> Poll<io::Result<Bytes>> {
        assert!(limit > 0, "chunk limit must be nonzero");
        self.poll_io(|mut window| {
            let mut chunk = match window.chunks.pop_front() {
                Some(chunk) => chunk,
                None if !window.pending.is_empty() => window.pending.split().freeze(),
                None if window.fin => return Poll::Ready(Ok(Bytes::new())),
                None => {
                    window.read_waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            };
            let data = chunk.split_to(chunk.len().min(limit));
            if !chunk.is_empty() {
                window.chunks.push_front(chunk);
            }
            window.len -= data.len();
            if let Some(waker) = window.write_waker.take() {
                waker.wake();
            }
            Poll::Ready(Ok(data))
        })
    }

    /// Async counterpart of [`Self::poll_read_chunk`]. Cancellation while
    /// waiting does not consume data.
    pub async fn read_chunk(&self, limit: usize) -> io::Result<Bytes> {
        poll_fn(|cx| self.poll_read_chunk(cx, limit)).await
    }

    /// Transfer as many bytes as currently fit into the bounded queue. Only
    /// the accepted prefix is removed from `bytes`; Pending leaves it intact.
    /// Payloads are shared, not copied. Small slices may retain larger backing
    /// allocations, so capacity bounds queued bytes, not retained allocations.
    /// Only one producer may wait at a time, including AsyncWrite users.
    pub fn poll_write_bytes(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut Bytes,
    ) -> Poll<io::Result<usize>> {
        self.poll_io(|mut window| {
            if bytes.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if window.fin {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            let count = bytes.len().min(window.capacity.saturating_sub(window.len));
            if count == 0 {
                window.write_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if !window.pending.is_empty() {
                let pending = window.pending.split().freeze();
                window.chunks.push_back(pending);
            }
            window.chunks.push_back(bytes.split_to(count));
            window.len += count;
            if let Some(waker) = window.read_waker.take() {
                waker.wake();
            }
            Poll::Ready(Ok(count))
        })
    }

    /// Enqueue an owned chunk without copying its payload, waiting for space.
    /// Like write_all, cancelling this future can leave a prefix enqueued;
    /// use poll_write_bytes with a retained Bytes value to resume explicitly.
    pub async fn write_bytes(&self, mut bytes: Bytes) -> io::Result<()> {
        while !bytes.is_empty() {
            poll_fn(|cx| self.poll_write_bytes(cx, &mut bytes)).await?;
        }
        Ok(())
    }

    pub(crate) fn error(&self, error: Error) {
        let mut state = self.window.lock().unwrap();
        if let Ok(window) = &mut *state {
            if let Some(waker) = window.read_waker.take() {
                waker.wake();
            }
            if let Some(waker) = window.write_waker.take() {
                waker.wake();
            }
            *state = Err(error.clone());
            let callback = self.error_cb.lock().unwrap().take();
            drop(state);
            if let Some(callback) = callback {
                callback(error);
            }
        }
    }

    pub(crate) fn on_error(&self, callback: impl FnOnce(Error) + Send + 'static) {
        let state = self.window.lock().unwrap();
        if let Err(error) = &*state {
            let error = error.clone();
            drop(state);
            callback(error);
        } else {
            *self.error_cb.lock().unwrap() = Some(Box::new(callback));
        }
    }

    pub(crate) fn cancel(&self, code: u64) {
        self.error(
            crate::ErrorCode::try_from(code)
                .unwrap_or(crate::ErrorCode::InternalError)
                .stream("body cancelled"),
        );
    }

    fn poll_io<T>(
        &self,
        poll: impl FnOnce(Pin<&mut WndBuf>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        match &mut *self.window.lock().unwrap() {
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
#[path = "../../tests/unit/common/wnd_buf.rs"]
mod tests;
