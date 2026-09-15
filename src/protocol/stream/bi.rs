//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    mem,
    sync::{Arc, Mutex},
};

use qbase::{ArcReceiving, varint::VarInt};

use super::{H3ReadStream, H3WriteStream, StreamState};
use crate::{
    Error, Result, Transport,
    protocol::{frame::Goaway, qpack::Qpack},
};

/// The connection and both application handles refer to this same stream.
pub(crate) struct BiStream<R, W> {
    pub(super) id: u64,
    pub(super) read: Mutex<StreamState<R>>,
    pub(super) write: Mutex<StreamState<W>>,
    // One completion signal for the connection's request-drain consumer.
    pub(super) finished: ArcReceiving<()>,
}

impl<R, W> BiStream<R, W> {
    pub(super) fn new(id: u64, read: StreamState<R>, write: StreamState<W>) -> Self {
        Self {
            id,
            read: Mutex::new(read),
            write: Mutex::new(write),
            finished: ArcReceiving::default(),
        }
    }

    fn goaway(&self, goaway: &Goaway) {
        let waker = self
            .read
            .lock()
            .unwrap()
            .terminate(StreamState::Goaway(goaway.clone()));
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
        let waker = self
            .write
            .lock()
            .unwrap()
            .terminate(StreamState::Goaway(goaway.clone()));
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close(&self, error: Error) {
        let waker = self
            .read
            .lock()
            .unwrap()
            .terminate(StreamState::Closed(error));
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
        let waker = self
            .write
            .lock()
            .unwrap()
            .terminate(StreamState::Closed(error));
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<R: qrecovery::recv::StopSending, W> qrecovery::recv::StopSending for &BiStream<R, W> {
    fn stop(&mut self, error_code: u64) {
        let waker = {
            let mut state = self.read.lock().unwrap();
            if let StreamState::Idle(io) | StreamState::Polling(io, _) = &mut *state {
                io.stop(error_code);
            }
            state.terminate(StreamState::Closed(Error::H3_REQUEST_CANCELLED))
        };
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<R: qrecovery::recv::StopSending, W> qrecovery::recv::StopSending for BiStream<R, W> {
    fn stop(&mut self, error_code: u64) {
        qrecovery::recv::StopSending::stop(&mut &*self, error_code);
    }
}

impl<R, W: qrecovery::send::CancelStream> qrecovery::send::CancelStream for &BiStream<R, W> {
    fn cancel(&mut self, error_code: u64) {
        let waker = {
            let mut state = self.write.lock().unwrap();
            if let StreamState::Idle(io) | StreamState::Polling(io, _) = &mut *state {
                io.cancel(error_code);
            }
            state.terminate(StreamState::Closed(Error::H3_REQUEST_CANCELLED))
        };
        if self.read.lock().unwrap().is_terminal() && self.write.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl<R, W: qrecovery::send::CancelStream> qrecovery::send::CancelStream for BiStream<R, W> {
    fn cancel(&mut self, error_code: u64) {
        qrecovery::send::CancelStream::cancel(&mut &*self, error_code);
    }
}

pub(crate) struct BiStreams<R, W> {
    streams: Mutex<HashMap<u64, Arc<BiStream<R, W>>>>,
}

impl<R, W> Default for BiStreams<R, W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R, W> BiStreams<R, W> {
    pub(crate) fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
        }
    }

    /// Wait for the fixed set admitted when peer GOAWAY arrived.
    /// The connection has one drain consumer; completion is not a broadcast.
    pub(crate) async fn drained(&self) {
        let running: Vec<_> = self.streams.lock().unwrap().values().cloned().collect();
        for stream in running {
            stream
                .finished
                .clone()
                .await
                .expect("stream completion is never cancelled");
        }
        self.cleanup();
    }

    // Idle connections retain finished entries until the next insert or GOAWAY.
    pub(crate) fn cleanup(&self) {
        self.streams.lock().unwrap().retain(|_, stream| {
            !(stream.read.lock().unwrap().is_terminal()
                && stream.write.lock().unwrap().is_terminal())
        });
    }

    pub(crate) fn goaway<T: Transport>(&self, id: u64, qpack: &Qpack<T>) {
        let streams: Vec<_> = self
            .streams
            .lock()
            .unwrap()
            .iter()
            .filter(|(stream_id, _)| **stream_id % 4 == id % 4 && **stream_id >= id)
            .map(|(_, stream)| Arc::clone(stream))
            .collect();
        let goaway = Goaway {
            id: VarInt::try_from(id).unwrap(),
        };
        for stream in streams {
            stream.goaway(&goaway);
            let _ = qpack.cancel(stream.id);
        }
        self.cleanup();
    }

    pub(crate) fn close(&self, error: Error) {
        let streams = mem::take(&mut *self.streams.lock().unwrap());
        for stream in streams.into_values() {
            stream.close(error);
        }
    }

    pub(crate) fn insert(
        &self,
        id: u64,
        recv: R,
        send: W,
    ) -> Result<(H3WriteStream<W, R>, H3ReadStream<R, W>)> {
        self.cleanup();
        let mut streams = self.streams.lock().unwrap();
        let stream = Arc::new(BiStream::new(
            id,
            StreamState::Idle(recv),
            StreamState::Idle(send),
        ));
        streams.insert(id, Arc::clone(&stream));
        drop(streams);
        Ok((
            H3WriteStream {
                stream: Arc::clone(&stream),
                stop_signal: None,
            },
            H3ReadStream { stream },
        ))
    }
}

#[cfg(test)]
impl<R, W> BiStreams<R, W> {
    pub(crate) fn len(&self) -> usize {
        self.streams.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::poll_fn,
        io,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn drain_waits_for_both_halves_and_remembers_early_completion() {
        use std::future::Future;

        for early in [false, true] {
            for read_first in [false, true] {
                let streams = BiStreams::new();
                let (mut send, mut recv) = streams
                    .insert(0, tokio::io::empty(), tokio::io::sink())
                    .unwrap();
                let mut draining = Box::pin(streams.drained());
                let mut cx = Context::from_waker(Waker::noop());
                if !early {
                    assert!(draining.as_mut().poll(&mut cx).is_pending());
                }
                if read_first {
                    assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
                } else {
                    send.shutdown().await.unwrap();
                }
                if !early {
                    assert!(draining.as_mut().poll(&mut cx).is_pending());
                }
                if read_first {
                    send.shutdown().await.unwrap();
                } else {
                    assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
                }
                // Repeated terminal notifications must not overwrite completion.
                drop(send);
                drop(recv);
                tokio::time::timeout(std::time::Duration::from_secs(1), draining)
                    .await
                    .unwrap();
                assert_eq!(streams.len(), 0);
            }
        }
    }

    #[tokio::test]
    async fn close_wakes_a_pending_drain() {
        let streams = Arc::new(BiStreams::new());
        let (_send, _recv) = streams
            .insert(0, tokio::io::empty(), tokio::io::sink())
            .unwrap();
        let draining = tokio::spawn({
            let streams = streams.clone();
            async move { streams.drained().await }
        });
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        streams.close(Error::H3_INTERNAL_ERROR);
        tokio::time::timeout(std::time::Duration::from_secs(1), draining)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn explicit_stop_and_cancel_forward_codes_once_and_complete_the_stream() {
        use std::{
            future::Future,
            sync::atomic::{AtomicU64, Ordering},
        };

        use qrecovery::{recv::StopSending, send::CancelStream};

        struct Recv(Arc<AtomicU64>);
        impl StopSending for Recv {
            fn stop(&mut self, code: u64) {
                self.0.store(code, Ordering::SeqCst);
            }
        }
        struct Send(Arc<AtomicU64>);
        impl CancelStream for Send {
            fn cancel(&mut self, code: u64) {
                self.0.store(code, Ordering::SeqCst);
            }
        }
        let read_code = Arc::new(AtomicU64::new(0));
        let write_code = Arc::new(AtomicU64::new(0));
        let streams = BiStreams::new();
        let (mut send, mut recv) = streams
            .insert(0, Recv(read_code.clone()), Send(write_code.clone()))
            .unwrap();
        let mut drained = Box::pin(streams.drained());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(drained.as_mut().poll(&mut cx).is_pending());
        recv.stop(123);
        assert!(drained.as_mut().poll(&mut cx).is_pending());
        send.cancel(456);
        assert!(drained.as_mut().poll(&mut cx).is_ready());
        recv.stop(789);
        send.cancel(789);
        assert_eq!(read_code.load(Ordering::SeqCst), 123);
        assert_eq!(write_code.load(Ordering::SeqCst), 456);

        let mut stream = BiStream::new(
            4,
            StreamState::Idle(Recv(read_code.clone())),
            StreamState::Idle(Send(write_code.clone())),
        );
        stream.stop(321);
        assert!(stream.read.lock().unwrap().is_terminal());
        assert!(!stream.write.lock().unwrap().is_terminal());
        stream.cancel(654);
        assert!(
            Pin::new(&mut stream.finished.clone())
                .poll(&mut cx)
                .is_ready()
        );
        assert_eq!(read_code.load(Ordering::SeqCst), 321);
        assert_eq!(write_code.load(Ordering::SeqCst), 654);
    }

    struct FailingShutdown(bool);

    impl AsyncWrite for FailingShutdown {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !self.0 {
                self.0 = true;
                Poll::Pending
            } else {
                Poll::Ready(Err(Error::H3_REQUEST_REJECTED.into()))
            }
        }
    }

    #[tokio::test]
    async fn pending_shutdown_keeps_entry_and_failure_reaps_without_dropping_handles() {
        let streams = Arc::new(BiStreams::default());
        let (mut send, mut recv) = streams
            .insert(0, tokio::io::empty(), FailingShutdown(false))
            .unwrap();
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut send).poll_shutdown(&mut cx).is_pending());
        streams.cleanup();
        assert_eq!(streams.len(), 1);
        let error = poll_fn(|cx| Pin::new(&mut send).poll_shutdown(cx))
            .await
            .unwrap_err();
        assert_eq!(Error::from(error), Error::H3_REQUEST_REJECTED);
        streams.cleanup();
        assert_eq!(streams.len(), 0);
        assert_eq!(
            Error::from(send.flush().await.unwrap_err()),
            Error::H3_REQUEST_REJECTED
        );
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
    }
}
