//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::{HashMap, VecDeque},
    mem,
    sync::{Arc, Mutex},
};

use qbase::{ArcReceiving, varint::VarInt};
use tokio::sync::Notify;

use super::{H3ReadStream, H3WriteStream, StreamState};
use crate::{
    Error, Result, Transport,
    protocol::{frame::Goaway, qpack::Qpack},
};

/// The connection and both application handles refer to this same stream.
pub(crate) struct BiStream<R, W> {
    pub(super) id: u64,
    pub(super) recv: Mutex<StreamState<R>>,
    pub(super) send: Mutex<StreamState<W>>,
    // One completion signal for the connection's request-drain consumer.
    finished: ArcReceiving<()>,
}

impl<R, W> BiStream<R, W> {
    pub(super) fn new(id: u64, recv: StreamState<R>, send: StreamState<W>) -> Self {
        Self {
            id,
            recv: Mutex::new(recv),
            send: Mutex::new(send),
            finished: ArcReceiving::default(),
        }
    }

    pub(super) fn terminate_read(&self, terminal: StreamState<R>) {
        let waker = {
            let mut state = self.recv.lock().unwrap();
            state.terminate(terminal)
        };
        self.notify_if_finished();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(super) fn terminate_write(&self, terminal: StreamState<W>) {
        let waker = {
            let mut state = self.send.lock().unwrap();
            state.terminate(terminal)
        };
        self.notify_if_finished();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(super) fn notify_if_finished(&self) {
        if self.recv.lock().unwrap().is_terminal() && self.send.lock().unwrap().is_terminal() {
            self.finished.obtain(());
        }
    }

    fn goaway(&self, goaway: &Goaway) {
        self.terminate_read(StreamState::Goaway(goaway.clone()));
        self.terminate_write(StreamState::Goaway(goaway.clone()));
    }

    fn close(&self, error: Error) {
        self.terminate_read(StreamState::Closed(error));
        self.terminate_write(StreamState::Closed(error));
    }
}

pub(crate) type Halves<R, W> = (H3WriteStream<W, R>, H3ReadStream<R, W>);

struct Incoming<R, W> {
    pending: VecDeque<Halves<R, W>>,
    error: Option<Error>,
}

pub(crate) struct BiStreams<R, W> {
    streams: Mutex<HashMap<u64, Arc<BiStream<R, W>>>>,
    incoming: Mutex<Incoming<R, W>>,
    incoming_changed: Notify,
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
            incoming: Mutex::new(Incoming {
                pending: VecDeque::new(),
                error: None,
            }),
            incoming_changed: Notify::new(),
        }
    }

    pub(crate) async fn accept(&self) -> Result<Halves<R, W>> {
        loop {
            let changed = self.incoming_changed.notified();
            {
                let mut incoming = self.incoming.lock().unwrap();
                if let Some(stream) = incoming.pending.pop_front() {
                    return Ok(stream);
                }
                if let Some(error) = incoming.error {
                    return Err(error);
                }
            }
            changed.await;
        }
    }

    pub(crate) fn insert_incoming(&self, id: u64, recv: R, send: W) -> Result<()> {
        let mut incoming = self.incoming.lock().unwrap();
        if let Some(error) = incoming.error {
            return Err(error);
        }
        incoming.pending.push_back(self.insert(id, recv, send)?);
        drop(incoming);
        self.incoming_changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn close_incoming(&self, error: Error) {
        self.incoming.lock().unwrap().error.get_or_insert(error);
        self.incoming_changed.notify_waiters();
    }

    pub(crate) fn release_incoming(&self) {
        let pending = {
            let mut incoming = self.incoming.lock().unwrap();
            incoming.error.get_or_insert(Error::H3_REQUEST_CANCELLED);
            mem::take(&mut incoming.pending)
        };
        self.incoming_changed.notify_waiters();
        drop(pending);
    }

    pub(crate) fn running(&self) -> Vec<Arc<BiStream<R, W>>> {
        self.streams.lock().unwrap().values().cloned().collect()
    }

    /// Wait for the fixed set admitted when peer GOAWAY arrived.
    /// The connection has one drain consumer; completion is not a broadcast.
    pub(crate) async fn drained(&self, running: Vec<Arc<BiStream<R, W>>>) {
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
            !(stream.recv.lock().unwrap().is_terminal()
                && stream.send.lock().unwrap().is_terminal())
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
        self.close_incoming(error);
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
    async fn incoming_streams_are_fifo_and_terminal_error_persists() {
        let streams = BiStreams::new();
        for id in [0, 4] {
            streams
                .insert_incoming(id, tokio::io::empty(), tokio::io::sink())
                .unwrap();
        }
        streams.close_incoming(Error::H3_NO_ERROR);
        for id in [0, 4] {
            let (send, _) = streams.accept().await.unwrap();
            assert_eq!(send.stream.id, id);
        }
        for _ in 0..2 {
            assert!(matches!(streams.accept().await, Err(Error::H3_NO_ERROR)));
        }
        assert_eq!(
            streams.insert_incoming(8, tokio::io::empty(), tokio::io::sink()),
            Err(Error::H3_NO_ERROR)
        );
    }

    #[tokio::test]
    async fn incoming_close_wakes_all_waiters_and_release_drops_queued_streams() {
        let streams = Arc::new(BiStreams::<tokio::io::Empty, tokio::io::Sink>::new());
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let streams = streams.clone();
            tasks.push(tokio::spawn(async move {
                assert!(matches!(
                    streams.accept().await,
                    Err(Error::H3_INTERNAL_ERROR)
                ));
            }));
        }
        tokio::task::yield_now().await;
        streams.close(Error::H3_INTERNAL_ERROR);
        for task in tasks {
            tokio::time::timeout(std::time::Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }

        let streams = BiStreams::new();
        streams
            .insert_incoming(0, tokio::io::empty(), tokio::io::sink())
            .unwrap();
        streams.release_incoming();
        streams.cleanup();
        assert_eq!(streams.len(), 0);
        assert!(matches!(
            streams.accept().await,
            Err(Error::H3_REQUEST_CANCELLED)
        ));
    }

    #[tokio::test]
    async fn drain_waits_for_both_halves_and_remembers_early_completion() {
        use std::future::Future;

        for early in [false, true] {
            for read_first in [false, true] {
                let streams = BiStreams::new();
                let (mut send, mut recv) = streams
                    .insert(0, tokio::io::empty(), tokio::io::sink())
                    .unwrap();
                let running = streams.running();
                let mut draining = Box::pin(streams.drained(running));
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
        let running = streams.running();
        let draining = tokio::spawn({
            let streams = streams.clone();
            async move { streams.drained(running).await }
        });
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        streams.close(Error::H3_INTERNAL_ERROR);
        tokio::time::timeout(std::time::Duration::from_secs(1), draining)
            .await
            .unwrap()
            .unwrap();
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
