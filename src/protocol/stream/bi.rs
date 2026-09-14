//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    future::Future,
    mem,
    pin::Pin,
    sync::{Arc, Mutex},
};

use qbase::varint::VarInt;
use tokio::sync::Notify;

use super::{H3ReadStream, H3WriteStream, StreamState};
use crate::{
    Error, Result,
    protocol::{frame::Goaway, qpack::Qpack},
};

type StopSignal = Pin<Box<dyn Future<Output = Error> + Send>>;
type ErrorHandler = Box<dyn FnOnce(Error) + Send>;

/// The connection and both application handles refer to this same stream.
pub(crate) struct BiStream<R, W> {
    pub(super) id: u64,
    pub(super) recv: Mutex<StreamState<R>>,
    pub(super) send: Mutex<StreamState<W>>,
    pub(super) send_changed: Notify,
    pub(super) send_stopped: Mutex<Option<StopSignal>>,
    pub(super) send_error_handler: Mutex<Option<ErrorHandler>>,
    finished: Option<Arc<Notify>>,
}

impl<R, W> BiStream<R, W> {
    pub(super) fn new(
        id: u64,
        recv: StreamState<R>,
        send: StreamState<W>,
        finished: Option<Arc<Notify>>,
    ) -> Self {
        Self {
            id,
            recv: Mutex::new(recv),
            send: Mutex::new(send),
            send_changed: Notify::new(),
            send_stopped: Mutex::new(None),
            send_error_handler: Mutex::new(None),
            finished,
        }
    }

    pub(super) fn terminate_read(&self, terminal: StreamState<R>) {
        let waker = {
            let mut state = self.recv.lock().unwrap();
            if state.is_terminal() {
                return;
            }
            state.terminate(terminal)
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        self.notify_if_finished();
    }

    pub(super) fn terminate_write(&self, terminal: StreamState<W>) {
        let waker = {
            let mut state = self.send.lock().unwrap();
            if state.is_terminal() {
                return;
            }
            state.terminate(terminal)
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        self.notify_write();
    }

    pub(super) fn notify_write(&self) {
        let (result, notify) = {
            let state = self.send.lock().unwrap();
            let Some(result) = state.result() else {
                return;
            };
            (result, self.send_error_handler.lock().unwrap().take())
        };
        // A handler may wake application I/O; release the stream locks first.
        if let (Err(error), Some(notify)) = (result, notify) {
            notify(error);
        }
        self.send_changed.notify_waiters();
        self.notify_if_finished();
    }

    pub(super) fn notify_if_finished(&self) {
        if let Some(finished) = &self.finished
            && self.recv.lock().unwrap().is_terminal()
            && self.send.lock().unwrap().is_terminal()
        {
            finished.notify_waiters();
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

enum BiStreamsState {
    Open,
    Draining { cutoff: u64 },
    Closed(Error),
}

pub(crate) struct BiStreams<R, W> {
    // When both locks are needed, hold state before locking streams.
    state: Mutex<BiStreamsState>,
    streams: Mutex<HashMap<u64, Arc<BiStream<R, W>>>>,
    stream_finished: Arc<Notify>,
}

impl<R, W> Default for BiStreams<R, W> {
    fn default() -> Self {
        Self {
            state: Mutex::new(BiStreamsState::Open),
            streams: Mutex::new(HashMap::new()),
            stream_finished: Arc::new(Notify::new()),
        }
    }
}

impl<R, W> BiStreams<R, W> {
    /// Wait for both halves of every admitted stream to finish or be cancelled.
    /// The caller must stop admitting streams before starting this wait.
    pub(crate) async fn drained(&self) {
        loop {
            let finished = self.stream_finished.notified();
            self.cleanup();
            if self.streams.lock().unwrap().is_empty() {
                return;
            }
            finished.await;
        }
    }

    // Idle connections retain finished entries until the next insert or GOAWAY.
    pub(crate) fn cleanup(&self) {
        self.streams.lock().unwrap().retain(|_, stream| {
            !(stream.recv.lock().unwrap().is_terminal()
                && stream.send.lock().unwrap().is_terminal())
        });
    }

    pub(crate) fn goaway(&self, id: u64, qpack: &Qpack) {
        let streams: Vec<_> = {
            let mut state = self.state.lock().unwrap();
            let cutoff = match *state {
                BiStreamsState::Open => id,
                BiStreamsState::Draining { cutoff } => cutoff.min(id),
                BiStreamsState::Closed(_) => return,
            };
            *state = BiStreamsState::Draining { cutoff };
            self.streams
                .lock()
                .unwrap()
                .iter()
                .filter(|(stream_id, _)| **stream_id >= id)
                .map(|(_, stream)| Arc::clone(stream))
                .collect()
        };
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
        let (error, streams) = {
            let mut state = self.state.lock().unwrap();
            let error = match *state {
                BiStreamsState::Closed(error) => error,
                _ => {
                    *state = BiStreamsState::Closed(error);
                    error
                }
            };
            (error, mem::take(&mut *self.streams.lock().unwrap()))
        };
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
        let state = self.state.lock().unwrap();
        match *state {
            BiStreamsState::Closed(error) => return Err(error),
            BiStreamsState::Draining { cutoff } if id >= cutoff => {
                return Err(Error::H3_REQUEST_REJECTED);
            }
            _ => {}
        }
        let mut streams = self.streams.lock().unwrap();
        if streams.contains_key(&id) {
            return Err(Error::H3_ID_ERROR);
        }
        let stream = Arc::new(BiStream::new(
            id,
            StreamState::Idle(recv),
            StreamState::Idle(send),
            Some(Arc::clone(&self.stream_finished)),
        ));
        streams.insert(id, Arc::clone(&stream));
        Ok((
            H3WriteStream {
                stream: Arc::clone(&stream),
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
