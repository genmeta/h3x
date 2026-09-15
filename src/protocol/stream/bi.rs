//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    mem,
    sync::{Arc, Mutex},
};

use qbase::varint::VarInt;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};

use super::{H3ReadStream, H3WriteStream, StreamState};
use crate::{
    ArcWndBuf, Error, Result, Transport,
    protocol::{frame::Goaway, qpack::Qpack},
    wnd_buf::WeakWndBuf,
};

/// The connection and both application handles refer to this same stream.
pub(crate) struct BiStream<R, W> {
    pub(super) id: u64,
    pub(super) recv: Mutex<StreamState<R>>,
    pub(super) send: Mutex<StreamState<W>>,
    // Lock the corresponding stream state before accessing its body binding.
    recv_body: Mutex<Option<WeakWndBuf>>,
    send_body: Mutex<Option<WeakWndBuf>>,
    // Both halves notify the existing request-drain waiter when they finish.
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
            recv_body: Mutex::new(None),
            send_body: Mutex::new(None),
            finished,
        }
    }

    pub(super) fn read_body(&self, body: &ArcWndBuf) {
        bind_body(&self.recv, &self.recv_body, body);
    }

    pub(super) fn write_body(&self, body: &ArcWndBuf) {
        bind_body(&self.send, &self.send_body, body);
    }

    pub(super) fn terminate_read(&self, terminal: StreamState<R>) {
        let waker = {
            let mut state = self.recv.lock().unwrap();
            state.terminate(terminal)
        };
        self.notify_read();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(super) fn terminate_write(&self, terminal: StreamState<W>) {
        let waker = {
            let mut state = self.send.lock().unwrap();
            state.terminate(terminal)
        };
        self.notify_write();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(super) fn notify_read(&self) {
        let (result, body) = {
            let state = self.recv.lock().unwrap();
            let Some(result) = state.result() else {
                return;
            };
            (result, self.recv_body.lock().unwrap().take())
        };
        notify_body(result, body);
        self.notify_if_finished();
    }

    pub(super) fn notify_write(&self) {
        let (result, body) = {
            let state = self.send.lock().unwrap();
            let Some(result) = state.result() else {
                return;
            };
            (result, self.send_body.lock().unwrap().take())
        };
        notify_body(result, body);
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

fn bind_body<T>(
    state: &Mutex<StreamState<T>>,
    binding: &Mutex<Option<WeakWndBuf>>,
    body: &ArcWndBuf,
) {
    let result = {
        let state = state.lock().unwrap();
        match state.result() {
            Some(result) => Some(result),
            None => {
                let weak = body.downgrade();
                let mut binding = binding.lock().unwrap();
                assert!(
                    binding.as_ref().is_none_or(|bound| bound.ptr_eq(&weak)),
                    "a stream direction can only bind one body"
                );
                *binding = Some(weak);
                None
            }
        }
    };
    // set_error wakes body tasks, which may immediately access the stream again.
    if let Some(Err(error)) = result {
        body.set_error(error);
    }
}

fn notify_body(result: Result<()>, body: Option<WeakWndBuf>) {
    if let (Err(error), Some(body)) = (result, body)
        && let Some(body) = ArcWndBuf::upgrade(&body)
    {
        body.set_error(error);
    }
}

pub(crate) type Halves<R, W> = (H3WriteStream<W, R>, H3ReadStream<R, W>);

struct Incoming<R, W> {
    receiver: Option<mpsc::UnboundedReceiver<Result<Halves<R, W>>>>,
    error: Error,
}

pub(crate) struct BiStreams<R, W> {
    streams: Mutex<HashMap<u64, Arc<BiStream<R, W>>>>,
    stream_finished: Arc<Notify>,
    incoming: AsyncMutex<Incoming<R, W>>,
}

impl<R, W> Default for BiStreams<R, W> {
    fn default() -> Self {
        Self::new().0
    }
}

impl<R, W> BiStreams<R, W> {
    pub(crate) fn new() -> (Self, mpsc::UnboundedSender<Result<Halves<R, W>>>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                streams: Mutex::new(HashMap::new()),
                stream_finished: Arc::new(Notify::new()),
                incoming: AsyncMutex::new(Incoming {
                    receiver: Some(receiver),
                    error: Error::H3_REQUEST_CANCELLED,
                }),
            },
            sender,
        )
    }

    pub(crate) async fn accept(&self) -> Result<Halves<R, W>> {
        let mut incoming = self.incoming.lock().await;
        let result = match incoming.receiver.as_mut() {
            Some(receiver) => receiver.recv().await,
            None => None,
        };
        match result {
            Some(Ok(stream)) => Ok(stream),
            Some(Err(error)) => {
                incoming.error = error;
                Err(error)
            }
            None => Err(incoming.error),
        }
    }

    pub(crate) fn release_incoming(&self) {
        // An accept call borrows H3Connection, so it cannot overlap its Drop.
        let receiver = self
            .incoming
            .try_lock()
            .expect("connection has no accept borrower")
            .receiver
            .take();
        drop(receiver);
    }

    pub(crate) fn running(&self) -> Vec<Arc<BiStream<R, W>>> {
        self.streams.lock().unwrap().values().cloned().collect()
    }

    /// Wait for the fixed set admitted when peer GOAWAY arrived.
    pub(crate) async fn drained(&self, running: Vec<Arc<BiStream<R, W>>>) {
        loop {
            let finished = self.stream_finished.notified();
            tokio::pin!(finished);
            finished.as_mut().enable();
            if running.iter().all(|stream| {
                stream.recv.lock().unwrap().is_terminal()
                    && stream.send.lock().unwrap().is_terminal()
            }) {
                self.cleanup();
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
            Some(Arc::clone(&self.stream_finished)),
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
