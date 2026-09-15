//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    future::poll_fn,
    mem,
    sync::{Arc, Mutex, Weak},
    task::Poll,
};

use super::{H3ReadStream, H3WriteStream, StreamState};
use crate::{Error, Result};

/// Observes application-owned directions without extending their lifetimes.
pub(crate) struct BiStream<R, W> {
    id: u64,
    read: Weak<Mutex<StreamState<R>>>,
    write: Weak<Mutex<StreamState<W>>>,
}

impl<R, W> BiStream<R, W> {
    async fn finished(&self) {
        poll_fn(|cx| {
            let read = self.read.upgrade().map_or(Poll::Ready(()), |state| {
                state.lock().unwrap().poll_finished(cx)
            });
            let write = self.write.upgrade().map_or(Poll::Ready(()), |state| {
                state.lock().unwrap().poll_finished(cx)
            });
            if read.is_ready() && write.is_ready() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }

    fn close(&self, error: Error) {
        if let Some(state) = self.read.upgrade() {
            let wakers = state.lock().unwrap().close(error, |_| {});
            for waker in wakers.into_iter().flatten() {
                waker.wake();
            }
        }
        if let Some(state) = self.write.upgrade() {
            let wakers = state.lock().unwrap().close(error, |_| {});
            for waker in wakers.into_iter().flatten() {
                waker.wake();
            }
        }
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

    /// Wait for the fixed set after both GOAWAY directions froze admission.
    /// The connection must freeze admission before calling this method.
    /// Each direction keeps the latest drain waiter alongside its I/O waiter.
    pub(crate) async fn drained(&self) {
        let running: Vec<_> = self.streams.lock().unwrap().values().cloned().collect();
        for stream in running {
            stream.finished().await;
        }
        self.cleanup();
    }

    // Idle connections retain finished entries until the next insert or GOAWAY.
    pub(crate) fn cleanup(&self) {
        self.streams.lock().unwrap().retain(|_, stream| {
            !(stream
                .read
                .upgrade()
                .is_none_or(|state| state.lock().unwrap().is_finished())
                && stream
                    .write
                    .upgrade()
                    .is_none_or(|state| state.lock().unwrap().is_finished()))
        });
    }

    pub(crate) fn goaway(&self, id: u64) -> Vec<u64> {
        let streams: Vec<_> = self
            .streams
            .lock()
            .unwrap()
            .iter()
            .filter(|(stream_id, _)| **stream_id % 4 == id % 4 && **stream_id >= id)
            .map(|(_, stream)| Arc::clone(stream))
            .collect();
        let rejected = streams.iter().map(|stream| stream.id).collect();
        for stream in streams {
            stream.close(Error::H3_REQUEST_REJECTED);
        }
        self.cleanup();
        rejected
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
    ) -> Result<(H3WriteStream<W>, H3ReadStream<R>)> {
        self.cleanup();
        let read = H3ReadStream::new(id, recv);
        let write = H3WriteStream::new(id, send);
        let stream = Arc::new(BiStream {
            id,
            read: Arc::downgrade(&read.state),
            write: Arc::downgrade(&write.state),
        });
        self.streams.lock().unwrap().insert(id, stream);
        Ok((write, read))
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
    }

    #[test]
    fn dropping_an_application_handle_only_terminates_its_direction() {
        use std::future::Future;

        for read_first in [false, true] {
            let streams = BiStreams::new();
            let (send, recv) = streams
                .insert(0, tokio::io::empty(), tokio::io::sink())
                .unwrap();
            let stream = streams.streams.lock().unwrap().get(&0).unwrap().clone();
            let mut draining = Box::pin(streams.drained());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(draining.as_mut().poll(&mut cx).is_pending());
            if read_first {
                drop(recv);
                assert!(
                    stream
                        .read
                        .upgrade()
                        .is_none_or(|state| state.lock().unwrap().is_finished())
                );
                assert!(
                    !stream
                        .write
                        .upgrade()
                        .is_none_or(|state| state.lock().unwrap().is_finished())
                );
                assert!(draining.as_mut().poll(&mut cx).is_pending());
                drop(send);
            } else {
                drop(send);
                assert!(
                    stream
                        .write
                        .upgrade()
                        .is_none_or(|state| state.lock().unwrap().is_finished())
                );
                assert!(
                    !stream
                        .read
                        .upgrade()
                        .is_none_or(|state| state.lock().unwrap().is_finished())
                );
                assert!(draining.as_mut().poll(&mut cx).is_pending());
                drop(recv);
            }
            assert!(draining.as_mut().poll(&mut cx).is_ready());
        }
    }

    #[tokio::test]
    async fn releasing_connection_references_does_not_cancel_application_handles() {
        let streams = BiStreams::new();
        let (mut send, mut recv) = streams
            .insert(0, std::io::Cursor::new(vec![7]), Vec::new())
            .unwrap();
        let weak = Arc::downgrade(streams.streams.lock().unwrap().get(&0).unwrap());
        drop(streams);
        assert!(weak.upgrade().is_none(), "handles must not retain BiStream");
        send.write_all(b"x").await.unwrap();
        let mut byte = [0];
        recv.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [7]);
    }

    #[test]
    fn sendability_does_not_depend_on_the_opposite_transport_half() {
        fn assert_send<T: Send>(_: &T) {}
        let streams = BiStreams::new();
        let (send, _recv) = streams
            .insert(0, std::rc::Rc::new(()), tokio::io::sink())
            .unwrap();
        assert_send(&send);
        let streams = BiStreams::new();
        let (_send, recv) = streams
            .insert(0, tokio::io::empty(), std::rc::Rc::new(()))
            .unwrap();
        assert_send(&recv);
    }

    #[derive(Default)]
    struct Wakes(std::sync::atomic::AtomicUsize);

    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Wakes {
        fn count(&self) -> usize {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[test]
    fn close_wakes_latest_io_and_drain_waiters_in_either_registration_order() {
        use std::future::Future;

        use tokio::io::AsyncRead;

        for drain_first in [false, true] {
            let streams = BiStreams::new();
            let (read, _read_peer) = tokio::io::duplex(1);
            let (write, _write_peer) = tokio::io::duplex(1);
            let (mut send, mut recv) = streams.insert(0, read, write).unwrap();
            // Fill the transport so the next write must wait.
            assert!(
                Pin::new(&mut send)
                    .poll_write(&mut Context::from_waker(Waker::noop()), b"x")
                    .is_ready()
            );
            let old_io = Arc::new(Wakes::default());
            let latest_io = Arc::new(Wakes::default());
            let old_drain = Arc::new(Wakes::default());
            let latest_drain = Arc::new(Wakes::default());
            let mut draining = Box::pin(streams.drained());
            for register_drain in [drain_first, !drain_first] {
                if register_drain {
                    for wakes in [&old_drain, &latest_drain] {
                        assert!(
                            draining
                                .as_mut()
                                .poll(&mut Context::from_waker(&Waker::from(wakes.clone())))
                                .is_pending()
                        );
                    }
                } else {
                    for wakes in [&old_io, &latest_io] {
                        let waker = Waker::from(wakes.clone());
                        let mut cx = Context::from_waker(&waker);
                        let mut bytes = [0];
                        assert!(
                            Pin::new(&mut recv)
                                .poll_read(&mut cx, &mut tokio::io::ReadBuf::new(&mut bytes))
                                .is_pending()
                        );
                        assert!(Pin::new(&mut send).poll_write(&mut cx, b"y").is_pending());
                    }
                }
            }
            streams.close(Error::H3_INTERNAL_ERROR);
            assert_eq!(old_io.count(), 0);
            assert_eq!(old_drain.count(), 0);
            assert!(latest_io.count() > 0);
            assert!(latest_drain.count() > 0);
            assert!(
                draining
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
            );
        }
    }

    #[tokio::test]
    async fn drain_wakes_after_successful_io_then_fin_or_shutdown_failure() {
        use std::future::Future;

        for fail in [false, true] {
            let streams = BiStreams::new();
            let write: Box<dyn AsyncWrite + Unpin> = if fail {
                Box::new(FailingShutdown(false))
            } else {
                Box::new(tokio::io::sink())
            };
            let (mut send, mut recv) = streams.insert(0, tokio::io::empty(), write).unwrap();
            assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
            let wakes = Arc::new(Wakes::default());
            let waker = Waker::from(wakes.clone());
            let mut draining = Box::pin(streams.drained());
            assert!(
                draining
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            send.write_all(b"x").await.unwrap();
            send.flush().await.unwrap();
            assert_eq!(wakes.count(), 0);
            if fail {
                assert!(
                    Pin::new(&mut send)
                        .poll_shutdown(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                assert_eq!(
                    Error::from(send.shutdown().await.unwrap_err()),
                    Error::H3_REQUEST_REJECTED
                );
            } else {
                send.shutdown().await.unwrap();
            }
            assert!(wakes.count() > 0);
            assert!(
                draining
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_ready()
            );
        }
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
