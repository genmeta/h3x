//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    mem,
    sync::{Arc, Mutex, Weak},
};

use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::sync::Notify;

use super::{Goaway, H3ReadStream, H3Stream, H3WriteStream};
use crate::{Error, ErrorCode, Result};

/// Observes application-owned directions without extending their lifetimes.
pub(crate) struct BiStream<R, W> {
    id: u64,
    read: Weak<Mutex<std::result::Result<H3Stream<R>, Goaway>>>,
    write: Weak<Mutex<std::result::Result<H3Stream<W>, Goaway>>>,
}

impl<R: StopSending, W: CancelStream> BiStream<R, W> {
    fn is_finished(&self) -> bool {
        self.read.upgrade().is_none_or(|state| {
            state
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
        }) && self.write.upgrade().is_none_or(|state| {
            state
                .lock()
                .unwrap()
                .as_ref()
                .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
        })
    }

    fn terminate(&self, code: u64, goaway: bool) {
        if let Some(state) = self.read.upgrade() {
            let mut state = state.lock().unwrap();
            let waker = if goaway {
                super::goaway(&mut state, |io| io.stop(code))
            } else {
                super::terminate(&mut state, |io| io.stop(code))
            };
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        if let Some(state) = self.write.upgrade() {
            let mut state = state.lock().unwrap();
            let waker = if goaway {
                super::goaway(&mut state, |io| io.cancel(code))
            } else {
                super::terminate(&mut state, |io| io.cancel(code))
            };
            drop(state);
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

pub(crate) struct BiStreams<R, W> {
    streams: Mutex<HashMap<u64, Arc<BiStream<R, W>>>>,
    drain_notify: Arc<Notify>,
}

impl<R: StopSending, W: CancelStream> Default for BiStreams<R, W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: StopSending, W: CancelStream> BiStreams<R, W> {
    pub(crate) fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            drain_notify: Arc::default(),
        }
    }

    /// Wait for the fixed set after both GOAWAY directions froze admission.
    /// The connection must freeze admission before calling this method.
    /// Completion is determined from the direction states.
    pub(crate) async fn drained(&self) {
        let running: Vec<_> = self.streams.lock().unwrap().values().cloned().collect();
        loop {
            let notified = self.drain_notify.notified();
            tokio::pin!(notified);
            // Register before inspecting states, so completion during the scan cannot be lost.
            notified.as_mut().enable();
            if running.iter().all(|stream| stream.is_finished()) {
                break;
            }
            notified.await;
        }
        self.cleanup();
    }

    // Idle connections retain finished entries until the next insert or GOAWAY.
    pub(crate) fn cleanup(&self) {
        self.streams
            .lock()
            .unwrap()
            .retain(|_, stream| !stream.is_finished());
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
            stream.terminate(ErrorCode::H3_REQUEST_REJECTED.as_u64(), true);
        }
        self.drain_notify.notify_waiters();
        self.cleanup();
        rejected
    }

    pub(crate) fn close(&self, error: Error) {
        let streams = mem::take(&mut *self.streams.lock().unwrap());
        for stream in streams.into_values() {
            stream.terminate(error.code.as_u64(), false);
        }
        self.drain_notify.notify_waiters();
    }

    pub(crate) fn insert(
        &self,
        id: u64,
        recv: R,
        send: W,
    ) -> Result<(H3WriteStream<W>, H3ReadStream<R>)> {
        self.cleanup();
        let read = H3ReadStream::new_observed(id, recv, self.drain_notify.clone());
        let write = H3WriteStream::new_observed(id, send, self.drain_notify.clone());
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
impl<R: StopSending, W: CancelStream> BiStreams<R, W> {
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
    use crate::test_support::TestStream;

    #[tokio::test]
    async fn drain_waits_for_both_halves_and_remembers_early_completion() {
        use std::future::Future;

        for early in [false, true] {
            for read_first in [false, true] {
                let streams = BiStreams::new();
                let (mut send, mut recv) = streams
                    .insert(
                        0,
                        TestStream::new(tokio::io::empty()),
                        TestStream::new(tokio::io::sink()),
                    )
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
            .insert(
                0,
                TestStream::new(tokio::io::empty()),
                TestStream::new(tokio::io::sink()),
            )
            .unwrap();
        let draining = tokio::spawn({
            let streams = streams.clone();
            async move { streams.drained().await }
        });
        tokio::task::yield_now().await;
        assert!(!draining.is_finished());
        streams.close(ErrorCode::H3_INTERNAL_ERROR.reason("test terminates an active stream"));
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
        let (send, mut recv) = streams
            .insert(0, Recv(read_code.clone()), Send(write_code.clone()))
            .unwrap();
        let mut drained = Box::pin(streams.drained());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(drained.as_mut().poll(&mut cx).is_pending());
        recv.stop(123);
        assert!(drained.as_mut().poll(&mut cx).is_pending());
        (&send).cancel(ErrorCode::H3_MESSAGE_ERROR.as_u64());
        assert!(drained.as_mut().poll(&mut cx).is_ready());
        recv.stop(789);
        (&send).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
        assert_eq!(read_code.load(Ordering::SeqCst), 123);
        assert_eq!(
            write_code.load(Ordering::SeqCst),
            ErrorCode::H3_MESSAGE_ERROR.as_u64()
        );
    }

    #[test]
    fn dropping_an_application_handle_only_terminates_its_direction() {
        use std::future::Future;

        for read_first in [false, true] {
            let streams = BiStreams::new();
            let (send, recv) = streams
                .insert(
                    0,
                    TestStream::new(tokio::io::empty()),
                    TestStream::new(tokio::io::sink()),
                )
                .unwrap();
            let stream = streams.streams.lock().unwrap().get(&0).unwrap().clone();
            let mut draining = Box::pin(streams.drained());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(draining.as_mut().poll(&mut cx).is_pending());
            if read_first {
                drop(recv);
                assert!(stream.read.upgrade().is_none_or(|state| {
                    state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
                }));
                assert!(!stream.write.upgrade().is_none_or(|state| {
                    state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
                }));
                assert!(draining.as_mut().poll(&mut cx).is_pending());
                drop(send);
            } else {
                drop(send);
                assert!(stream.write.upgrade().is_none_or(|state| {
                    state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
                }));
                assert!(!stream.read.upgrade().is_none_or(|state| {
                    state
                        .lock()
                        .unwrap()
                        .as_ref()
                        .map_or(true, |s| matches!(s, super::H3Stream::Finished(_)))
                }));
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
            .insert(
                0,
                TestStream::new(std::io::Cursor::new(vec![7])),
                TestStream::new(Vec::new()),
            )
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
            .insert(
                0,
                TestStream::new(std::rc::Rc::new(())),
                TestStream::new(tokio::io::sink()),
            )
            .unwrap();
        assert_send(&send);
        let streams = BiStreams::new();
        let (_send, recv) = streams
            .insert(
                0,
                TestStream::new(tokio::io::empty()),
                TestStream::new(std::rc::Rc::new(())),
            )
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
            let (mut send, mut recv) = streams
                .insert(0, TestStream::new(read), TestStream::new(write))
                .unwrap();
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
            streams.close(ErrorCode::H3_INTERNAL_ERROR.reason("test terminates an active stream"));
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
    async fn shared_notification_wakes_all_drains_and_rechecks_every_stream() {
        use std::future::Future;

        let streams = BiStreams::new();
        let (mut send0, mut recv0) = streams
            .insert(
                0,
                TestStream::new(tokio::io::empty()),
                TestStream::new(tokio::io::sink()),
            )
            .unwrap();
        let (send4, recv4) = streams
            .insert(
                4,
                TestStream::new(tokio::io::empty()),
                TestStream::new(tokio::io::sink()),
            )
            .unwrap();
        let mut first = Box::pin(streams.drained());
        let mut second = Box::pin(streams.drained());
        let first_wakes = Arc::new(Wakes::default());
        let second_wakes = Arc::new(Wakes::default());
        let first_waker = std::task::Waker::from(first_wakes.clone());
        let second_waker = std::task::Waker::from(second_wakes.clone());
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);
        assert!(first.as_mut().poll(&mut first_cx).is_pending());
        assert!(second.as_mut().poll(&mut second_cx).is_pending());

        // Finishing one direction wakes both waiters, but does not complete either drain.
        assert_eq!(recv0.read(&mut [0]).await.unwrap(), 0);
        assert!(first_wakes.count() > 0);
        assert!(second_wakes.count() > 0);
        assert!(first.as_mut().poll(&mut first_cx).is_pending());
        assert!(second.as_mut().poll(&mut second_cx).is_pending());
        let before = (first_wakes.count(), second_wakes.count());

        // GOAWAY removes another request from the registry while both drains hold snapshots.
        assert_eq!(streams.goaway(4), [4]);
        assert!(first_wakes.count() > before.0);
        assert!(second_wakes.count() > before.1);
        assert!(first.as_mut().poll(&mut first_cx).is_pending());
        assert!(second.as_mut().poll(&mut second_cx).is_pending());
        let before = (first_wakes.count(), second_wakes.count());

        send0.shutdown().await.unwrap();
        assert!(first_wakes.count() > before.0);
        assert!(second_wakes.count() > before.1);
        assert!(first.as_mut().poll(&mut first_cx).is_ready());
        assert!(second.as_mut().poll(&mut second_cx).is_ready());
        assert_eq!(streams.len(), 0);
        drop((send4, recv4));
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
            let (mut send, mut recv) = streams
                .insert(
                    0,
                    TestStream::new(tokio::io::empty()),
                    TestStream::new(write),
                )
                .unwrap();
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
                    ErrorCode::from(send.shutdown().await.unwrap_err()),
                    ErrorCode::H3_REQUEST_REJECTED
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
                Poll::Ready(Err(ErrorCode::H3_REQUEST_REJECTED
                    .reason("test peer rejects stream shutdown")
                    .into()))
            }
        }
    }

    #[tokio::test]
    async fn pending_shutdown_keeps_entry_and_failure_reaps_without_dropping_handles() {
        let streams = Arc::new(BiStreams::default());
        let (mut send, mut recv) = streams
            .insert(
                0,
                TestStream::new(tokio::io::empty()),
                TestStream::new(FailingShutdown(false)),
            )
            .unwrap();
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut send).poll_shutdown(&mut cx).is_pending());
        streams.cleanup();
        assert_eq!(streams.len(), 1);
        let error = poll_fn(|cx| Pin::new(&mut send).poll_shutdown(cx))
            .await
            .unwrap_err();
        assert_eq!(ErrorCode::from(error), ErrorCode::H3_REQUEST_REJECTED);
        streams.cleanup();
        assert_eq!(streams.len(), 0);
        // The shutdown error is returned directly, not cached for later operations.
        send.flush().await.unwrap();
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
    }
}
