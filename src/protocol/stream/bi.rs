//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    mem,
    sync::{Arc, Mutex, Weak},
    task::Waker,
};

use qbase::{ArcReceiving, sid::StreamId};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::sync::Notify;

use super::{Goaway, H3ReadStream, H3Stream, H3WriteStream, view::StreamView};
use crate::{Error, ErrorCode, Result, Role};

/// Observes application-owned directions without extending their lifetimes.
pub(crate) struct BiStream<R, W> {
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

    fn terminate(&self, code: u64, goaway: bool) -> (bool, Vec<Waker>) {
        let mut changed = false;
        let mut wakers = Vec::new();
        if let Some(state) = self.read.upgrade() {
            let mut state = state.lock().unwrap();
            changed |= goaway && !super::is_finished(&state);
            let waker = if goaway {
                super::goaway(&mut state, |io| io.stop(code))
            } else {
                super::terminate(&mut state, |io| io.stop(code))
            };
            drop(state);
            if let Some(waker) = waker {
                wakers.push(waker);
            }
        }
        if let Some(state) = self.write.upgrade() {
            let mut state = state.lock().unwrap();
            changed |= goaway && !super::is_finished(&state);
            let waker = if goaway {
                super::goaway(&mut state, |io| io.cancel(code))
            } else {
                super::terminate(&mut state, |io| io.cancel(code))
            };
            drop(state);
            if let Some(waker) = waker {
                wakers.push(waker);
            }
        }
        (changed, wakers)
    }
}

/// Admission boundaries and registered streams share the connection's lock.
pub(crate) struct BiStreams<R, W> {
    view: StreamView,
    streams: HashMap<u64, Arc<BiStream<R, W>>>,
    drain_notify: Arc<Notify>,
}

impl<R: StopSending, W: CancelStream> BiStreams<R, W> {
    pub(crate) fn new(role: Role) -> Self {
        Self {
            view: StreamView::new(role),
            streams: HashMap::new(),
            drain_notify: Arc::default(),
        }
    }

    pub(crate) fn can_accept(&self) -> Result<()> {
        self.view.local_not_goaway()
    }

    pub(crate) fn can_open(&self) -> Result<()> {
        self.view.remote_not_goway()
    }

    pub(crate) fn accept(&mut self, id: StreamId) -> Result<()> {
        self.view.accept(id)
    }

    pub(crate) fn send_goaway(&self) -> impl Future<Output = StreamId> + use<R, W> {
        self.view.local_goaway_notification()
    }

    pub(crate) fn goaway_written(&self) -> impl Future<Output = Result<()>> + use<R, W> {
        self.view.goaway_written()
    }

    pub(crate) fn on_goaway_written(&self, result: Result<()>) {
        self.view.on_goaway_written(result);
    }

    pub(crate) fn recv_goway(&self) -> ArcReceiving<()> {
        self.view.remote_goaway_notification()
    }

    /// Wait for the fixed set after both GOAWAY directions froze admission.
    /// The connection must freeze admission before calling this method.
    /// Completion is determined from the direction states.
    pub(crate) fn drained(&self) -> impl Future<Output = ()> + use<R, W> {
        let running: Vec<_> = self.streams.values().cloned().collect();
        let notify = self.drain_notify.clone();
        async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                // Register before inspecting states, so completion during the scan cannot be lost.
                notified.as_mut().enable();
                if running.iter().all(|stream| stream.is_finished()) {
                    break;
                }
                notified.await;
            }
        }
    }

    // Idle connections retain finished entries until the next insert or GOAWAY.
    pub(crate) fn cleanup(&mut self) {
        self.streams.retain(|_, stream| !stream.is_finished());
    }

    fn reject_from(&mut self, id: u64) -> (Vec<u64>, Vec<Waker>) {
        let mut rejected = Vec::new();
        let mut wakers = Vec::new();
        for (stream_id, stream) in &self.streams {
            if *stream_id % 4 != id % 4 || *stream_id < id {
                continue;
            }
            let (changed, mut stream_wakers) =
                stream.terminate(ErrorCode::H3_REQUEST_REJECTED.as_u64(), true);
            if changed {
                rejected.push(*stream_id);
            }
            wakers.append(&mut stream_wakers);
        }
        (rejected, wakers)
    }

    pub(crate) fn local_goaway(&mut self) -> (StreamId, Vec<u64>) {
        let id = self.view.local_goaway();
        let (rejected, wakers) = self.reject_from(id.into());
        wakers.into_iter().for_each(Waker::wake);
        self.drain_notify.notify_waiters();
        self.cleanup();
        (id, rejected)
    }

    pub(crate) fn receive_goaway(&mut self, id: StreamId) -> Vec<u64> {
        self.view.receive_goaway(id);
        let (rejected, wakers) = self.reject_from(id.into());
        wakers.into_iter().for_each(Waker::wake);
        self.drain_notify.notify_waiters();
        self.cleanup();
        rejected
    }

    pub(crate) fn close(&mut self, error: Error) {
        for stream in mem::take(&mut self.streams).into_values() {
            let (_, wakers) = stream.terminate(error.code.as_u64(), false);
            wakers.into_iter().for_each(Waker::wake);
        }
        self.drain_notify.notify_waiters();
    }

    pub(crate) fn insert(
        &mut self,
        id: u64,
        recv: R,
        send: W,
    ) -> (H3WriteStream<W>, H3ReadStream<R>) {
        self.cleanup();
        let read = H3ReadStream::new_observed(id, recv, self.drain_notify.clone());
        let write = H3WriteStream::new_observed(id, send, self.drain_notify.clone());
        self.streams.insert(
            id,
            Arc::new(BiStream {
                read: Arc::downgrade(&read.state),
                write: Arc::downgrade(&write.state),
            }),
        );
        (write, read)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use qbase::sid::{Dir, StreamId};

    use super::*;

    #[derive(Clone, Default)]
    struct Recv(Arc<Mutex<Vec<u64>>>);

    impl StopSending for Recv {
        fn stop(&mut self, error_code: u64) {
            self.0.lock().unwrap().push(error_code);
        }
    }

    #[derive(Clone, Default)]
    struct Send(Arc<Mutex<Vec<u64>>>);

    impl CancelStream for Send {
        fn cancel(&mut self, error_code: u64) {
            self.0.lock().unwrap().push(error_code);
        }
    }

    fn is_goaway<T>(state: &Arc<Mutex<std::result::Result<H3Stream<T>, Goaway>>>) -> bool {
        matches!(*state.lock().unwrap(), Err(Goaway))
    }

    #[test]
    fn received_goaway_rejects_opened_streams_at_the_boundary() {
        let mut streams = BiStreams::new(Role::Client);
        let (below_write, below_read) = streams.insert(0, Recv::default(), Send::default());
        let (rejected_write, rejected_read) = streams.insert(4, Recv::default(), Send::default());

        let rejected = streams.receive_goaway(StreamId::new(Role::Client, Dir::Bi, 1));

        assert_eq!(rejected, vec![4]);
        assert!(!is_goaway(&below_read.state));
        assert!(!is_goaway(&below_write.state));
        assert!(is_goaway(&rejected_read.state));
        assert!(is_goaway(&rejected_write.state));
    }

    #[test]
    fn local_goaway_rejects_peer_streams_at_the_boundary() {
        let mut streams = BiStreams::new(Role::Client);
        streams
            .accept(StreamId::new(Role::Server, Dir::Bi, 0))
            .unwrap();
        let (below_write, below_read) = streams.insert(1, Recv::default(), Send::default());
        let (rejected_write, rejected_read) = streams.insert(5, Recv::default(), Send::default());

        let (boundary, rejected) = streams.local_goaway();

        assert_eq!(u64::from(boundary), 5);
        assert_eq!(rejected, vec![5]);
        assert!(!is_goaway(&below_read.state));
        assert!(!is_goaway(&below_write.state));
        assert!(is_goaway(&rejected_read.state));
        assert!(is_goaway(&rejected_write.state));
    }
}
