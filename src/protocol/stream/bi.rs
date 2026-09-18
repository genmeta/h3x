//! Connection ownership and GOAWAY dispatch for bidirectional streams.
use std::{
    collections::HashMap,
    mem,
    sync::{Arc, Mutex, Weak},
};

use qbase::{ArcReceiving, sid::StreamId};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::sync::Notify;

use super::{Goaway, H3ReadStream, H3Stream, H3WriteStream, view::StreamView};
use crate::{ArcQpack, Error, ErrorCode, Result, Role};

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

    fn terminate(&self, code: u64, goaway: bool) -> bool {
        let mut changed = false;
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
                waker.wake();
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
                waker.wake();
            }
        }
        changed
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

    fn reject_from(&mut self, id: u64) -> Vec<u64> {
        let mut rejected = Vec::new();
        for (stream_id, stream) in &self.streams {
            if *stream_id % 4 != id % 4 || *stream_id < id {
                continue;
            }
            if stream.terminate(ErrorCode::H3_REQUEST_REJECTED.as_u64(), true) {
                rejected.push(*stream_id);
            }
        }
        rejected
    }

    /// Freeze admission and cancel rejected requests without waiting for the write.
    pub(crate) fn local_goaway(&mut self, qpack: &ArcQpack) -> Result<()> {
        let id = self.view.local_goaway();
        let rejected = self.reject_from(id.into());
        self.drain_notify.notify_waiters();
        self.cleanup();
        for id in rejected {
            qpack.cancel(id)?
        }
        Ok(())
    }

    pub(crate) fn receive_goaway(&mut self, id: StreamId, qpack: ArcQpack) -> Result<()> {
        self.view.receive_goaway(id);
        let rejected = self.reject_from(id.into());
        self.drain_notify.notify_waiters();
        self.cleanup();
        for id in rejected {
            qpack.cancel(id)?
        }
        Ok(())
    }

    pub(crate) fn close(&mut self, error: Error) {
        for stream in mem::take(&mut self.streams).into_values() {
            stream.terminate(error.code.as_u64(), false);
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
