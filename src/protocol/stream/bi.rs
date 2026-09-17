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
