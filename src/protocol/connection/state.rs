//! Connection state: termination, GOAWAY boundaries, and pending request registration.
//! Admission checks and transitions share the state lock, including rejection and cancellation.
//! Stream parsing, request delivery, and task supervision live in the connection flows.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use bytes::Bytes;
use futures::future::AbortHandle;
use qbase::varint::{VarInt, WriteVarInt};
use tokio::sync::{oneshot, watch};

use super::{H3Connection, ResponseReply, map_connection_error};
use crate::{
    ChunkBody, Code, Error, StreamId,
    transport::{self, ResetOnDrop},
    wire::ChunkReader,
};

#[derive(Default)]
pub(super) struct Goaway {
    pub(super) local_boundary: Option<u64>,
    pub(super) peer_boundary: Option<StreamId>,
    pub(super) max_delivered: Option<StreamId>,
}
impl Goaway {
    pub(super) fn begin_shutdown(&mut self) -> Result<u64, Error> {
        if self.local_boundary.is_some() {
            return Err(Error::invalid_state("shutdown"));
        }
        let boundary = self
            .max_delivered
            .map_or(Some(0), |id| u64::from(id).checked_add(4))
            .filter(|v| *v <= qbase::varint::VARINT_MAX)
            .ok_or_else(|| {
                Error::connection_protocol(Code::H3_ID_ERROR, "GOAWAY boundary overflow")
            })?;
        self.local_boundary = Some(boundary);
        Ok(boundary)
    }
}

#[derive(Default)]
pub(super) struct ConnectionState {
    pub(super) terminated: bool,
    pub(super) directions: usize,
    pub(super) queued: VecDeque<super::QueuedRequest>,
    pub(super) goaway: Goaway,
    pub(super) preparations: HashMap<usize, AbortHandle>,
    next_preparation: usize,
    pub(super) pending_accepts: HashMap<StreamId, AbortHandle>,
    pub(super) pending_responses: HashMap<StreamId, (ResponseReply, AbortHandle)>,
}
impl ConnectionState {
    pub(super) fn is_drained(&self) -> bool {
        self.preparations.is_empty() && self.pending_accepts.is_empty() && self.directions == 0
    }

    pub(super) fn cancel_preparations(&mut self) {
        for stop in self.preparations.values() {
            stop.abort();
        }
        for stop in self.pending_accepts.values() {
            stop.abort();
        }
    }

    pub(super) fn reject_responses_from(&mut self, boundary: StreamId) {
        let covered: Vec<_> = self
            .pending_responses
            .keys()
            .copied()
            .filter(|id| *id >= boundary)
            .collect();
        for id in covered {
            if let Some((reply, stop)) = self.pending_responses.remove(&id) {
                let _ = reply.send(Err(Error::Goaway { boundary }));
                stop.abort();
            }
        }
    }
}

pub(super) struct PendingIncoming<T: transport::Connection> {
    pub(super) connection: Arc<H3Connection<T>>,
    pub(super) stream_id: StreamId,
}
impl<T: transport::Connection> Drop for PendingIncoming<T> {
    fn drop(&mut self) {
        self.connection
            .state
            .lock()
            .unwrap()
            .pending_accepts
            .remove(&self.stream_id);
        self.connection.state_changed.notify_one();
    }
}
pub(super) struct PendingResponse<T: transport::Connection> {
    pub(super) connection: Arc<H3Connection<T>>,
    pub(super) stream_id: StreamId,
}
impl<T: transport::Connection> Drop for PendingResponse<T> {
    fn drop(&mut self) {
        self.connection
            .state
            .lock()
            .unwrap()
            .pending_responses
            .remove(&self.stream_id);
    }
}

pub(super) async fn stopped(terminal: &watch::Sender<Option<Error>>) -> Error {
    let mut receiver = terminal.subscribe();
    receiver
        .wait_for(|value| value.is_some())
        .await
        .expect("H3Connection owns terminal sender")
        .clone()
        .unwrap()
}

impl<T: transport::Connection> H3Connection<T> {
    pub(super) fn failure(&self) -> Error {
        self.terminal
            .borrow()
            .clone()
            .unwrap_or(Error::OwnerStopped)
    }

    pub(super) fn is_draining(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.terminated
            || state.goaway.local_boundary.is_some()
            || state.goaway.peer_boundary.is_some()
    }

    // Record the first terminal error and wake the driver to close the transport.
    pub(crate) fn terminate(&self, error: Error) {
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return;
        }
        state.terminated = true;
        state.cancel_preparations();
        for (_, (reply, stop)) in state.pending_responses.drain() {
            let _ = reply.send(Err(error.clone()));
            stop.abort();
        }
        self.terminal.send_replace(Some(error));
        let queued = std::mem::take(&mut state.queued);
        drop(state);
        // Stream cleanup calls back into the state; release the lock first.
        drop(queued);
    }

    pub(super) fn check<V>(&self, result: Result<V, Error>) -> Result<V, Error> {
        if let Err(error) = &result
            && error.is_connection()
        {
            self.terminate(error.clone());
        }
        result
    }

    pub(super) fn prepare_request(
        self: &Arc<Self>,
    ) -> Result<(Preparation<T>, super::AbortRegistration), Error> {
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return Err(self.failure());
        }
        if let Some(boundary) = state.goaway.peer_boundary {
            return Err(Error::Goaway { boundary });
        }
        if state.goaway.local_boundary.is_some() {
            return Err(Error::Draining);
        }
        let (stop, cancellation) = AbortHandle::new_pair();
        let id = state.next_preparation;
        state.next_preparation += 1;
        state.preparations.insert(id, stop);
        Ok((
            Preparation {
                connection: self.clone(),
                id,
            },
            cancellation,
        ))
    }

    /// Only the number of live directions is needed for graceful shutdown.
    pub(super) fn track_request(
        self: &Arc<Self>,
        reader: &mut super::MessageReader,
        writer: &mut ResetOnDrop,
    ) {
        self.state.lock().unwrap().directions += 2;
        let finished = || {
            let connection = Arc::downgrade(self);
            move || {
                if let Some(connection) = connection.upgrade() {
                    connection.state.lock().unwrap().directions -= 1;
                    connection.state_changed.notify_one();
                }
            }
        };
        reader.on_finish(finished());
        writer.on_finish(finished());
    }

    pub(super) async fn drained(&self) {
        // There is one shutdown waiter; notify_one retains a wake between this check and await.
        while !self.state.lock().unwrap().is_drained() {
            self.state_changed.notified().await;
        }
    }

    pub(super) fn on_peer_goaway(&self, value: u64) -> Result<(), Error> {
        let role = self.transport.role().map_err(map_connection_error)?;
        if value != 0 && value & 3 != role as u64 {
            return Err(Error::connection_protocol(
                Code::H3_ID_ERROR,
                "GOAWAY has the wrong stream role",
            ));
        }
        let boundary = VarInt::try_from(value)
            .map(StreamId::from)
            .map_err(|_| Error::invalid_stream_id(value))?;
        let mut state = self.state.lock().unwrap();
        if !state.terminated {
            if state
                .goaway
                .peer_boundary
                .is_some_and(|previous| boundary > previous)
            {
                return Err(Error::connection_protocol(
                    Code::H3_ID_ERROR,
                    "GOAWAY boundary increased",
                ));
            }
            state.goaway.peer_boundary = Some(boundary);
            state.reject_responses_from(boundary);
        }
        Ok(())
    }

    pub(super) fn register_pending_response(
        self: &Arc<Self>,
        id: StreamId,
    ) -> Result<
        (
            super::ResponseFuture,
            PendingResponse<T>,
            super::AbortRegistration,
        ),
        Error,
    > {
        let (reply, receive) = oneshot::channel();
        let (stop, registration) = AbortHandle::new_pair();
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return Err(self.failure());
        }
        if state.goaway.local_boundary.is_some() {
            return Err(Error::Draining);
        }
        if let Some(boundary) = state.goaway.peer_boundary
            && id >= boundary
        {
            return Err(Error::Goaway { boundary });
        }
        state.pending_responses.insert(id, (reply, stop.clone()));
        drop(state);
        Ok((
            super::ResponseFuture {
                reply: receive,
                stop: Some(stop),
            },
            PendingResponse {
                connection: self.clone(),
                stream_id: id,
            },
            registration,
        ))
    }

    pub(super) fn complete_response(
        &self,
        id: StreamId,
        result: Result<http::Response<ChunkBody>, Error>,
    ) {
        let pending = self.state.lock().unwrap().pending_responses.remove(&id);
        // Releasing a Body may report a QPACK error; never drop it under the state lock.
        if let Some((reply, stop)) = pending {
            if result.is_err() {
                stop.abort();
            }
            let _ = reply.send(result);
        }
    }

    pub(super) fn register_incoming(
        &self,
        id: StreamId,
        stop: AbortHandle,
        reader: &mut ChunkReader,
        writer: &mut ResetOnDrop,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return Err(self.failure());
        }
        if state.goaway.local_boundary.is_some() {
            writer.reset(Code::H3_REQUEST_REJECTED);
            reader.stop(Code::H3_REQUEST_REJECTED)?;
            return Err(Error::request_rejected("connection draining"));
        }
        state.pending_accepts.insert(id, stop);
        Ok(())
    }

    pub(super) fn begin_shutdown(&self) -> Result<Bytes, Error> {
        let mut state = self.state.lock().unwrap();
        if state.terminated {
            return Err(Error::invalid_state("shutdown"));
        }
        let boundary = state.goaway.begin_shutdown()?;
        state.cancel_preparations();
        let mut payload = Vec::new();
        payload.put_varint(&VarInt::try_from(boundary).expect("validated GOAWAY boundary"));
        let queued = std::mem::take(&mut state.queued);
        drop(state);
        drop(queued);
        Ok(Bytes::from(payload))
    }
}

pub(super) struct Preparation<T: transport::Connection> {
    connection: Arc<H3Connection<T>>,
    id: usize,
}
impl<T: transport::Connection> Drop for Preparation<T> {
    fn drop(&mut self) {
        self.connection
            .state
            .lock()
            .unwrap()
            .preparations
            .remove(&self.id);
        self.connection.state_changed.notify_one();
    }
}
