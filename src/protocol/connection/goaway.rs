//! GOAWAY state, admission notifications, and queued frame completion.

use std::sync::Mutex;

use qbase::varint::{VARINT_MAX, VarInt};
use tokio::sync::{Notify, oneshot, watch};

use crate::{
    Error, Result,
    protocol::{
        frame::{self, Frame, H3Frame},
        qpack::Qpack,
        stream::UniStreams,
    },
};

pub(super) enum GoawayState {
    Open {
        accepted_boundary: u64,
        peer: Option<u64>,
    },
    Draining {
        boundary: u64,
        peer: Option<u64>,
    },
}

impl Default for GoawayState {
    fn default() -> Self {
        Self::Open {
            accepted_boundary: 0,
            peer: None,
        }
    }
}

impl GoawayState {
    pub(super) fn local(&self) -> Option<u64> {
        match self {
            Self::Open { .. } => None,
            Self::Draining { boundary, .. } => Some(*boundary),
        }
    }

    pub(super) fn peer(&self) -> Option<u64> {
        match self {
            Self::Open { peer, .. } | Self::Draining { peer, .. } => *peer,
        }
    }

    pub(super) fn accept(&mut self, id: u64) -> Result<()> {
        match self {
            Self::Open {
                accepted_boundary, ..
            } => {
                *accepted_boundary = (*accepted_boundary).max(id + 4);
                Ok(())
            }
            Self::Draining { .. } => Err(Error::H3_REQUEST_REJECTED),
        }
    }

    fn drain(&mut self) -> Result<u64> {
        match *self {
            Self::Open {
                accepted_boundary,
                peer,
            } => {
                if accepted_boundary > VARINT_MAX {
                    return Err(Error::H3_ID_ERROR);
                }
                *self = Self::Draining {
                    boundary: accepted_boundary,
                    peer,
                };
                Ok(accepted_boundary)
            }
            Self::Draining { boundary, .. } => Ok(boundary),
        }
    }
}

#[derive(Default)]
pub(crate) struct Goaway {
    pub(super) state: Mutex<GoawayState>,
    draining: Notify,
    received: Notify,
    // Concurrent callers share the driver's single GOAWAY write result.
    written: watch::Sender<Option<Result<()>>>,
}

impl Goaway {
    pub(super) fn is_draining(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.local().or(state.peer()).is_some()
    }

    pub(super) fn begin_draining(&self) -> Result<()> {
        self.state.lock().unwrap().drain()?;
        self.draining.notify_waiters();
        Ok(())
    }

    /// Wait until this endpoint stops admitting new request streams.
    pub(super) async fn draining(&self) {
        // Subscribe before checking state so a concurrent notification cannot be missed.
        let draining = self.draining.notified();
        if self.state.lock().unwrap().local().is_some() {
            return;
        }
        draining.await;
    }

    pub(super) async fn written(&self, qpack: &Qpack) -> Result<()> {
        let mut written = self.written.subscribe();
        tokio::select! {
            biased;
            // Preserve a completed write if the transport terminates before
            // the caller is polled again.
            result = written.wait_for(Option::is_some) => {
                result.expect("GOAWAY retains its completion sender").unwrap()
            }
            error = qpack.terminated() => Err(error),
        }
    }

    /// Wait until a valid peer GOAWAY has been received.
    pub(super) async fn received(&self) {
        let received = self.received.notified();
        if self.state.lock().unwrap().peer().is_some() {
            return;
        }
        received.await;
    }

    pub(crate) fn receive(&self, id: u64) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            let peer = match &mut *state {
                GoawayState::Open { peer, .. } | GoawayState::Draining { peer, .. } => peer,
            };
            if peer.is_some_and(|previous| id > previous) {
                return Err(Error::H3_ID_ERROR);
            }
            *peer = Some(id);
        }
        self.received.notify_waiters();
        Ok(())
    }
}

pub(super) async fn send_goaway(uni: &UniStreams) -> Result<()> {
    let permit = tokio::select! {
        biased;
        error = uni.qpack.terminated() => return Err(error),
        permit = uni.control.sender.reserve() => {
            permit.map_err(|_| uni.qpack.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM))?
        }
    };
    let (completed, completion) = oneshot::channel();
    {
        let state = uni.goaway.state.lock().unwrap();
        uni.qpack.error().map_or(Ok(()), Err)?;
        let id = state.local().expect("draining before sending GOAWAY");
        let frame = H3Frame::Goaway(Frame::new(frame::Goaway {
            id: VarInt::try_from(id).unwrap(),
        })?);
        permit.send((frame, completed));
    }
    let result = tokio::select! {
        biased;
        error = uni.qpack.terminated() => Err(error),
        result = completion => {
            result.unwrap_or_else(|_| Err(uni.qpack.error().unwrap_or(Error::H3_CLOSED_CRITICAL_STREAM)))
        }
    };
    uni.goaway.written.send_replace(Some(result));
    result
}
