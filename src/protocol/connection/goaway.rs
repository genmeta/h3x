//! Directional stream cursors and the actual GOAWAY operation's waiters.

use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::{Poll, Waker},
};

use qbase::varint::VARINT_MAX;

use crate::{
    Error, Result, Role, Transport,
    protocol::{
        connection::Settings,
        qpack::Qpack,
        stream::{bi::BiStreams, control},
    },
};

/// Max(u64::MAX) means no stream has been observed; it is never sent on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamView {
    Max(u64),
    Gone(u64),
}

pub(crate) struct StreamCursor {
    pub(super) role: Role,
    pub(super) local: StreamView,
    pub(super) peer: StreamView,
    local_waiter: Option<Waker>,
    peer_waiter: Option<Waker>,
    goaway_written: Option<Result<()>>,
    // goaway() and the control reader each wait for this same write operation.
    written_waiters: Vec<Waker>,
}

impl StreamCursor {
    pub(super) fn new<T: Transport>(
        transport: Arc<T>,
        settings: Arc<Settings>,
        qpack: Arc<Qpack<T>>,
        bi: Arc<BiStreams<T::Recv, T::Send>>,
    ) -> Arc<Mutex<Self>> {
        let cursor = Arc::new(Mutex::new(Self::for_role(transport.role())));
        tokio::spawn({
            let cursor = cursor.clone();
            async move { control::send(transport.as_ref(), &settings, &qpack, &cursor, &bi).await }
        });
        cursor
    }

    pub(super) fn for_role(role: Role) -> Self {
        Self {
            role,
            local: StreamView::Max(u64::MAX),
            peer: StreamView::Max(u64::MAX),
            local_waiter: None,
            peer_waiter: None,
            goaway_written: None,
            written_waiters: Vec::new(),
        }
    }

    pub(crate) fn peer(&self) -> Option<u64> {
        match self.peer {
            StreamView::Gone(id) => Some(id),
            _ => None,
        }
    }

    pub(super) fn accept(&mut self, id: u64) -> Result<()> {
        match &mut self.local {
            StreamView::Max(max) => {
                *max = if *max == u64::MAX { id } else { (*max).max(id) };
                Ok(())
            }
            StreamView::Gone(_) => Err(Error::H3_REQUEST_REJECTED),
        }
    }

    pub(super) fn boundary(&self) -> Result<u64> {
        let id = match self.local {
            StreamView::Gone(id) => id,
            StreamView::Max(u64::MAX) => u64::from(self.role == Role::Client),
            StreamView::Max(id) => id.checked_add(4).ok_or(Error::H3_ID_ERROR)?,
        };
        if id > VARINT_MAX {
            return Err(Error::H3_ID_ERROR);
        }
        Ok(id)
    }

    pub(crate) fn goaway(&mut self) -> Result<Option<Waker>> {
        if matches!(self.local, StreamView::Gone(_)) {
            return Ok(None);
        }
        self.local = StreamView::Gone(self.boundary()?);
        Ok(self.local_waiter.take())
    }

    pub(crate) fn receive(&mut self, id: u64) -> Result<Option<Waker>> {
        let expected = u64::from(self.role == Role::Server);
        if id % 4 != expected || self.peer().is_some_and(|previous| id > previous) {
            return Err(Error::H3_ID_ERROR);
        }
        self.peer = StreamView::Gone(id);
        Ok(self.peer_waiter.take())
    }

    pub(crate) async fn local(cursor: &Mutex<Self>) -> u64 {
        poll_fn(|cx| {
            let mut state = cursor.lock().unwrap();
            match state.local {
                StreamView::Gone(id) => Poll::Ready(id),
                StreamView::Max(_) => {
                    state.local_waiter = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    pub(crate) async fn received(cursor: &Mutex<Self>) -> u64 {
        poll_fn(|cx| {
            let mut state = cursor.lock().unwrap();
            match state.peer() {
                Some(id) => Poll::Ready(id),
                None => {
                    state.peer_waiter = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    pub(crate) async fn written(cursor: &Mutex<Self>) -> Result<()> {
        poll_fn(|cx| {
            let mut state = cursor.lock().unwrap();
            if let Some(result) = state.goaway_written {
                return Poll::Ready(result);
            }
            if !state
                .written_waiters
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                state.written_waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
        .await
    }

    pub(crate) fn complete_write(cursor: &Mutex<Self>, result: Result<()>) {
        let waiters = {
            let mut state = cursor.lock().unwrap();
            if state.goaway_written.is_some() {
                return;
            }
            state.goaway_written = Some(result);
            std::mem::take(&mut state.written_waiters)
        };
        for waker in waiters {
            waker.wake();
        }
    }
}
