use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::mpsc;

use super::{
    error::{RegisterSessionError, SessionClosed},
    session::{RoutedBiStream, RoutedUniStream},
};
use crate::stream_id::StreamId;

const SESSION_STREAM_CHANNEL_SIZE: usize = 16;

#[derive(Debug, Default, Clone)]
pub(super) struct Registry {
    inner: Arc<Mutex<HashMap<StreamId, SessionStreamRouter>>>,
}

impl Registry {
    pub(super) fn register(
        &self,
        session_id: StreamId,
    ) -> Result<RegisteredSession, RegisterSessionError> {
        let (bidi_tx, bidi_rx) = mpsc::channel(SESSION_STREAM_CHANNEL_SIZE);
        let (uni_tx, uni_rx) = mpsc::channel(SESSION_STREAM_CHANNEL_SIZE);

        let mut sessions = self
            .inner
            .lock()
            .map_err(|_| RegisterSessionError::RegistryPoisoned)?;

        if sessions.contains_key(&session_id) {
            return Err(RegisterSessionError::AlreadyRegistered { session_id });
        }

        sessions.insert(session_id, SessionStreamRouter::new(bidi_tx, uni_tx));

        Ok(RegisteredSession {
            state: Arc::new(SessionState::new(session_id, self.clone())),
            bidi_rx,
            uni_rx,
        })
    }

    pub(super) fn unregister(&self, session_id: StreamId) {
        let Ok(mut sessions) = self.inner.lock() else {
            tracing::debug!(?session_id, "webtransport session registry lock poisoned");
            return;
        };
        sessions.remove(&session_id);
    }

    pub(super) fn route_bi(&self, session_id: StreamId, stream: RoutedBiStream) {
        let Ok(sessions) = self.inner.lock() else {
            tracing::debug!(?session_id, "webtransport session registry lock poisoned");
            return;
        };
        if let Some(router) = sessions.get(&session_id) {
            router.route_bi(session_id, stream);
        } else {
            tracing::debug!(
                ?session_id,
                "no registered session for webtransport bidi stream"
            );
        }
    }

    pub(super) fn route_uni(&self, session_id: StreamId, stream: RoutedUniStream) {
        let Ok(sessions) = self.inner.lock() else {
            tracing::debug!(?session_id, "webtransport session registry lock poisoned");
            return;
        };
        if let Some(router) = sessions.get(&session_id) {
            router.route_uni(session_id, stream);
        } else {
            tracing::debug!(
                ?session_id,
                "no registered session for webtransport uni stream"
            );
        }
    }

    pub(super) fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }
}

#[derive(Debug)]
pub(super) struct RegisteredSession {
    pub(super) state: Arc<SessionState>,
    pub(super) bidi_rx: mpsc::Receiver<RoutedBiStream>,
    pub(super) uni_rx: mpsc::Receiver<RoutedUniStream>,
}

#[derive(Debug)]
pub(super) struct SessionState {
    session_id: StreamId,
    registry: Registry,
    closed: AtomicBool,
}

impl SessionState {
    fn new(session_id: StreamId, registry: Registry) -> Self {
        Self {
            session_id,
            registry,
            closed: AtomicBool::new(false),
        }
    }

    pub(super) fn id(&self) -> StreamId {
        self.session_id
    }

    pub(super) fn check_open(&self) -> Result<(), SessionClosed> {
        if self.closed.load(Ordering::Acquire) {
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    pub(super) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.registry.unregister(self.session_id);
        }
    }
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Debug)]
struct SessionStreamRouter {
    bidi_tx: mpsc::Sender<RoutedBiStream>,
    uni_tx: mpsc::Sender<RoutedUniStream>,
}

impl SessionStreamRouter {
    fn new(bidi_tx: mpsc::Sender<RoutedBiStream>, uni_tx: mpsc::Sender<RoutedUniStream>) -> Self {
        Self { bidi_tx, uni_tx }
    }

    fn route_bi(&self, session_id: StreamId, stream: RoutedBiStream) {
        if self.bidi_tx.try_send(stream).is_err() {
            tracing::debug!(
                ?session_id,
                "session bidi channel full or closed, dropping stream"
            );
        }
    }

    fn route_uni(&self, session_id: StreamId, stream: RoutedUniStream) {
        if self.uni_tx.try_send(stream).is_err() {
            tracing::debug!(
                ?session_id,
                "session uni channel full or closed, dropping stream"
            );
        }
    }
}
