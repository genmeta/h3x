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

        let Ok(mut sessions) = self.inner.lock() else {
            return Err(RegisterSessionError::RegistryPoisoned);
        };

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

    pub(super) fn route_bi(
        &self,
        session_id: StreamId,
        stream: RoutedBiStream,
    ) -> Result<(), RoutedBiStream> {
        let Ok(sessions) = self.inner.lock() else {
            tracing::debug!(session_id = %session_id, "webtransport session registry lock poisoned");
            return Err(stream);
        };
        let Some(router) = sessions.get(&session_id) else {
            tracing::debug!(session_id = %session_id, "no registered session for webtransport bidi stream");
            return Err(stream);
        };
        router.route_bi(session_id, stream)
    }

    pub(super) fn route_uni(
        &self,
        session_id: StreamId,
        stream: RoutedUniStream,
    ) -> Result<(), RoutedUniStream> {
        let Ok(sessions) = self.inner.lock() else {
            tracing::debug!(session_id = %session_id, "webtransport session registry lock poisoned");
            return Err(stream);
        };
        let Some(router) = sessions.get(&session_id) else {
            tracing::debug!(session_id = %session_id, "no registered session for webtransport uni stream");
            return Err(stream);
        };
        router.route_uni(session_id, stream)
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

    fn route_bi(&self, session_id: StreamId, stream: RoutedBiStream) -> Result<(), RoutedBiStream> {
        match self.bidi_tx.try_send(stream) {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::debug!(
                    session_id = %session_id,
                    "session bidi channel full or closed, rejecting stream"
                );
                Err(error.into_inner())
            }
        }
    }

    fn route_uni(
        &self,
        session_id: StreamId,
        stream: RoutedUniStream,
    ) -> Result<(), RoutedUniStream> {
        match self.uni_tx.try_send(stream) {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::debug!(
                    session_id = %session_id,
                    "session uni channel full or closed, rejecting stream"
                );
                Err(error.into_inner())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        panic::{AssertUnwindSafe, catch_unwind},
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, Stream};

    use super::*;
    use crate::{
        codec::{BoxReadStream, BoxWriteStream},
        quic::{self, GetStreamIdExt},
        varint::VarInt,
    };

    #[derive(Debug, Default)]
    struct StreamState {
        written: Mutex<Vec<u8>>,
    }

    #[derive(Debug)]
    struct TestReadStream {
        chunks: VecDeque<Bytes>,
        stream_id: VarInt,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    impl quic::GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl quic::GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_read_stream(id: u32, bytes: Vec<u8>) -> BoxReadStream {
        Box::pin(TestReadStream {
            chunks: VecDeque::from([Bytes::from(bytes)]),
            stream_id: VarInt::from_u32(id),
        }) as BoxReadStream
    }

    fn test_write_stream(id: u32, state: Arc<StreamState>) -> BoxWriteStream {
        Box::pin(TestWriteStream {
            state,
            stream_id: VarInt::from_u32(id),
        }) as BoxWriteStream
    }

    fn bidi_stream(id: u32) -> RoutedBiStream {
        let state = Arc::new(StreamState::default());
        (
            test_read_stream(id, vec![id as u8]),
            test_write_stream(id, Arc::clone(&state)),
        )
    }

    fn uni_stream(id: u32) -> RoutedUniStream {
        test_read_stream(id, vec![id as u8])
    }

    fn poison_registry(registry: &Registry) {
        let registry = registry.clone();
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _guard = registry.inner.lock().expect("registry lock should succeed");
            panic!("poison registry mutex");
        }));
    }

    #[test]
    fn register_len_duplicate_and_close_unregister() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(4));

        let registered = registry
            .register(session_id)
            .expect("first registration should succeed");
        assert_eq!(registry.len(), 1);
        assert_eq!(registered.state.id(), session_id);
        assert!(registered.state.check_open().is_ok());

        let error = registry
            .register(session_id)
            .expect_err("duplicate session should be rejected");
        assert!(matches!(
            error,
            RegisterSessionError::AlreadyRegistered { session_id: duplicate } if duplicate == session_id
        ));

        registered.state.close();
        assert_eq!(registry.len(), 0);
        assert!(registered.state.check_open().is_err());

        registered.state.close();
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn dropping_registered_session_unregisters_it() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(8));

        let registered = registry
            .register(session_id)
            .expect("registration should succeed");
        assert_eq!(registry.len(), 1);

        drop(registered);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn route_unknown_sessions_return_original_streams() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(4));

        let bidi = bidi_stream(1);
        let mut returned_bidi = registry
            .route_bi(session_id, bidi)
            .expect_err("unknown bidi session should reject stream");
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(1)
        );

        let uni = uni_stream(2);
        let mut returned_uni = registry
            .route_uni(session_id, uni)
            .expect_err("unknown uni session should reject stream");
        assert_eq!(
            returned_uni
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(2)
        );
    }

    #[tokio::test]
    async fn route_known_sessions_deliver_streams_to_receivers() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(4));
        let mut registered = registry
            .register(session_id)
            .expect("registration should succeed");

        assert!(registry.route_bi(session_id, bidi_stream(3)).is_ok());
        assert!(registry.route_uni(session_id, uni_stream(4)).is_ok());

        let (mut bidi_reader, _bidi_writer) = registered
            .bidi_rx
            .recv()
            .await
            .expect("bidi receiver should get a stream");
        let mut uni_reader = registered
            .uni_rx
            .recv()
            .await
            .expect("uni receiver should get a stream");

        assert_eq!(
            bidi_reader
                .stream_id()
                .await
                .expect("bidi stream id should be readable"),
            VarInt::from_u32(3)
        );
        assert_eq!(
            uni_reader
                .stream_id()
                .await
                .expect("uni stream id should be readable"),
            VarInt::from_u32(4)
        );
    }

    #[test]
    fn route_rejects_closed_or_full_channels() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(4));
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");

        drop(registered.bidi_rx);
        drop(registered.uni_rx);
        assert!(registry.route_bi(session_id, bidi_stream(5)).is_err());
        assert!(registry.route_uni(session_id, uni_stream(6)).is_err());
    }

    #[tokio::test]
    async fn route_closed_channels_return_original_streams() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(16));
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");

        drop(registered.bidi_rx);
        drop(registered.uni_rx);

        let mut returned_bidi = registry
            .route_bi(session_id, bidi_stream(17))
            .expect_err("closed bidi receiver should reject stream");
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(17)
        );

        let mut returned_uni = registry
            .route_uni(session_id, uni_stream(18))
            .expect_err("closed uni receiver should reject stream");
        assert_eq!(
            returned_uni
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(18)
        );
    }

    #[test]
    fn route_rejects_when_session_channel_is_full() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(9));
        let _registered = registry
            .register(session_id)
            .expect("registration should succeed");

        for id in 0..SESSION_STREAM_CHANNEL_SIZE {
            assert!(
                registry
                    .route_bi(session_id, bidi_stream(id as u32))
                    .is_ok()
            );
            assert!(
                registry
                    .route_uni(session_id, uni_stream(id as u32))
                    .is_ok()
            );
        }

        assert!(registry.route_bi(session_id, bidi_stream(99)).is_err());
        assert!(registry.route_uni(session_id, uni_stream(100)).is_err());
    }

    #[tokio::test]
    async fn route_full_channels_return_original_streams() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(20));
        let _registered = registry
            .register(session_id)
            .expect("registration should succeed");

        for id in 0..SESSION_STREAM_CHANNEL_SIZE {
            assert!(
                registry
                    .route_bi(session_id, bidi_stream(id as u32))
                    .is_ok()
            );
            assert!(
                registry
                    .route_uni(session_id, uni_stream(id as u32))
                    .is_ok()
            );
        }

        let mut returned_bidi = registry
            .route_bi(session_id, bidi_stream(21))
            .expect_err("full bidi channel should reject stream");
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(21)
        );

        let mut returned_uni = registry
            .route_uni(session_id, uni_stream(22))
            .expect_err("full uni channel should reject stream");
        assert_eq!(
            returned_uni
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(22)
        );
    }

    #[tokio::test]
    async fn close_unregisters_session_and_allows_id_reuse() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(24));
        let registered = registry
            .register(session_id)
            .expect("initial registration should succeed");

        registered.state.close();
        assert_eq!(registry.len(), 0);

        let mut returned = registry
            .route_uni(session_id, uni_stream(25))
            .expect_err("closed session should no longer route streams");
        assert_eq!(
            returned
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(25)
        );

        let mut registered_again = registry
            .register(session_id)
            .expect("closed session id should be reusable");
        assert_eq!(registry.len(), 1);
        assert!(registry.route_uni(session_id, uni_stream(26)).is_ok());

        let mut routed = registered_again
            .uni_rx
            .recv()
            .await
            .expect("re-registered session should receive streams");
        assert_eq!(
            routed
                .stream_id()
                .await
                .expect("routed uni stream id should be readable"),
            VarInt::from_u32(26)
        );
    }

    #[test]
    fn cloned_session_state_keeps_registration_until_last_state_drop() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(28));
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");
        let state = Arc::clone(&registered.state);

        drop(registered);
        assert_eq!(registry.len(), 1);
        assert!(registry.route_uni(session_id, uni_stream(29)).is_err());
        assert!(state.check_open().is_ok());

        drop(state);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn poisoned_registry_surfaces_errors_and_preserves_streams() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(12));
        poison_registry(&registry);

        let error = registry
            .register(session_id)
            .expect_err("poisoned registry should reject new registrations");
        assert!(matches!(error, RegisterSessionError::RegistryPoisoned));
        assert_eq!(registry.len(), 0);

        registry.unregister(session_id);

        let mut returned_bidi = registry
            .route_bi(session_id, bidi_stream(13))
            .expect_err("poisoned registry should return routed bidi stream");
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(13)
        );

        let mut returned_uni = registry
            .route_uni(session_id, uni_stream(14))
            .expect_err("poisoned registry should return routed uni stream");
        assert_eq!(
            returned_uni
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(14)
        );
    }
}
