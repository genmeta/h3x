use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use tokio::sync::mpsc;
use tracing::Instrument;

use super::{
    WebTransportSessionId,
    error::{RegisterSessionError, SessionClosed},
    protocol::WT_SESSION_GONE,
    session::{
        RoutedBiStream, RoutedUniStream,
        stream::{TrackedStreamReader, TrackedStreamWriter},
    },
};
use crate::{
    quic::{ResetStreamExt, StopStreamExt},
    stream_id::StreamId,
};

const SESSION_STREAM_CHANNEL_SIZE: usize = 16;

#[derive(Debug, Default)]
struct RegistryInner {
    active: HashMap<WebTransportSessionId, SessionStreamRouter>,
    closed: HashSet<WebTransportSessionId>,
}

#[derive(Debug, Default, Clone)]
pub(super) struct Registry {
    inner: Arc<Mutex<RegistryInner>>,
}

pub(super) enum RouteBiError {
    Unknown(RoutedBiStream),
    Closed(RoutedBiStream),
    Rejected(RoutedBiStream),
}

pub(super) enum RouteUniError {
    Unknown(RoutedUniStream),
    Closed(RoutedUniStream),
    Rejected(RoutedUniStream),
}

impl Registry {
    pub(super) fn register(
        &self,
        session_id: WebTransportSessionId,
    ) -> Result<RegisteredSession, RegisterSessionError> {
        let (bidi_tx, bidi_rx) = mpsc::channel(SESSION_STREAM_CHANNEL_SIZE);
        let (uni_tx, uni_rx) = mpsc::channel(SESSION_STREAM_CHANNEL_SIZE);

        let Ok(mut inner) = self.inner.lock() else {
            return Err(RegisterSessionError::RegistryPoisoned);
        };

        if inner.active.contains_key(&session_id) {
            return Err(RegisterSessionError::AlreadyRegistered { session_id });
        }

        inner.closed.remove(&session_id);
        inner
            .active
            .insert(session_id, SessionStreamRouter::new(bidi_tx, uni_tx));

        Ok(RegisteredSession {
            state: Arc::new(SessionState::new(session_id, self.clone())),
            bidi_rx,
            uni_rx,
        })
    }

    pub(super) fn unregister(&self, session_id: WebTransportSessionId) {
        self.close(session_id);
    }

    fn close(&self, session_id: WebTransportSessionId) {
        let Ok(mut inner) = self.inner.lock() else {
            tracing::debug!(?session_id, "webtransport session registry lock poisoned");
            return;
        };
        inner.active.remove(&session_id);
        inner.closed.insert(session_id);
    }

    pub(super) fn route_bi(
        &self,
        session_id: WebTransportSessionId,
        stream: RoutedBiStream,
    ) -> Result<(), RouteBiError> {
        let Ok(inner) = self.inner.lock() else {
            tracing::debug!(session_id = %session_id, "webtransport session registry lock poisoned");
            return Err(RouteBiError::Rejected(stream));
        };
        let Some(router) = inner.active.get(&session_id) else {
            if inner.closed.contains(&session_id) {
                tracing::debug!(session_id = %session_id, "webtransport bidi stream belongs to closed session");
                return Err(RouteBiError::Closed(stream));
            }
            tracing::debug!(session_id = %session_id, "no registered session for webtransport bidi stream");
            return Err(RouteBiError::Unknown(stream));
        };
        router
            .route_bi(session_id, stream)
            .map_err(RouteBiError::Rejected)
    }

    pub(super) fn route_uni(
        &self,
        session_id: WebTransportSessionId,
        stream: RoutedUniStream,
    ) -> Result<(), RouteUniError> {
        let Ok(inner) = self.inner.lock() else {
            tracing::debug!(session_id = %session_id, "webtransport session registry lock poisoned");
            return Err(RouteUniError::Rejected(stream));
        };
        let Some(router) = inner.active.get(&session_id) else {
            if inner.closed.contains(&session_id) {
                tracing::debug!(session_id = %session_id, "webtransport uni stream belongs to closed session");
                return Err(RouteUniError::Closed(stream));
            }
            tracing::debug!(session_id = %session_id, "no registered session for webtransport uni stream");
            return Err(RouteUniError::Unknown(stream));
        };
        router
            .route_uni(session_id, stream)
            .map_err(RouteUniError::Rejected)
    }

    pub(super) fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.active.len())
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
    session_id: WebTransportSessionId,
    registry: Registry,
    closed: AtomicBool,
    tracked_readers: Mutex<HashMap<StreamId, TrackedStreamReader>>,
    tracked_writers: Mutex<HashMap<StreamId, TrackedStreamWriter>>,
}

impl SessionState {
    fn new(session_id: WebTransportSessionId, registry: Registry) -> Self {
        Self {
            session_id,
            registry,
            closed: AtomicBool::new(false),
            tracked_readers: Mutex::new(HashMap::new()),
            tracked_writers: Mutex::new(HashMap::new()),
        }
    }

    pub(super) fn id(&self) -> WebTransportSessionId {
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
            let (readers, writers) = self.take_tracked_streams();
            spawn_tracked_stream_cleanup(self.session_id, readers, writers);
        }
    }

    pub(super) fn insert_tracked_bi(
        &self,
        stream_id: StreamId,
        reader: TrackedStreamReader,
        writer: TrackedStreamWriter,
    ) -> Result<(), SessionClosed> {
        self.check_open()?;

        let Ok(mut readers) = self.tracked_readers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session reader tracking lock poisoned"
            );
            return Err(SessionClosed);
        };
        let Ok(mut writers) = self.tracked_writers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session writer tracking lock poisoned"
            );
            return Err(SessionClosed);
        };

        if self.closed.load(Ordering::Acquire) {
            return Err(SessionClosed);
        }

        readers.insert(stream_id, reader);
        writers.insert(stream_id, writer);

        if self.closed.load(Ordering::Acquire) {
            readers.remove(&stream_id);
            writers.remove(&stream_id);
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    pub(super) fn insert_tracked_reader(
        &self,
        stream_id: StreamId,
        reader: TrackedStreamReader,
    ) -> Result<(), SessionClosed> {
        self.check_open()?;

        let Ok(mut readers) = self.tracked_readers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session reader tracking lock poisoned"
            );
            return Err(SessionClosed);
        };

        if self.closed.load(Ordering::Acquire) {
            return Err(SessionClosed);
        }

        readers.insert(stream_id, reader);

        if self.closed.load(Ordering::Acquire) {
            readers.remove(&stream_id);
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    pub(super) fn insert_tracked_writer(
        &self,
        stream_id: StreamId,
        writer: TrackedStreamWriter,
    ) -> Result<(), SessionClosed> {
        self.check_open()?;

        let Ok(mut writers) = self.tracked_writers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session writer tracking lock poisoned"
            );
            return Err(SessionClosed);
        };

        if self.closed.load(Ordering::Acquire) {
            return Err(SessionClosed);
        }

        writers.insert(stream_id, writer);

        if self.closed.load(Ordering::Acquire) {
            writers.remove(&stream_id);
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    pub(super) fn remove_tracked_reader(&self, stream_id: StreamId) {
        let Ok(mut readers) = self.tracked_readers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session reader tracking lock poisoned"
            );
            return;
        };
        readers.remove(&stream_id);
    }

    pub(super) fn remove_tracked_writer(&self, stream_id: StreamId) {
        let Ok(mut writers) = self.tracked_writers.lock() else {
            tracing::debug!(
                session_id = %self.session_id,
                "webtransport session writer tracking lock poisoned"
            );
            return;
        };
        writers.remove(&stream_id);
    }

    fn take_tracked_streams(&self) -> (Vec<TrackedStreamReader>, Vec<TrackedStreamWriter>) {
        let readers = match self.tracked_readers.lock() {
            Ok(mut readers) => readers.drain().map(|(_stream_id, reader)| reader).collect(),
            Err(_) => {
                tracing::debug!(
                    session_id = %self.session_id,
                    "webtransport session reader tracking lock poisoned"
                );
                Vec::new()
            }
        };
        let writers = match self.tracked_writers.lock() {
            Ok(mut writers) => writers.drain().map(|(_stream_id, writer)| writer).collect(),
            Err(_) => {
                tracing::debug!(
                    session_id = %self.session_id,
                    "webtransport session writer tracking lock poisoned"
                );
                Vec::new()
            }
        };
        (readers, writers)
    }
}

fn spawn_tracked_stream_cleanup(
    session_id: WebTransportSessionId,
    readers: Vec<TrackedStreamReader>,
    writers: Vec<TrackedStreamWriter>,
) {
    if readers.is_empty() && writers.is_empty() {
        return;
    }

    let cleanup = cleanup_tracked_streams(session_id, readers, writers);
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // Inherent termination: the task owns the taken tracked halves and
            // exits after every STOP/RESET future resolves or returns an error.
            let _cleanup_task = handle.spawn(cleanup.in_current_span());
        }
        Err(error) => {
            let report = snafu::Report::from_error(&error);
            tracing::debug!(
                session_id = %session_id,
                error = %report,
                "failed to spawn webtransport session stream cleanup"
            );
        }
    }
}

async fn cleanup_tracked_streams(
    session_id: WebTransportSessionId,
    readers: Vec<TrackedStreamReader>,
    writers: Vec<TrackedStreamWriter>,
) {
    let mut cleanup = FuturesUnordered::<BoxFuture<'static, ()>>::new();

    for mut reader in readers {
        cleanup.push(Box::pin(async move {
            if let Err(error) = reader.stop(WT_SESSION_GONE).await {
                let report = snafu::Report::from_error(&error);
                tracing::debug!(
                    session_id = %session_id,
                    error = %report,
                    "failed to stop webtransport session stream reader"
                );
            }
        }));
    }

    for mut writer in writers {
        cleanup.push(Box::pin(async move {
            if let Err(error) = writer.reset(WT_SESSION_GONE).await {
                let report = snafu::Report::from_error(&error);
                tracing::debug!(
                    session_id = %session_id,
                    error = %report,
                    "failed to reset webtransport session stream writer"
                );
            }
        }));
    }

    while cleanup.next().await.is_some() {}
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

    fn route_bi(
        &self,
        session_id: WebTransportSessionId,
        stream: RoutedBiStream,
    ) -> Result<(), RoutedBiStream> {
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
        session_id: WebTransportSessionId,
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
    use futures::{Sink, SinkExt, Stream, StreamExt};

    use super::*;
    use crate::{
        quic::{
            self, BoxQuicStreamReader, BoxQuicStreamWriter, GetStreamIdExt, ResetStreamExt,
            StopStreamExt,
        },
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

    impl quic::ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    fn test_read_stream(id: u32, bytes: Vec<u8>) -> BoxQuicStreamReader {
        Box::pin(TestReadStream {
            chunks: VecDeque::from([Bytes::from(bytes)]),
            stream_id: VarInt::from_u32(id),
        }) as BoxQuicStreamReader
    }

    fn test_write_stream(id: u32, state: Arc<StreamState>) -> BoxQuicStreamWriter {
        Box::pin(TestWriteStream {
            state,
            stream_id: VarInt::from_u32(id),
        }) as BoxQuicStreamWriter
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

    fn wt_session_id(id: u32) -> WebTransportSessionId {
        WebTransportSessionId::try_from(StreamId::from(VarInt::from_u32(id)))
            .expect("test id must be a valid webtransport session id")
    }

    fn poison_registry(registry: &Registry) {
        let registry = registry.clone();
        let _ = catch_unwind(AssertUnwindSafe(move || {
            let _guard = registry.inner.lock().expect("registry lock should succeed");
            panic!("poison registry mutex");
        }));
    }

    fn route_bi_error_stream(error: RouteBiError) -> RoutedBiStream {
        match error {
            RouteBiError::Unknown(stream)
            | RouteBiError::Closed(stream)
            | RouteBiError::Rejected(stream) => stream,
        }
    }

    fn route_uni_error_stream(error: RouteUniError) -> RoutedUniStream {
        match error {
            RouteUniError::Unknown(stream)
            | RouteUniError::Closed(stream)
            | RouteUniError::Rejected(stream) => stream,
        }
    }

    #[tokio::test]
    async fn test_read_stream_reads_chunks_and_stops() {
        let mut stream = test_read_stream(40, b"chunk".to_vec());

        assert_eq!(
            stream
                .next()
                .await
                .expect("read stream should yield one chunk")
                .expect("read chunk should succeed"),
            Bytes::from_static(b"chunk")
        );
        assert!(
            stream.next().await.is_none(),
            "read stream should be exhausted"
        );
        stream
            .stop(VarInt::from_u32(41))
            .await
            .expect("read stream stop should succeed");
    }

    #[tokio::test]
    async fn test_write_stream_writes_flushes_closes_and_resets() {
        let state = Arc::new(StreamState::default());
        let mut stream = test_write_stream(42, Arc::clone(&state));

        assert_eq!(
            stream
                .stream_id()
                .await
                .expect("write stream id should be readable"),
            VarInt::from_u32(42)
        );
        stream
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("write stream send should succeed");
        stream
            .close()
            .await
            .expect("write stream close should succeed");
        stream
            .reset(VarInt::from_u32(43))
            .await
            .expect("write stream reset should succeed");

        assert_eq!(
            *state
                .written
                .lock()
                .expect("written lock should not poison"),
            b"payload".to_vec()
        );
    }

    #[test]
    fn register_len_duplicate_and_close_unregister() {
        let registry = Registry::default();
        let session_id = wt_session_id(4);

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
        let session_id = wt_session_id(8);

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
        let session_id = wt_session_id(4);

        let bidi = bidi_stream(1);
        let error = registry
            .route_bi(session_id, bidi)
            .expect_err("unknown bidi session should reject stream");
        assert!(matches!(&error, RouteBiError::Unknown(_)));
        let mut returned_bidi = route_bi_error_stream(error);
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(1)
        );

        let uni = uni_stream(2);
        let error = registry
            .route_uni(session_id, uni)
            .expect_err("unknown uni session should reject stream");
        assert!(matches!(&error, RouteUniError::Unknown(_)));
        let mut returned_uni = route_uni_error_stream(error);
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
        let session_id = wt_session_id(4);
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
        let session_id = wt_session_id(4);
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");

        drop(registered.bidi_rx);
        drop(registered.uni_rx);
        assert!(matches!(
            registry.route_bi(session_id, bidi_stream(5)),
            Err(RouteBiError::Rejected(_))
        ));
        assert!(matches!(
            registry.route_uni(session_id, uni_stream(6)),
            Err(RouteUniError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn route_closed_channels_return_original_streams() {
        let registry = Registry::default();
        let session_id = wt_session_id(16);
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");

        drop(registered.bidi_rx);
        drop(registered.uni_rx);

        let error = registry
            .route_bi(session_id, bidi_stream(17))
            .expect_err("closed bidi receiver should reject stream");
        assert!(matches!(&error, RouteBiError::Rejected(_)));
        let mut returned_bidi = route_bi_error_stream(error);
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(17)
        );

        let error = registry
            .route_uni(session_id, uni_stream(18))
            .expect_err("closed uni receiver should reject stream");
        assert!(matches!(&error, RouteUniError::Rejected(_)));
        let mut returned_uni = route_uni_error_stream(error);
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
        let session_id = wt_session_id(8);
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

        assert!(matches!(
            registry.route_bi(session_id, bidi_stream(99)),
            Err(RouteBiError::Rejected(_))
        ));
        assert!(matches!(
            registry.route_uni(session_id, uni_stream(100)),
            Err(RouteUniError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn route_uses_exact_registered_session_id() {
        let registry = Registry::default();
        let first_session_id = wt_session_id(32);
        let second_session_id = wt_session_id(36);
        let mut first = registry
            .register(first_session_id)
            .expect("first registration should succeed");
        let mut second = registry
            .register(second_session_id)
            .expect("second registration should succeed");

        assert!(
            registry
                .route_bi(second_session_id, bidi_stream(37))
                .is_ok()
        );
        assert!(
            registry
                .route_uni(second_session_id, uni_stream(38))
                .is_ok()
        );

        assert!(matches!(
            first.bidi_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert!(matches!(
            first.uni_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));

        let (mut second_bidi_reader, _second_bidi_writer) = second
            .bidi_rx
            .recv()
            .await
            .expect("second session should receive routed bidi stream");
        assert_eq!(
            second_bidi_reader
                .stream_id()
                .await
                .expect("second bidi stream id should be readable"),
            VarInt::from_u32(37)
        );

        let mut second_uni_reader = second
            .uni_rx
            .recv()
            .await
            .expect("second session should receive routed uni stream");
        assert_eq!(
            second_uni_reader
                .stream_id()
                .await
                .expect("second uni stream id should be readable"),
            VarInt::from_u32(38)
        );
    }

    #[tokio::test]
    async fn route_full_channels_return_original_streams() {
        let registry = Registry::default();
        let session_id = wt_session_id(20);
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

        let error = registry
            .route_bi(session_id, bidi_stream(21))
            .expect_err("full bidi channel should reject stream");
        assert!(matches!(&error, RouteBiError::Rejected(_)));
        let mut returned_bidi = route_bi_error_stream(error);
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(21)
        );

        let error = registry
            .route_uni(session_id, uni_stream(22))
            .expect_err("full uni channel should reject stream");
        assert!(matches!(&error, RouteUniError::Rejected(_)));
        let mut returned_uni = route_uni_error_stream(error);
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
        let session_id = wt_session_id(24);
        let registered = registry
            .register(session_id)
            .expect("initial registration should succeed");

        registered.state.close();
        assert_eq!(registry.len(), 0);

        let error = registry
            .route_uni(session_id, uni_stream(25))
            .expect_err("closed session should no longer route streams");
        assert!(matches!(&error, RouteUniError::Closed(_)));
        let mut returned = route_uni_error_stream(error);
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
        let session_id = wt_session_id(28);
        let registered = registry
            .register(session_id)
            .expect("registration should succeed");
        let state = Arc::clone(&registered.state);

        drop(registered);
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            registry.route_uni(session_id, uni_stream(29)),
            Err(RouteUniError::Rejected(_))
        ));
        assert!(state.check_open().is_ok());

        drop(state);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn poisoned_registry_surfaces_errors_and_preserves_streams() {
        let registry = Registry::default();
        let session_id = wt_session_id(12);
        poison_registry(&registry);

        let error = registry
            .register(session_id)
            .expect_err("poisoned registry should reject new registrations");
        assert!(matches!(error, RegisterSessionError::RegistryPoisoned));
        assert_eq!(registry.len(), 0);

        registry.unregister(session_id);

        let error = registry
            .route_bi(session_id, bidi_stream(13))
            .expect_err("poisoned registry should return routed bidi stream");
        assert!(matches!(&error, RouteBiError::Rejected(_)));
        let mut returned_bidi = route_bi_error_stream(error);
        assert_eq!(
            returned_bidi
                .0
                .stream_id()
                .await
                .expect("returned bidi stream id should be readable"),
            VarInt::from_u32(13)
        );

        let error = registry
            .route_uni(session_id, uni_stream(14))
            .expect_err("poisoned registry should return routed uni stream");
        assert!(matches!(&error, RouteUniError::Rejected(_)));
        let mut returned_uni = route_uni_error_stream(error);
        assert_eq!(
            returned_uni
                .stream_id()
                .await
                .expect("returned uni stream id should be readable"),
            VarInt::from_u32(14)
        );
    }
}
