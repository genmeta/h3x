use std::{
    fmt,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use futures::{Sink, Stream, task::AtomicWaker};

use crate::{
    quic::{self, BoxQuicStreamReader, BoxQuicStreamWriter, GetStreamId, ResetStream, StopStream},
    stream_id::StreamId,
    varint::VarInt,
    webtransport::registry::SessionState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TrackingState {
    Tracked,
    Untracked,
}

struct InFlightWakers {
    handle: AtomicWaker,
    tracked: AtomicWaker,
}

impl InFlightWakers {
    fn new() -> Self {
        Self {
            handle: AtomicWaker::new(),
            tracked: AtomicWaker::new(),
        }
    }

    fn wake_all(&self) {
        self.handle.wake();
        self.tracked.wake();
    }
}

struct InFlightControl {
    code: VarInt,
    wakers: Arc<InFlightWakers>,
}

struct ReaderCore<S> {
    stream_id: StreamId,
    stream: S,
    session: Weak<SessionState>,
    tracking: TrackingState,
    stop: Option<InFlightControl>,
    stop_result: Option<Result<(), quic::StreamError>>,
}

struct WriterCore<S> {
    stream_id: StreamId,
    stream: S,
    session: Weak<SessionState>,
    tracking: TrackingState,
    reset: Option<InFlightControl>,
    reset_result: Option<Result<(), quic::StreamError>>,
}

pub struct WebTransportStreamReader<S = BoxQuicStreamReader> {
    core: Arc<Mutex<ReaderCore<S>>>,
}

pub(in crate::webtransport) struct TrackedStreamReader<S = BoxQuicStreamReader> {
    core: Arc<Mutex<ReaderCore<S>>>,
}

pub struct WebTransportStreamWriter<S = BoxQuicStreamWriter> {
    core: Arc<Mutex<WriterCore<S>>>,
}

pub(in crate::webtransport) struct TrackedStreamWriter<S = BoxQuicStreamWriter> {
    core: Arc<Mutex<WriterCore<S>>>,
}

impl<S> WebTransportStreamReader<S> {
    pub(super) fn tracked(
        stream_id: StreamId,
        stream: S,
        session: Weak<SessionState>,
    ) -> (Self, TrackedStreamReader<S>) {
        let core = Arc::new(Mutex::new(ReaderCore {
            stream_id,
            stream,
            session,
            tracking: TrackingState::Tracked,
            stop: None,
            stop_result: None,
        }));
        (
            Self {
                core: Arc::clone(&core),
            },
            TrackedStreamReader { core },
        )
    }
}

impl<S> WebTransportStreamWriter<S> {
    pub(super) fn tracked(
        stream_id: StreamId,
        stream: S,
        session: Weak<SessionState>,
    ) -> (Self, TrackedStreamWriter<S>) {
        let core = Arc::new(Mutex::new(WriterCore {
            stream_id,
            stream,
            session,
            tracking: TrackingState::Tracked,
            reset: None,
            reset_result: None,
        }));
        (
            Self {
                core: Arc::clone(&core),
            },
            TrackedStreamWriter { core },
        )
    }
}

impl<S> fmt::Debug for WebTransportStreamReader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.core.lock() {
            Ok(core) => f
                .debug_struct("WebTransportStreamReader")
                .field("stream_id", &core.stream_id)
                .field("tracking", &core.tracking)
                .finish(),
            Err(_) => f
                .debug_struct("WebTransportStreamReader")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

impl<S> fmt::Debug for TrackedStreamReader<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.core.lock() {
            Ok(core) => f
                .debug_struct("TrackedStreamReader")
                .field("stream_id", &core.stream_id)
                .field("tracking", &core.tracking)
                .finish(),
            Err(_) => f
                .debug_struct("TrackedStreamReader")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

impl<S> fmt::Debug for WebTransportStreamWriter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.core.lock() {
            Ok(core) => f
                .debug_struct("WebTransportStreamWriter")
                .field("stream_id", &core.stream_id)
                .field("tracking", &core.tracking)
                .finish(),
            Err(_) => f
                .debug_struct("WebTransportStreamWriter")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

impl<S> fmt::Debug for TrackedStreamWriter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.core.lock() {
            Ok(core) => f
                .debug_struct("TrackedStreamWriter")
                .field("stream_id", &core.stream_id)
                .field("tracking", &core.tracking)
                .finish(),
            Err(_) => f
                .debug_struct("TrackedStreamWriter")
                .field("poisoned", &true)
                .finish(),
        }
    }
}

fn mark_reader_untracked<S>(
    core: &Arc<Mutex<ReaderCore<S>>>,
) -> Option<(Weak<SessionState>, StreamId)> {
    let mut core = core.lock().expect("webtransport reader core lock poisoned");
    if core.tracking == TrackingState::Tracked {
        core.tracking = TrackingState::Untracked;
        Some((core.session.clone(), core.stream_id))
    } else {
        None
    }
}

fn remove_reader_tracking<S>(core: &Arc<Mutex<ReaderCore<S>>>) {
    let Some((session, stream_id)) = mark_reader_untracked(core) else {
        return;
    };
    if let Some(session) = session.upgrade() {
        session.remove_tracked_reader(stream_id);
    }
}

fn remove_reader_tracking_if_untracked<S>(core: &Arc<Mutex<ReaderCore<S>>>) {
    let (session, stream_id, untracked) = {
        let core = core.lock().expect("webtransport reader core lock poisoned");
        (
            core.session.clone(),
            core.stream_id,
            core.tracking == TrackingState::Untracked,
        )
    };
    if untracked && let Some(session) = session.upgrade() {
        session.remove_tracked_reader(stream_id);
    }
}

fn mark_writer_untracked<S>(
    core: &Arc<Mutex<WriterCore<S>>>,
) -> Option<(Weak<SessionState>, StreamId)> {
    let mut core = core.lock().expect("webtransport writer core lock poisoned");
    if core.tracking == TrackingState::Tracked {
        core.tracking = TrackingState::Untracked;
        Some((core.session.clone(), core.stream_id))
    } else {
        None
    }
}

fn remove_writer_tracking<S>(core: &Arc<Mutex<WriterCore<S>>>) {
    let Some((session, stream_id)) = mark_writer_untracked(core) else {
        return;
    };
    if let Some(session) = session.upgrade() {
        session.remove_tracked_writer(stream_id);
    }
}

fn remove_writer_tracking_if_untracked<S>(core: &Arc<Mutex<WriterCore<S>>>) {
    let (session, stream_id, untracked) = {
        let core = core.lock().expect("webtransport writer core lock poisoned");
        (
            core.session.clone(),
            core.stream_id,
            core.tracking == TrackingState::Untracked,
        )
    };
    if untracked && let Some(session) = session.upgrade() {
        session.remove_tracked_writer(stream_id);
    }
}

impl<S> Drop for WebTransportStreamReader<S> {
    fn drop(&mut self) {
        remove_reader_tracking_if_untracked(&self.core);
    }
}

impl<S> Drop for WebTransportStreamWriter<S> {
    fn drop(&mut self) {
        remove_writer_tracking_if_untracked(&self.core);
    }
}

struct AggregateWake {
    wakers: Arc<InFlightWakers>,
}

impl std::task::Wake for AggregateWake {
    fn wake(self: Arc<Self>) {
        self.wakers.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakers.wake_all();
    }
}

fn with_aggregate_context<T>(
    wakers: Arc<InFlightWakers>,
    f: impl FnOnce(&mut Context<'_>) -> T,
) -> T {
    let waker = Waker::from(Arc::new(AggregateWake { wakers }));
    let mut cx = Context::from_waker(&waker);
    f(&mut cx)
}

impl<S> GetStreamId for WebTransportStreamReader<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let core = self
            .core
            .lock()
            .expect("webtransport reader core lock poisoned");
        Poll::Ready(Ok(core.stream_id.into()))
    }
}

impl<S> GetStreamId for TrackedStreamReader<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let core = self
            .core
            .lock()
            .expect("webtransport reader core lock poisoned");
        Poll::Ready(Ok(core.stream_id.into()))
    }
}

impl<S> GetStreamId for WebTransportStreamWriter<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let core = self
            .core
            .lock()
            .expect("webtransport writer core lock poisoned");
        Poll::Ready(Ok(core.stream_id.into()))
    }
}

impl<S> GetStreamId for TrackedStreamWriter<S> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let core = self
            .core
            .lock()
            .expect("webtransport writer core lock poisoned");
        Poll::Ready(Ok(core.stream_id.into()))
    }
}

impl<S> Stream for WebTransportStreamReader<S>
where
    S: Stream<Item = Result<Bytes, quic::StreamError>> + Unpin,
{
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let poll = {
            let mut core = self
                .core
                .lock()
                .expect("webtransport reader core lock poisoned");
            Pin::new(&mut core.stream).poll_next(cx)
        };

        match &poll {
            Poll::Ready(None | Some(Err(_))) => remove_reader_tracking(&self.core),
            Poll::Ready(Some(Ok(_))) | Poll::Pending => {}
        }

        poll
    }
}

impl<S> Sink<Bytes> for WebTransportStreamWriter<S>
where
    S: Sink<Bytes, Error = quic::StreamError> + Unpin,
{
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let poll = {
            let mut core = self
                .core
                .lock()
                .expect("webtransport writer core lock poisoned");
            Pin::new(&mut core.stream).poll_ready(cx)
        };
        if matches!(poll, Poll::Ready(Err(_))) {
            remove_writer_tracking(&self.core);
        }
        poll
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let result = {
            let mut core = self
                .core
                .lock()
                .expect("webtransport writer core lock poisoned");
            Pin::new(&mut core.stream).start_send(item)
        };
        if result.is_err() {
            remove_writer_tracking(&self.core);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let poll = {
            let mut core = self
                .core
                .lock()
                .expect("webtransport writer core lock poisoned");
            Pin::new(&mut core.stream).poll_flush(cx)
        };
        if matches!(poll, Poll::Ready(Err(_))) {
            remove_writer_tracking(&self.core);
        }
        poll
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let poll = {
            let mut core = self
                .core
                .lock()
                .expect("webtransport writer core lock poisoned");
            Pin::new(&mut core.stream).poll_close(cx)
        };
        match poll {
            Poll::Ready(Ok(()) | Err(_)) => remove_writer_tracking(&self.core),
            Poll::Pending => {}
        }
        poll
    }
}

fn poll_reader_stop<S>(
    core: &Arc<Mutex<ReaderCore<S>>>,
    cx: &mut Context<'_>,
    code: VarInt,
    tracked_side: bool,
) -> Poll<Result<(), quic::StreamError>>
where
    S: StopStream + Unpin,
{
    let (committed_code, wakers) = {
        let mut core = core.lock().expect("webtransport reader core lock poisoned");
        if let Some(result) = core.stop_result.clone() {
            return Poll::Ready(result);
        }
        let control = core.stop.get_or_insert_with(|| InFlightControl {
            code,
            wakers: Arc::new(InFlightWakers::new()),
        });
        if tracked_side {
            control.wakers.tracked.register(cx.waker());
        } else {
            control.wakers.handle.register(cx.waker());
        }
        (control.code, Arc::clone(&control.wakers))
    };

    let poll_wakers = Arc::clone(&wakers);
    let poll = with_aggregate_context(poll_wakers, |cx| {
        let mut core = core.lock().expect("webtransport reader core lock poisoned");
        Pin::new(&mut core.stream).poll_stop(cx, committed_code)
    });

    match poll {
        Poll::Ready(result) => {
            {
                let mut core = core.lock().expect("webtransport reader core lock poisoned");
                core.stop = None;
                core.stop_result = Some(result.clone());
            }
            remove_reader_tracking(core);
            wakers.wake_all();
            Poll::Ready(result)
        }
        Poll::Pending => Poll::Pending,
    }
}

impl<S> StopStream for WebTransportStreamReader<S>
where
    S: StopStream + Unpin,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        poll_reader_stop(&self.core, cx, code, false)
    }
}

impl<S> StopStream for TrackedStreamReader<S>
where
    S: StopStream + Unpin,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        poll_reader_stop(&self.core, cx, code, true)
    }
}

fn poll_writer_reset<S>(
    core: &Arc<Mutex<WriterCore<S>>>,
    cx: &mut Context<'_>,
    code: VarInt,
    tracked_side: bool,
) -> Poll<Result<(), quic::StreamError>>
where
    S: ResetStream + Unpin,
{
    let (committed_code, wakers) = {
        let mut core = core.lock().expect("webtransport writer core lock poisoned");
        if let Some(result) = core.reset_result.clone() {
            return Poll::Ready(result);
        }
        let control = core.reset.get_or_insert_with(|| InFlightControl {
            code,
            wakers: Arc::new(InFlightWakers::new()),
        });
        if tracked_side {
            control.wakers.tracked.register(cx.waker());
        } else {
            control.wakers.handle.register(cx.waker());
        }
        (control.code, Arc::clone(&control.wakers))
    };

    let poll_wakers = Arc::clone(&wakers);
    let poll = with_aggregate_context(poll_wakers, |cx| {
        let mut core = core.lock().expect("webtransport writer core lock poisoned");
        Pin::new(&mut core.stream).poll_reset(cx, committed_code)
    });

    match poll {
        Poll::Ready(result) => {
            {
                let mut core = core.lock().expect("webtransport writer core lock poisoned");
                core.reset = None;
                core.reset_result = Some(result.clone());
            }
            remove_writer_tracking(core);
            wakers.wake_all();
            Poll::Ready(result)
        }
        Poll::Pending => Poll::Pending,
    }
}

impl<S> ResetStream for WebTransportStreamWriter<S>
where
    S: ResetStream + Unpin,
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        poll_writer_reset(&self.core, cx, code, false)
    }
}

impl<S> ResetStream for TrackedStreamWriter<S>
where
    S: ResetStream + Unpin,
{
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        poll_writer_reset(&self.core, cx, code, true)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream, StreamExt, task::noop_waker_ref};

    use super::*;
    use crate::{
        quic::{self, ResetStream, StopStream},
        stream_id::StreamId,
        varint::VarInt,
    };

    #[derive(Debug)]
    struct TestReadStream {
        chunks: VecDeque<Result<Bytes, quic::StreamError>>,
        stream_id: VarInt,
        stopped: Arc<Mutex<Vec<VarInt>>>,
    }

    impl TestReadStream {
        fn with_chunks<const N: usize>(stream_id: u32, chunks: [Bytes; N]) -> Self {
            Self {
                chunks: chunks.into_iter().map(Ok).collect(),
                stream_id: VarInt::from_u32(stream_id),
                stopped: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn stopped_codes(&self) -> Vec<VarInt> {
            self.stopped.lock().expect("stopped lock poisoned").clone()
        }
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front())
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

    impl StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.stopped
                .lock()
                .expect("stopped lock poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct TestWriteState {
        written: Mutex<Vec<u8>>,
        flushes: Mutex<usize>,
        closes: Mutex<usize>,
        resets: Mutex<Vec<VarInt>>,
    }

    impl TestWriteState {
        fn written(&self) -> Vec<u8> {
            self.written.lock().expect("written lock poisoned").clone()
        }

        fn flushes(&self) -> usize {
            *self.flushes.lock().expect("flushes lock poisoned")
        }

        fn closes(&self) -> usize {
            *self.closes.lock().expect("closes lock poisoned")
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<TestWriteState>,
        stream_id: VarInt,
    }

    impl TestWriteStream {
        fn new(stream_id: u32, state: Arc<TestWriteState>) -> Self {
            Self {
                state,
                stream_id: VarInt::from_u32(stream_id),
            }
        }
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
            let mut flushes = self.state.flushes.lock().expect("flushes lock poisoned");
            *flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let mut closes = self.state.closes.lock().expect("closes lock poisoned");
            *closes += 1;
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

    impl ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .resets
                .lock()
                .expect("resets lock poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct PendingStopReadStream {
        stream_id: VarInt,
        stop_codes: Vec<VarInt>,
        ready: Arc<AtomicBool>,
        waker: Option<Waker>,
    }

    impl PendingStopReadStream {
        fn new(stream_id: u32) -> Self {
            Self {
                stream_id: VarInt::from_u32(stream_id),
                stop_codes: Vec::new(),
                ready: Arc::new(AtomicBool::new(false)),
                waker: None,
            }
        }

        fn with_ready(stream_id: u32, ready: Arc<AtomicBool>) -> Self {
            Self {
                stream_id: VarInt::from_u32(stream_id),
                stop_codes: Vec::new(),
                ready,
                waker: None,
            }
        }

        fn stop_codes(&self) -> Vec<VarInt> {
            self.stop_codes.clone()
        }
    }

    impl Stream for PendingStopReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl quic::GetStreamId for PendingStopReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for PendingStopReadStream {
        fn poll_stop(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.stop_codes.push(code);
            self.waker = Some(cx.waker().clone());
            if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[derive(Debug)]
    struct PendingResetWriteStream {
        stream_id: VarInt,
        reset_codes: Vec<VarInt>,
        ready: Arc<AtomicBool>,
        waker: Option<Waker>,
    }

    impl PendingResetWriteStream {
        fn new(stream_id: u32) -> Self {
            Self {
                stream_id: VarInt::from_u32(stream_id),
                reset_codes: Vec::new(),
                ready: Arc::new(AtomicBool::new(false)),
                waker: None,
            }
        }

        fn with_ready(stream_id: u32, ready: Arc<AtomicBool>) -> Self {
            Self {
                stream_id: VarInt::from_u32(stream_id),
                reset_codes: Vec::new(),
                ready,
                waker: None,
            }
        }

        fn reset_codes(&self) -> Vec<VarInt> {
            self.reset_codes.clone()
        }
    }

    impl Sink<Bytes> for PendingResetWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }
    }

    impl quic::GetStreamId for PendingResetWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl ResetStream for PendingResetWriteStream {
        fn poll_reset(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.reset_codes.push(code);
            self.waker = Some(cx.waker().clone());
            if self.ready.load(Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    #[derive(Debug)]
    struct CountWake {
        wakes: Arc<AtomicUsize>,
    }

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn count_waker() -> (Waker, Arc<AtomicUsize>) {
        let wakes = Arc::new(AtomicUsize::new(0));
        (
            Waker::from(Arc::new(CountWake {
                wakes: Arc::clone(&wakes),
            })),
            wakes,
        )
    }

    fn poll_once<T>(f: impl FnOnce(&mut Context<'_>) -> Poll<T>) -> Poll<T> {
        let mut cx = Context::from_waker(noop_waker_ref());
        f(&mut cx)
    }

    #[tokio::test]
    async fn ordinary_reader_io_delegates_to_inner_stream() {
        let session = std::sync::Weak::new();
        let inner = TestReadStream::with_chunks(7, [Bytes::from_static(b"chunk")]);
        let (mut reader, _tracked) =
            WebTransportStreamReader::tracked(StreamId::from(VarInt::from_u32(7)), inner, session);

        assert_eq!(
            reader.next().await.expect("chunk").expect("ok"),
            Bytes::from_static(b"chunk")
        );
        assert!(reader.next().await.is_none());
    }

    #[tokio::test]
    async fn ordinary_writer_io_delegates_to_inner_sink() {
        let session = std::sync::Weak::new();
        let state = Arc::new(TestWriteState::default());
        let inner = TestWriteStream::new(8, Arc::clone(&state));
        let (mut writer, _tracked) =
            WebTransportStreamWriter::tracked(StreamId::from(VarInt::from_u32(8)), inner, session);

        writer
            .feed(Bytes::from_static(b"payload"))
            .await
            .expect("feed");
        writer.flush().await.expect("flush");
        writer.close().await.expect("close");

        assert_eq!(state.written(), b"payload".to_vec());
        assert_eq!(state.flushes(), 1);
        assert_eq!(state.closes(), 1);
    }

    #[tokio::test]
    async fn reader_stop_does_not_imply_eos() {
        let session = std::sync::Weak::new();
        let inner = TestReadStream::with_chunks(9, [Bytes::from_static(b"after-stop")]);
        let (mut reader, _tracked) =
            WebTransportStreamReader::tracked(StreamId::from(VarInt::from_u32(9)), inner, session);

        let mut cx = Context::from_waker(noop_waker_ref());
        assert!(
            Pin::new(&mut reader)
                .poll_stop(&mut cx, VarInt::from_u32(0x31))
                .is_ready()
        );

        {
            let core = reader.core.lock().expect("reader core lock poisoned");
            assert_eq!(core.stream.stopped_codes(), vec![VarInt::from_u32(0x31)]);
        }
        assert_eq!(
            reader.next().await.expect("chunk").expect("ok"),
            Bytes::from_static(b"after-stop")
        );
        assert!(reader.next().await.is_none());
    }

    #[test]
    fn concurrent_reader_stop_uses_first_committed_code() {
        let session = std::sync::Weak::new();
        let inner = PendingStopReadStream::new(10);
        let (mut reader, mut tracked) =
            WebTransportStreamReader::tracked(StreamId::from(VarInt::from_u32(10)), inner, session);

        let first = VarInt::from_u32(0x31);
        let second = VarInt::from_u32(0x32);

        assert!(poll_once(|cx| Pin::new(&mut reader).poll_stop(cx, first)).is_pending());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_stop(cx, second)).is_pending());

        let core = reader.core.lock().expect("reader core lock poisoned");
        assert_eq!(core.stream.stop_codes(), vec![first, first]);
    }

    #[test]
    fn completed_reader_stop_is_shared_by_both_control_sides() {
        let session = std::sync::Weak::new();
        let ready = Arc::new(AtomicBool::new(false));
        let inner = PendingStopReadStream::with_ready(14, Arc::clone(&ready));
        let (mut reader, mut tracked) =
            WebTransportStreamReader::tracked(StreamId::from(VarInt::from_u32(14)), inner, session);

        let first = VarInt::from_u32(0x71);
        let second = VarInt::from_u32(0x72);

        assert!(poll_once(|cx| Pin::new(&mut reader).poll_stop(cx, first)).is_pending());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_stop(cx, second)).is_pending());
        ready.store(true, Ordering::SeqCst);

        assert!(poll_once(|cx| Pin::new(&mut reader).poll_stop(cx, first)).is_ready());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_stop(cx, second)).is_ready());

        let core = reader.core.lock().expect("reader core lock poisoned");
        assert_eq!(core.stream.stop_codes(), vec![first, first, first]);
    }

    #[test]
    fn concurrent_writer_reset_uses_first_committed_code() {
        let session = std::sync::Weak::new();
        let inner = PendingResetWriteStream::new(11);
        let (mut writer, mut tracked) =
            WebTransportStreamWriter::tracked(StreamId::from(VarInt::from_u32(11)), inner, session);

        let first = VarInt::from_u32(0x41);
        let second = VarInt::from_u32(0x42);

        assert!(poll_once(|cx| Pin::new(&mut writer).poll_reset(cx, first)).is_pending());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_reset(cx, second)).is_pending());

        let core = writer.core.lock().expect("writer core lock poisoned");
        assert_eq!(core.stream.reset_codes(), vec![first, first]);
    }

    #[test]
    fn completed_writer_reset_is_shared_by_both_control_sides() {
        let session = std::sync::Weak::new();
        let ready = Arc::new(AtomicBool::new(false));
        let inner = PendingResetWriteStream::with_ready(15, Arc::clone(&ready));
        let (mut writer, mut tracked) =
            WebTransportStreamWriter::tracked(StreamId::from(VarInt::from_u32(15)), inner, session);

        let first = VarInt::from_u32(0x81);
        let second = VarInt::from_u32(0x82);

        assert!(poll_once(|cx| Pin::new(&mut writer).poll_reset(cx, first)).is_pending());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_reset(cx, second)).is_pending());
        ready.store(true, Ordering::SeqCst);

        assert!(poll_once(|cx| Pin::new(&mut writer).poll_reset(cx, first)).is_ready());
        assert!(poll_once(|cx| Pin::new(&mut tracked).poll_reset(cx, second)).is_ready());

        let core = writer.core.lock().expect("writer core lock poisoned");
        assert_eq!(core.stream.reset_codes(), vec![first, first, first]);
    }

    #[test]
    fn aggregate_wake_wakes_both_reader_control_sides() {
        let session = std::sync::Weak::new();
        let inner = PendingStopReadStream::new(12);
        let (mut reader, mut tracked) =
            WebTransportStreamReader::tracked(StreamId::from(VarInt::from_u32(12)), inner, session);
        let (handle_waker, handle_wakes) = count_waker();
        let (tracked_waker, tracked_wakes) = count_waker();
        let mut handle_cx = Context::from_waker(&handle_waker);
        let mut tracked_cx = Context::from_waker(&tracked_waker);

        assert!(
            Pin::new(&mut reader)
                .poll_stop(&mut handle_cx, VarInt::from_u32(0x51))
                .is_pending()
        );
        assert!(
            Pin::new(&mut tracked)
                .poll_stop(&mut tracked_cx, VarInt::from_u32(0x52))
                .is_pending()
        );

        let aggregate = {
            let core = reader.core.lock().expect("reader core lock poisoned");
            core.stream.waker.as_ref().expect("aggregate waker").clone()
        };
        aggregate.wake_by_ref();

        assert_eq!(handle_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(tracked_wakes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn aggregate_wake_wakes_both_writer_control_sides() {
        let session = std::sync::Weak::new();
        let inner = PendingResetWriteStream::new(13);
        let (mut writer, mut tracked) =
            WebTransportStreamWriter::tracked(StreamId::from(VarInt::from_u32(13)), inner, session);
        let (handle_waker, handle_wakes) = count_waker();
        let (tracked_waker, tracked_wakes) = count_waker();
        let mut handle_cx = Context::from_waker(&handle_waker);
        let mut tracked_cx = Context::from_waker(&tracked_waker);

        assert!(
            Pin::new(&mut writer)
                .poll_reset(&mut handle_cx, VarInt::from_u32(0x61))
                .is_pending()
        );
        assert!(
            Pin::new(&mut tracked)
                .poll_reset(&mut tracked_cx, VarInt::from_u32(0x62))
                .is_pending()
        );

        let aggregate = {
            let core = writer.core.lock().expect("writer core lock poisoned");
            core.stream.waker.as_ref().expect("aggregate waker").clone()
        };
        aggregate.wake_by_ref();

        assert_eq!(handle_wakes.load(Ordering::SeqCst), 1);
        assert_eq!(tracked_wakes.load(Ordering::SeqCst), 1);
    }
}
