//! Shared state-machine primitives for [`PipeReader`] and [`PipeWriter`].
//!
//! This module provides the building blocks that both the reader and writer
//! halves compose to implement their respective poll methods:
//!
//! - [`Step<T>`] — a poll-step monad supporting `map` / `and_then` chaining.
//! - [`Transition`] — the vocabulary of state transitions.
//! - [`PipeState<L>`] — generic three-state lifecycle machine.
//! - [`drain()`] — higher-order function for non-blocking inbound frame drain.
//! - [`flush_pending()`] / [`check_lifecycle()`] / [`encode_control()`] — I/O
//!   primitives shared across reader and writer.

use std::{
    io::IoSlice,
    ops::ControlFlow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Stream, future::BoxFuture};
use tokio::{io::AsyncWrite, net::unix::OwnedReadHalf};
use tokio_util::codec::FramedRead;

use super::codec::{
    CONTROL_MAX_LEN, Frame, PUSH_HEADER_MAX_LEN, StreamCodec, encode_push_header,
    encode_varint_to_slice,
};
use crate::{
    quic::{self, ConnectionError, StreamError},
    varint::VarInt,
};

// ── Step<T> — poll-step monad ───────────────────────────────────────────────

/// Result of a single poll step on a live pipe half.
///
/// Supports monadic chaining: `and_then` short-circuits on `Pending` and
/// `Transition`, only calling the continuation on `Done`.
pub(super) enum Step<T> {
    /// Operation completed with value `T`.
    Done(T),
    /// Operation would block — register waker and return `Poll::Pending`.
    Pending,
    /// A state transition should be applied before the next poll iteration.
    Transition(Transition),
}

impl<T> Step<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Step<U> {
        match self {
            Step::Done(v) => Step::Done(f(v)),
            Step::Pending => Step::Pending,
            Step::Transition(t) => Step::Transition(t),
        }
    }

    pub fn and_then<U>(self, f: impl FnOnce(T) -> Step<U>) -> Step<U> {
        match self {
            Step::Done(v) => f(v),
            Step::Pending => Step::Pending,
            Step::Transition(t) => Step::Transition(t),
        }
    }
}

// ── Transition — state-change vocabulary ────────────────────────────────────

/// A state transition to be applied by [`PipeState::apply`].
pub(super) enum Transition {
    /// Peer requested reset (STOP on writer / CANCEL on reader).
    Reset(VarInt),
    /// Clean close (writer SHUT_WR / reader EOF on alive connection).
    Finish,
    /// Connection died (CONN_CLOSED / lifecycle check failure / EOF on dead
    /// connection).  Carries the lifecycle handle so `apply` can create the
    /// `Dying` future without borrowing the `Live` state.
    ConnDied(Arc<dyn quic::DynLifecycle>),
}

// ── PipeState<L> — generic three-state lifecycle machine ────────────────────

/// Three-state lifecycle machine parameterised over the live-state type `L`.
///
/// ```text
/// Live(L) ──Reset──→ Dead(Err(Reset))
///         ──Finish─→ Dead(Ok(()))
///         ──ConnDied→ Dying(fut) ──Ready(e)→ Dead(Err(Connection(e)))
///                     └─check()→Err──────→ Dead(Err(Connection(e)))
/// ```
pub(super) enum PipeState<L> {
    /// Normal operation.
    Live(L),
    /// Connection closed — waiting for the terminal error.
    Dying(BoxFuture<'static, ConnectionError>),
    /// Stream has ended.
    Dead(Result<(), StreamError>),
}

impl<L> PipeState<L> {
    /// Apply a [`Transition`], consuming the `Live` state if necessary.
    ///
    /// After this call the state is guaranteed to be `Dying` or `Dead`.
    pub fn apply(&mut self, transition: Transition, cx: &mut Context<'_>) {
        match transition {
            Transition::Reset(code) => {
                *self = PipeState::Dead(Err(StreamError::Reset { code }));
            }
            Transition::Finish => {
                *self = PipeState::Dead(Ok(()));
            }
            Transition::ConnDied(lifecycle) => {
                if let Err(e) = lifecycle.check() {
                    *self = PipeState::Dead(Err(StreamError::Connection { source: e }));
                    return;
                }
                let mut fut: BoxFuture<'static, ConnectionError> =
                    Box::pin(async move { lifecycle.closed().await });
                match fut.as_mut().poll(cx) {
                    Poll::Ready(e) => {
                        *self = PipeState::Dead(Err(StreamError::Connection { source: e }));
                    }
                    Poll::Pending => {
                        *self = PipeState::Dying(fut);
                    }
                }
            }
        }
    }

    /// Drive non-`Live` states towards `Dead` and return the terminal result.
    ///
    /// Returns `None` when in `Live` — the caller should proceed with the
    /// step function.  Returns `Some(poll)` for `Dying` / `Dead`.
    pub fn poll_non_live(&mut self, cx: &mut Context<'_>) -> Option<Poll<Result<(), StreamError>>> {
        loop {
            match self {
                PipeState::Live(_) => return None,
                PipeState::Dying(fut) => {
                    let e = match fut.as_mut().poll(cx) {
                        Poll::Ready(e) => e,
                        Poll::Pending => return Some(Poll::Pending),
                    };
                    *self = PipeState::Dead(Err(StreamError::Connection { source: e }));
                    continue;
                }
                PipeState::Dead(Ok(())) => return Some(Poll::Ready(Ok(()))),
                PipeState::Dead(Err(e)) => return Some(Poll::Ready(Err(e.clone()))),
            }
        }
    }

    /// Access the `Live` state.  Returns `None` for `Dying`/`Dead`.
    pub fn live_mut(&mut self) -> Option<&mut L> {
        match self {
            PipeState::Live(l) => Some(l),
            _ => None,
        }
    }
}

// ── DrainOutcome + drain() HOF ──────────────────────────────────────────────

/// Result of draining all ready inbound frames from a `FramedRead`.
pub(super) enum DrainOutcome {
    /// All ready frames consumed, no terminal signal.
    Drained,
    /// Callback returned `Break` — a state transition is required.
    Break(Transition),
    /// Read half EOF or codec error.
    ReadClosed,
}

impl DrainOutcome {
    /// Convert to [`Step<()>`].
    ///
    /// `Drained` → `Step::Done(())`, `Break` → `Step::Transition`.
    /// `ReadClosed` semantics differ between reader and writer, so the caller
    /// provides a closure to handle it.
    pub fn resolve(self, on_read_closed: impl FnOnce() -> Step<()>) -> Step<()> {
        match self {
            DrainOutcome::Drained => Step::Done(()),
            DrainOutcome::Break(t) => Step::Transition(t),
            DrainOutcome::ReadClosed => on_read_closed(),
        }
    }
}

/// Non-blocking drain of all ready inbound frames.
///
/// Calls `on_frame` for each decoded frame.  The callback returns
/// `ControlFlow::Continue(())` to keep draining or
/// `ControlFlow::Break(Transition)` to stop immediately.
pub(super) fn drain(
    read: &mut FramedRead<OwnedReadHalf, StreamCodec>,
    cx: &mut Context<'_>,
    mut on_frame: impl FnMut(Frame) -> ControlFlow<Transition>,
) -> DrainOutcome {
    loop {
        match Pin::new(&mut *read).poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => match on_frame(frame) {
                ControlFlow::Continue(()) => continue,
                ControlFlow::Break(t) => return DrainOutcome::Break(t),
            },
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                return DrainOutcome::ReadClosed;
            }
            Poll::Pending => return DrainOutcome::Drained,
        }
    }
}

// ── Shared I/O primitives ───────────────────────────────────────────────────

/// Buffered PUSH frame waiting to be flushed via vectored I/O.
pub(super) struct PendingPush {
    header: [u8; PUSH_HEADER_MAX_LEN],
    header_len: usize,
    header_off: usize,
    body: Bytes,
    body_off: usize,
}

impl PendingPush {
    /// Create a new pending PUSH frame from a body payload.
    pub fn new(body: Bytes) -> Result<Self, StreamError> {
        let (header, header_len) =
            encode_push_header(body.len()).map_err(|_| StreamError::Reset {
                code: VarInt::default(),
            })?;
        Ok(Self {
            header,
            header_len,
            header_off: 0,
            body,
            body_off: 0,
        })
    }

    fn header_remaining(&self) -> &[u8] {
        &self.header[self.header_off..self.header_len]
    }

    fn body_remaining(&self) -> &[u8] {
        &self.body[self.body_off..]
    }

    fn is_done(&self) -> bool {
        self.header_off == self.header_len && self.body_off == self.body.len()
    }

    fn advance(&mut self, mut written: usize) {
        let header_left = self.header_len - self.header_off;
        let take_header = written.min(header_left);
        self.header_off += take_header;
        written -= take_header;
        self.body_off += written;
    }
}

/// Buffered STOP/CANCEL control frame waiting to be flushed.
pub(super) struct PendingControl {
    buf: [u8; CONTROL_MAX_LEN],
    len: usize,
    off: usize,
}

impl PendingControl {
    /// Create a pending control frame from a frame tag and QUIC error code.
    pub fn new(tag: u8, code: VarInt) -> Self {
        let (buf, len) = encode_control(tag, code);
        Self { buf, len, off: 0 }
    }

    fn remaining(&self) -> &[u8] {
        &self.buf[self.off..self.len]
    }

    fn advance(&mut self, written: usize) {
        self.off += written;
    }

    fn is_done(&self) -> bool {
        self.off == self.len
    }
}

/// Flush a pending control frame through `write`.
pub(super) fn flush_control(
    write: &mut (impl AsyncWrite + Unpin),
    lifecycle: &Arc<dyn quic::DynLifecycle>,
    pending: &mut Option<PendingControl>,
    cx: &mut Context<'_>,
) -> Step<()> {
    loop {
        let Some(control) = pending.as_mut() else {
            return Step::Done(());
        };

        let written = match Pin::new(&mut *write).poll_write(cx, control.remaining()) {
            Poll::Ready(Ok(0)) => {
                return check_lifecycle(lifecycle, Step::Transition(Transition::Finish));
            }
            Poll::Ready(Ok(written)) => written,
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe write error during control frame flush");
                return check_lifecycle(lifecycle, Step::Transition(Transition::Finish));
            }
            Poll::Pending => return Step::Pending,
        };

        control.advance(written);
        if control.is_done() {
            *pending = None;
        }
    }
}

/// Flush a pending PUSH frame through `write` using vectored I/O.
///
/// Returns `Step::Done(())` when fully written, `Step::Pending` when blocked,
/// or `Step::Transition(ConnDied)` on I/O error (after lifecycle check).
pub(super) fn flush_pending(
    write: &mut (impl AsyncWrite + Unpin),
    lifecycle: &Arc<dyn quic::DynLifecycle>,
    pending: &mut Option<PendingPush>,
    cx: &mut Context<'_>,
) -> Step<()> {
    loop {
        let Some(p) = pending.as_ref() else {
            return Step::Done(());
        };

        let header_remaining = p.header_remaining();
        let body_remaining = p.body_remaining();
        let bufs = [IoSlice::new(header_remaining), IoSlice::new(body_remaining)];
        let bufs: &[IoSlice<'_>] = if header_remaining.is_empty() {
            &bufs[1..]
        } else if body_remaining.is_empty() {
            &bufs[..1]
        } else {
            &bufs
        };

        let written = match Pin::new(&mut *write).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(0)) => {
                return check_lifecycle(lifecycle, Step::Transition(Transition::Finish));
            }
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(e)) => {
                tracing::debug!(%e, "pipe write error during PUSH flush");
                return check_lifecycle(lifecycle, Step::Transition(Transition::Finish));
            }
            Poll::Pending => return Step::Pending,
        };

        let p = pending.as_mut().unwrap();
        p.advance(written);
        if p.is_done() {
            *pending = None;
        }
    }
}

/// Check the connection lifecycle.
///
/// If the connection is dead, returns `Transition::ConnDied`.
/// Otherwise returns `on_alive` unchanged.
pub(super) fn check_lifecycle(
    lifecycle: &Arc<dyn quic::DynLifecycle>,
    on_alive: Step<()>,
) -> Step<()> {
    if lifecycle.check().is_err() {
        Step::Transition(Transition::ConnDied(lifecycle.clone()))
    } else {
        on_alive
    }
}

/// Encode a control frame (STOP or CANCEL) into a stack buffer.
///
/// Returns `(buffer, length)` ready for a single `poll_write`.
pub(super) fn encode_control(tag: u8, code: VarInt) -> ([u8; CONTROL_MAX_LEN], usize) {
    let mut buf = [0u8; CONTROL_MAX_LEN];
    buf[0] = tag;
    let vi_len = encode_varint_to_slice(&mut buf[1..], code);
    (buf, 1 + vi_len)
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        io::{self, ErrorKind},
        ops::ControlFlow,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::{Bytes, BytesMut};
    use futures::{future::poll_fn, task::noop_waker_ref};
    use tokio::{
        io::{AsyncWrite, AsyncWriteExt},
        net::{
            UnixStream,
            unix::{OwnedReadHalf, OwnedWriteHalf},
        },
        sync::Notify,
    };
    use tokio_util::codec::{Encoder, FramedRead};

    use super::{
        super::codec::{Frame, StreamCodec},
        DrainOutcome, PendingPush, PipeState, Step, Transition,
    };
    use crate::{
        error::Code,
        quic::{self, StreamError},
        varint::VarInt,
    };

    fn test_connection_error(reason: &str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x02),
                frame_type: VarInt::from_u32(0x07),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn create_context() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    struct TestLifecycle {
        terminal_error: Arc<Mutex<Option<quic::ConnectionError>>>,
        notify: Arc<Notify>,
    }

    impl TestLifecycle {
        fn alive() -> Self {
            Self {
                terminal_error: Arc::new(Mutex::new(None)),
                notify: Arc::new(Notify::new()),
            }
        }

        fn dead(reason: &str) -> Self {
            let lifecycle = Self::alive();
            lifecycle.set_error(test_connection_error(reason));
            lifecycle
        }

        fn set_error(&self, error: quic::ConnectionError) {
            let mut terminal_error = self.terminal_error.lock().unwrap();
            *terminal_error = Some(error);
            self.notify.notify_waiters();
        }
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            match self.terminal_error.lock().unwrap().clone() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }

        async fn closed(&self) -> quic::ConnectionError {
            loop {
                let terminal_error = self.terminal_error.lock().unwrap().clone();
                if let Some(error) = terminal_error {
                    break error;
                }
                self.notify.notified().await;
            }
        }
    }

    #[test]
    fn step_map_and_then_are_functor_like() {
        let value = Step::Done(1).map(|x| x + 1);
        assert!(matches!(value, Step::Done(2)));
        assert!(matches!(Step::<u8>::Pending.map(|x| x + 1), Step::Pending));
        assert!(matches!(
            Step::<u8>::Transition(Transition::Finish).map(|x| x + 1),
            Step::Transition(Transition::Finish)
        ));

        let transition = Transition::Reset(VarInt::from_u32(7));
        let value = Step::Done(1).and_then(|x| Step::Done(x + 10));
        assert!(matches!(value, Step::Done(11)));
        assert!(matches!(
            Step::<u8>::Pending.and_then(Step::Done),
            Step::Pending
        ));
        assert!(matches!(
            Step::<u8>::Transition(transition).and_then(Step::Done),
            Step::Transition(Transition::Reset(_))
        ));
    }

    #[test]
    fn pipe_state_apply_transitions_to_dead_and_dying_states() {
        let code = VarInt::from_u32(4);
        let mut cx = create_context();
        let mut state = PipeState::Live(());

        state.apply(Transition::Reset(code), &mut cx);
        assert!(matches!(
            state,
            PipeState::Dead(Err(StreamError::Reset { code: got })) if got == code
        ));

        let mut state = PipeState::Live(());
        state.apply(Transition::Finish, &mut cx);
        assert!(matches!(state, PipeState::Dead(Ok(()))));

        let dead_lifecycle = TestLifecycle::dead("closed");
        let mut state = PipeState::Live(());
        state.apply(Transition::ConnDied(Arc::new(dead_lifecycle)), &mut cx);
        assert!(matches!(
            state,
            PipeState::Dead(Err(StreamError::Connection { .. }))
        ));

        let alive_lifecycle = Arc::new(TestLifecycle::alive());
        let mut state = PipeState::Live(());
        state.apply(Transition::ConnDied(alive_lifecycle.clone() as _), &mut cx);
        assert!(matches!(state, PipeState::Dying(_)));
        let ready = state.poll_non_live(&mut cx);
        assert!(matches!(ready, Some(Poll::Pending)));

        alive_lifecycle.set_error(test_connection_error("gone"));
        let ready = state.poll_non_live(&mut cx);
        assert!(matches!(
            ready,
            Some(Poll::Ready(Err(StreamError::Connection { .. })))
        ));
    }

    #[test]
    fn pipe_state_poll_non_live_and_live_mut_behaviour() {
        let mut cx = create_context();

        let mut state: PipeState<i32> = PipeState::Live(8);
        assert!(state.poll_non_live(&mut cx).is_none());
        assert!(state.live_mut().is_some());

        state = PipeState::Dead(Ok(()));
        assert!(matches!(
            state.poll_non_live(&mut cx),
            Some(Poll::Ready(Ok(())))
        ));
        assert!(state.live_mut().is_none());

        let mut state: PipeState<i32> = PipeState::Dead(Err(StreamError::Connection {
            source: test_connection_error("bad"),
        }));
        assert!(matches!(
            state.poll_non_live(&mut cx),
            Some(Poll::Ready(Err(StreamError::Connection { .. })))
        ));
    }

    #[test]
    fn drain_outcome_resolve_maps_read_closed_and_break_cases() {
        let step = DrainOutcome::Drained.resolve(|| Step::Done(()));
        assert!(matches!(step, Step::Done(())));

        assert!(matches!(
            DrainOutcome::Break(Transition::Finish).resolve(|| Step::Done(())),
            Step::Transition(Transition::Finish)
        ));

        let step = DrainOutcome::ReadClosed
            .resolve(|| Step::Transition(Transition::Reset(VarInt::from_u32(3))));
        assert!(matches!(
            step,
            Step::Transition(Transition::Reset(code)) if code == VarInt::from_u32(3)
        ));
    }

    async fn make_framed_reader_and_writer()
    -> (FramedRead<OwnedReadHalf, StreamCodec>, OwnedWriteHalf) {
        let (left, right) = UnixStream::pair().unwrap();
        let (left_read, _left_write) = left.into_split();
        let (right_read, right_write) = right.into_split();
        let read = FramedRead::new(left_read, StreamCodec::new());
        drop(right_read);
        (read, right_write)
    }

    async fn write_frames(write: &mut OwnedWriteHalf, frames: &[Frame]) -> io::Result<()> {
        let mut codec = StreamCodec::new();
        let mut buf = BytesMut::new();
        for frame in frames {
            Encoder::encode(&mut codec, frame.clone(), &mut buf).map_err(io::Error::other)?;
        }
        write.write_all(&buf).await?;
        write.flush().await
    }

    #[tokio::test]
    async fn drain_returns_drained_when_no_frames_available() {
        let (mut read, write) = make_framed_reader_and_writer().await;
        drop(write);
        let mut cx = create_context();
        let outcome = super::drain(&mut read, &mut cx, |_| ControlFlow::Continue(()));
        assert!(matches!(outcome, super::DrainOutcome::Drained));
    }

    #[tokio::test]
    async fn drain_returns_break_when_callback_requests_transition() {
        let (mut read, mut write) = make_framed_reader_and_writer().await;
        write_frames(
            &mut write,
            &[
                Frame::Pull,
                Frame::Push(Bytes::from_static(b"hello")),
                Frame::Stop(VarInt::from_u32(7)),
            ],
        )
        .await
        .unwrap();
        let mut pulled = false;
        let mut saw_push = false;
        let mut outcome = super::DrainOutcome::Drained;
        for _ in 0..4 {
            outcome = poll_fn(|cx| {
                Poll::Ready(super::drain(&mut read, cx, |frame| match frame {
                    super::super::codec::Frame::Pull => {
                        pulled = true;
                        ControlFlow::Continue(())
                    }
                    super::super::codec::Frame::Push(_) => {
                        saw_push = true;
                        ControlFlow::Continue(())
                    }
                    super::super::codec::Frame::Stop(code) => {
                        assert_eq!(code, VarInt::from_u32(7));
                        ControlFlow::Break(Transition::Reset(code))
                    }
                    super::super::codec::Frame::Cancel(_)
                    | super::super::codec::Frame::ConnClosed => ControlFlow::Continue(()),
                }))
            })
            .await;
            if !matches!(outcome, super::DrainOutcome::Drained) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(pulled);
        assert!(saw_push);
        assert!(matches!(
            outcome,
            super::DrainOutcome::Break(Transition::Reset(code)) if code == VarInt::from_u32(7)
        ));
    }

    #[tokio::test]
    async fn drain_returns_read_closed_on_eof_and_codec_error() {
        let (mut read, mut write) = make_framed_reader_and_writer().await;
        write_frames(&mut write, &[Frame::Push(Bytes::from_static(b"bye"))])
            .await
            .unwrap();
        write.shutdown().await.unwrap();
        drop(write);
        let mut push_seen = false;
        let mut outcome = super::DrainOutcome::Drained;
        for _ in 0..4 {
            outcome = poll_fn(|cx| {
                Poll::Ready(super::drain(&mut read, cx, |frame| {
                    push_seen = matches!(frame, super::super::codec::Frame::Push(_));
                    ControlFlow::Continue(())
                }))
            })
            .await;
            if !matches!(outcome, super::DrainOutcome::Drained) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(push_seen);
        assert!(matches!(
            outcome,
            super::DrainOutcome::ReadClosed | super::DrainOutcome::Drained
        ));

        let (mut read, mut raw) = make_framed_reader_and_writer().await;
        raw.write_all(&[0xff]).await.unwrap();
        let outcome =
            poll_fn(|cx| Poll::Ready(super::drain(&mut read, cx, |_| ControlFlow::Continue(()))))
                .await;
        assert!(matches!(
            outcome,
            super::DrainOutcome::ReadClosed | super::DrainOutcome::Drained
        ));
    }

    enum MockWriteBehavior {
        Chunk(usize),
        Pending,
        Zero,
        Error,
    }

    struct MockWrite {
        behavior: MockWriteBehavior,
        written: Vec<u8>,
        pending_returned: bool,
    }

    impl MockWrite {
        fn new(behavior: MockWriteBehavior) -> Self {
            Self {
                behavior,
                written: Vec::new(),
                pending_returned: false,
            }
        }
    }

    impl AsyncWrite for MockWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            let slices = [std::io::IoSlice::new(buf)];
            self.poll_write_vectored(cx, &slices)
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<Result<usize, io::Error>> {
            let this = self.get_mut();
            match &this.behavior {
                MockWriteBehavior::Chunk(chunk) => {
                    let total = bufs.iter().map(|b| b.len()).sum::<usize>();
                    let count = total.min(*chunk);
                    let mut remaining = count;
                    for buf in bufs {
                        let take = remaining.min(buf.len());
                        this.written.extend_from_slice(&buf[..take]);
                        remaining -= take;
                        if remaining == 0 {
                            break;
                        }
                    }
                    Poll::Ready(Ok(count))
                }
                MockWriteBehavior::Pending => {
                    if this.pending_returned {
                        Poll::Ready(Ok(0))
                    } else {
                        this.pending_returned = true;
                        Poll::Pending
                    }
                }
                MockWriteBehavior::Zero => Poll::Ready(Ok(0)),
                MockWriteBehavior::Error => Poll::Ready(Err(io::Error::new(
                    ErrorKind::BrokenPipe,
                    "mock write error",
                ))),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn flush_pending_reports_done_and_clears_pending_on_success() {
        let mut write = MockWrite::new(MockWriteBehavior::Chunk(4));
        let payload = Bytes::from_static(b"hello world");
        let mut pending = Some(PendingPush::new(payload.clone()).unwrap());
        let mut cx = create_context();
        let lifecycle: Arc<dyn quic::DynLifecycle> = Arc::new(TestLifecycle::alive());

        let result = super::flush_pending(&mut write, &lifecycle, &mut pending, &mut cx);
        assert!(matches!(result, super::Step::Done(())));
        assert!(pending.is_none());
        assert!(!write.written.is_empty());

        let mut expected = Vec::new();
        let (header, header_len) = super::super::codec::encode_push_header(payload.len()).unwrap();
        expected.extend_from_slice(&header[..header_len]);
        expected.extend_from_slice(&payload);
        assert_eq!(write.written, expected);
    }

    #[test]
    fn flush_pending_passes_readiness_changes() {
        let mut write = MockWrite::new(MockWriteBehavior::Pending);
        let mut pending = Some(PendingPush::new(Bytes::from_static(b"hello")).unwrap());
        let mut cx = create_context();
        let lifecycle: Arc<dyn quic::DynLifecycle> = Arc::new(TestLifecycle::alive());

        let result = super::flush_pending(&mut write, &lifecycle, &mut pending, &mut cx);
        assert!(matches!(result, super::Step::Pending));
        assert!(pending.is_some());
    }

    #[test]
    fn flush_pending_converts_zero_and_error_to_transition() {
        let lifecycle: Arc<dyn quic::DynLifecycle> = Arc::new(TestLifecycle::alive());
        let mut cx = create_context();

        let mut zero = MockWrite::new(MockWriteBehavior::Zero);
        let mut pending = Some(PendingPush::new(Bytes::from_static(b"hello")).unwrap());
        let result = super::flush_pending(&mut zero, &lifecycle, &mut pending, &mut cx);
        assert!(matches!(
            result,
            super::Step::Transition(super::Transition::Finish)
        ));

        let mut error = MockWrite::new(MockWriteBehavior::Error);
        let mut pending = Some(PendingPush::new(Bytes::from_static(b"hello")).unwrap());
        let result = super::flush_pending(&mut error, &lifecycle, &mut pending, &mut cx);
        assert!(matches!(
            result,
            super::Step::Transition(super::Transition::Finish)
        ));
    }

    #[test]
    fn check_lifecycle_preserves_alive_or_transitions_to_conn_died() {
        let alive = Arc::new(TestLifecycle::alive());
        let step = super::check_lifecycle(
            &(alive as Arc<dyn quic::DynLifecycle>),
            Step::Transition(Transition::Finish),
        );
        assert!(matches!(step, Step::Transition(Transition::Finish)));

        let dead = Arc::new(TestLifecycle::dead("dead"));
        let step = super::check_lifecycle(&(dead as Arc<dyn quic::DynLifecycle>), Step::Done(()));
        assert!(matches!(step, Step::Transition(Transition::ConnDied(_))));
    }

    #[test]
    fn encode_control_has_expected_prefix_and_length() {
        use super::super::codec::encode_varint_to_slice;

        let tag = 0x09;
        let code = VarInt::from_u32(0x1f4);
        let (buf, len) = super::encode_control(tag, code);
        let mut expected = [0u8; super::super::codec::CONTROL_MAX_LEN];
        expected[0] = tag;
        let vi_len = encode_varint_to_slice(&mut expected[1..], code);
        let expected_len = 1 + vi_len;
        assert_eq!(len, expected_len);
        assert_eq!(&buf[..len], &expected[..expected_len]);
    }
}
