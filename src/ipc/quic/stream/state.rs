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
