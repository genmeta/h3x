//! Reusable error-latching utilities for RPC/IPC.
//!
//! These types enforce the QUIC connection-error consistency requirement:
//! once a connection error occurs, **every** subsequent operation on the
//! same connection must observe the **same** error.
//!
//! # Design rules
//!
//! - **No eager `latch(e)` on the public surface.** Callers must always use
//!   `latch_with(|| ...)` / `guard*_with(...)` so that error construction is
//!   lazy and skipped entirely when an error is already latched.
//! - **No bare `check()?` on operation paths.** Use one of the `guard*`
//!   helpers on [`LifecycleExt`] so the check / execute / latch sequence
//!   stays in one place.
//! - **The latch is an implementation detail.** Application code never
//!   touches [`ConnectionErrorLatch`] directly — it interacts through
//!   [`LifecycleExt`] on the owning container type.
//!
//! # Design
//!
//! Container types (e.g. `RemoteConnection`, `IpcLifecycle`, session types)
//! own a [`ConnectionErrorLatch`] field and expose it to the crate through
//! the sealed [`HasLatch`] trait. Implementing `HasLatch` plus
//! [`quic::Lifecycle`] automatically gives the container all of
//! [`LifecycleExt`]'s guard/check/closed helpers via blanket impl.
//!
//! The container authors its own `impl Lifecycle` using
//! [`check_with_probe`](LifecycleExt::check_with_probe) and
//! [`resolve_closed`](LifecycleExt::resolve_closed) as building blocks;
//! operation paths use [`guard`](LifecycleExt::guard) /
//! [`guard_with`](LifecycleExt::guard_with) /
//! [`guard_sync`](LifecycleExt::guard_sync) /
//! [`guard_sync_with`](LifecycleExt::guard_sync_with) exclusively.

use std::future::Future;

use crate::{
    quic::{self, ConnectionError},
    util::set_once::SetOnce,
};

// ---------------------------------------------------------------------------
// ConnectionErrorLatch
// ---------------------------------------------------------------------------

/// First-wins connection error latch.
///
/// Cloning yields a handle to the **same** underlying state — the latch is
/// `Arc`-backed via [`SetOnce`].
///
/// This type is a crate-internal primitive. Application code interacts with
/// it only through [`LifecycleExt`] on the owning container.
#[derive(Debug, Clone, Default)]
pub struct ConnectionErrorLatch {
    terminal_error: SetOnce<ConnectionError>,
}

impl ConnectionErrorLatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lazy latch: only calls `f` when no error is latched yet.
    ///
    /// Returns the canonical (first-wins) error.
    pub(crate) fn latch_with(&self, f: impl FnOnce() -> ConnectionError) -> ConnectionError {
        match self.terminal_error.peek() {
            Some(existing) => existing,
            None => {
                let error = f();
                let _ = self.terminal_error.set(error.clone());
                error
            }
        }
    }

    /// Crate-internal shortcut equivalent to `latch_with(|| error)`.
    ///
    /// Intended for call sites that already own a concrete [`ConnectionError`]
    /// (e.g. forwarding the terminal error out of `closed()` after the
    /// underlying future resolved).
    pub(crate) fn latch_raw(&self, error: ConnectionError) -> ConnectionError {
        self.latch_with(|| error)
    }

    /// Return the latched error, if any.
    pub(crate) fn check(&self) -> Result<(), ConnectionError> {
        match self.terminal_error.peek() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Peek at the latched error without consuming it.
    pub(crate) fn peek(&self) -> Option<ConnectionError> {
        self.terminal_error.peek()
    }
}

// ---------------------------------------------------------------------------
// Sealed HasLatch — bridge between container types and LifecycleExt
// ---------------------------------------------------------------------------

pub(crate) mod sealed {
    use super::ConnectionErrorLatch;

    /// Crate-internal trait that lets [`super::LifecycleExt`] reach into a
    /// container's latch without making the latch a public API.
    ///
    /// Implementers must return a stable reference to the same
    /// [`ConnectionErrorLatch`] on every call.
    pub trait HasLatch {
        fn latch(&self) -> &ConnectionErrorLatch;
    }
}

pub(crate) use sealed::HasLatch;

// ---------------------------------------------------------------------------
// LifecycleExt — the only public surface for guard / check / closed
// ---------------------------------------------------------------------------

/// Extension trait layered on top of [`quic::Lifecycle`] that enforces the
/// first-wins error-latching discipline for all operation paths.
///
/// This trait is **sealed**: it is automatically implemented for any type
/// that implements both [`quic::Lifecycle`] and the crate-private
/// [`HasLatch`] marker.
///
/// Implementers typically do two things:
///
/// 1. Own a `latch: ConnectionErrorLatch` field and implement [`HasLatch`].
/// 2. Author their own `impl quic::Lifecycle`, using
///    [`check_with_probe`](Self::check_with_probe) inside `check` and
///    [`resolve_closed`](Self::resolve_closed) inside `closed`.
///
/// Callers use [`guard`](Self::guard) /
/// [`guard_with`](Self::guard_with) /
/// [`guard_sync`](Self::guard_sync) /
/// [`guard_sync_with`](Self::guard_sync_with) for operation paths. No other
/// mechanism for installing errors is exposed.
#[allow(async_fn_in_trait)]
pub trait LifecycleExt: quic::Lifecycle + HasLatch {
    /// Standard implementation of [`quic::Lifecycle::check`].
    ///
    /// Consults the latch first; if clean, invokes `probe` for any
    /// liveness signal the container wants to expose (e.g. a remoc channel
    /// being closed, or a parent lifecycle being dead). A `Some(error)`
    /// result is folded into the latch via `latch_with` so every subsequent
    /// observer sees the same canonical error.
    fn check_with_probe(
        &self,
        probe: impl FnOnce() -> Option<ConnectionError>,
    ) -> Result<(), ConnectionError> {
        self.latch().check()?;
        match probe() {
            None => Ok(()),
            Some(error) => Err(self.latch().latch_with(|| error)),
        }
    }

    /// Standard implementation of [`quic::Lifecycle::closed`].
    ///
    /// Returns the latched error immediately if one exists; otherwise awaits
    /// `wait` (the container-specific terminal-error future) and latches
    /// whatever it produces.
    async fn resolve_closed(&self, wait: impl Future<Output = ConnectionError>) -> ConnectionError {
        if let Some(error) = self.latch().peek() {
            return error;
        }
        let error = wait.await;
        self.latch().latch_raw(error)
    }

    /// Guard an async operation whose error is already a [`ConnectionError`].
    ///
    /// Checks liveness via [`quic::Lifecycle::check`] first; on success runs
    /// `fut` and lazily latches any error produced.
    async fn guard<T>(
        &self,
        fut: impl Future<Output = Result<T, ConnectionError>>,
    ) -> Result<T, ConnectionError> {
        quic::Lifecycle::check(self)?;
        match fut.await {
            Ok(v) => Ok(v),
            Err(e) => Err(self.latch().latch_with(|| e)),
        }
    }

    /// Guard an async operation whose error must be lazily converted to a
    /// [`ConnectionError`].
    ///
    /// The conversion closure `map_err` is **only** invoked if the operation
    /// errors **and** no error has been latched yet.
    async fn guard_with<T, E, M>(
        &self,
        fut: impl Future<Output = Result<T, E>>,
        map_err: M,
    ) -> Result<T, ConnectionError>
    where
        M: FnOnce(E) -> ConnectionError,
    {
        quic::Lifecycle::check(self)?;
        match fut.await {
            Ok(v) => Ok(v),
            Err(e) => Err(self.latch().latch_with(|| map_err(e))),
        }
    }

    /// Guard a synchronous fallible closure.
    ///
    /// Useful for code paths where both the pre-check and the post-op
    /// error-latching would otherwise be written by hand (e.g. FD unwrapping
    /// after an async stream-open call).
    fn guard_sync<T>(
        &self,
        f: impl FnOnce() -> Result<T, ConnectionError>,
    ) -> Result<T, ConnectionError> {
        quic::Lifecycle::check(self)?;
        match f() {
            Ok(v) => Ok(v),
            Err(e) => Err(self.latch().latch_with(|| e)),
        }
    }

    /// Like [`guard_sync`](Self::guard_sync) but with a lazy error converter.
    fn guard_sync_with<T, E, M>(
        &self,
        f: impl FnOnce() -> Result<T, E>,
        map_err: M,
    ) -> Result<T, ConnectionError>
    where
        M: FnOnce(E) -> ConnectionError,
    {
        quic::Lifecycle::check(self)?;
        match f() {
            Ok(v) => Ok(v),
            Err(e) => Err(self.latch().latch_with(|| map_err(e))),
        }
    }
}

impl<T: quic::Lifecycle + HasLatch + ?Sized> LifecycleExt for T {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        sync::{Arc, Mutex},
    };

    use super::*;
    use crate::{error::Code, varint::VarInt};

    fn make_err(tag: u32) -> ConnectionError {
        ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(tag),
                frame_type: VarInt::from_u32(0),
                reason: format!("test-{tag}").into(),
            },
        }
    }

    /// Minimal container used to exercise the sealed trait.
    struct TestLifecycle {
        latch: ConnectionErrorLatch,
        probe: Mutex<Option<ConnectionError>>,
        wait: Mutex<Option<ConnectionError>>,
    }

    impl TestLifecycle {
        fn new() -> Self {
            Self {
                latch: ConnectionErrorLatch::new(),
                probe: Mutex::new(None),
                wait: Mutex::new(None),
            }
        }

        fn set_probe(&self, error: ConnectionError) {
            *self.probe.lock().unwrap() = Some(error);
        }

        fn set_wait(&self, error: ConnectionError) {
            *self.wait.lock().unwrap() = Some(error);
        }
    }

    impl HasLatch for TestLifecycle {
        fn latch(&self) -> &ConnectionErrorLatch {
            &self.latch
        }
    }

    impl quic::Lifecycle for TestLifecycle {
        fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), ConnectionError> {
            self.check_with_probe(|| self.probe.lock().unwrap().take())
        }

        async fn closed(&self) -> ConnectionError {
            self.resolve_closed(async {
                self.wait
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap_or_else(|| make_err(99))
            })
            .await
        }
    }

    #[test]
    fn latch_with_is_lazy_when_already_latched() {
        let latch = ConnectionErrorLatch::new();
        let first = latch.latch_with(|| make_err(1));
        assert!(matches!(
            &first,
            ConnectionError::Transport { source } if source.kind == VarInt::from_u32(1)
        ));

        let called = Mutex::new(false);
        let again = latch.latch_with(|| {
            *called.lock().unwrap() = true;
            make_err(2)
        });
        assert!(
            !*called.lock().unwrap(),
            "closure must not be invoked once latched"
        );
        assert!(matches!(
            &again,
            ConnectionError::Transport { source } if source.kind == VarInt::from_u32(1)
        ));
    }

    #[test]
    fn check_with_probe_folds_probe_into_latch() {
        let lc = TestLifecycle::new();
        lc.set_probe(make_err(42));
        let e1 = quic::Lifecycle::check(&lc).unwrap_err();
        // probe now consumed — but latch remembers the error.
        let e2 = quic::Lifecycle::check(&lc).unwrap_err();
        match (&e1, &e2) {
            (
                ConnectionError::Transport { source: s1 },
                ConnectionError::Transport { source: s2 },
            ) => {
                assert_eq!(s1.kind, VarInt::from_u32(42));
                assert_eq!(s2.kind, VarInt::from_u32(42));
            }
            _ => panic!("unexpected error shape"),
        }
    }

    #[test]
    fn check_with_probe_no_error_when_clean() {
        let lc = TestLifecycle::new();
        assert!(quic::Lifecycle::check(&lc).is_ok());
    }

    #[tokio::test]
    async fn resolve_closed_returns_latched_without_awaiting() {
        let lc = TestLifecycle::new();
        lc.latch.latch_with(|| make_err(7));
        // `wait` is never polled because the latch is already set; if it
        // were, the `take()` below would come back `None`.
        let never = Mutex::new(Some(make_err(8)));
        let got = lc
            .resolve_closed(async { never.lock().unwrap().take().unwrap() })
            .await;
        assert!(matches!(
            &got,
            ConnectionError::Transport { source } if source.kind == VarInt::from_u32(7)
        ));
        assert!(never.lock().unwrap().is_some(), "wait must not be polled");
    }

    #[tokio::test]
    async fn resolve_closed_latches_wait_result() {
        let lc = TestLifecycle::new();
        lc.set_wait(make_err(5));
        let got = quic::Lifecycle::closed(&lc).await;
        assert!(matches!(
            &got,
            ConnectionError::Transport { source } if source.kind == VarInt::from_u32(5)
        ));
        // Second call must return the same error and must not hit the wait
        // future again.
        let again = quic::Lifecycle::closed(&lc).await;
        assert!(matches!(
            &again,
            ConnectionError::Transport { source } if source.kind == VarInt::from_u32(5)
        ));
    }

    #[tokio::test]
    async fn guard_with_skips_closure_when_latched() {
        let lc = TestLifecycle::new();
        lc.latch.latch_with(|| make_err(7));

        let called = Arc::new(Mutex::new(false));
        let called2 = called.clone();
        let res: Result<(), ConnectionError> = lc
            .guard_with(async { Result::<(), &'static str>::Err("x") }, move |_| {
                *called2.lock().unwrap() = true;
                make_err(8)
            })
            .await;
        assert!(res.is_err());
        assert!(
            !*called.lock().unwrap(),
            "map_err must stay lazy once latched"
        );
    }

    #[tokio::test]
    async fn guard_with_success_is_untouched() {
        let lc = TestLifecycle::new();
        let out: Result<i32, ConnectionError> = lc
            .guard_with(async { Ok::<_, &'static str>(7) }, |_| make_err(1))
            .await;
        assert_eq!(out.unwrap(), 7);
    }

    #[test]
    fn guard_sync_latches_only_first_error() {
        let lc = TestLifecycle::new();
        let a = lc.guard_sync(|| Err::<(), _>(make_err(1))).unwrap_err();
        let b = lc.guard_sync(|| Err::<(), _>(make_err(2))).unwrap_err();
        match (&a, &b) {
            (
                ConnectionError::Transport { source: sa },
                ConnectionError::Transport { source: sb },
            ) => {
                assert_eq!(sa.kind, sb.kind);
                assert_eq!(sa.kind, VarInt::from_u32(1));
            }
            _ => panic!("unexpected error shape"),
        }
    }
}
