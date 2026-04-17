//! Reusable error-latching utilities for RPC/IPC.
//!
//! These types enforce the QUIC connection-error consistency requirement:
//! once a connection error occurs, **every** subsequent operation on the
//! same connection must observe the **same** error.
//!
//! # [`ConnectionErrorLatch`]
//!
//! A thin wrapper around [`SetOnce<ConnectionError>`] with *first-wins*
//! semantics: [`latch`](ConnectionErrorLatch::latch) records the first error
//! and returns it; any later call returns the previously recorded error,
//! discarding the new one.

use std::future::Future;

use crate::{quic::ConnectionError, util::set_once::SetOnce};

// ---------------------------------------------------------------------------
// ConnectionErrorLatch
// ---------------------------------------------------------------------------

/// First-wins connection error latch.
///
/// Calling [`latch`](Self::latch) with an error either:
/// - **records** it (if no error is latched yet) and returns it, or
/// - **returns the already-latched** error, discarding the new one.
///
/// Because [`SetOnce`] is backed by `Arc`, cloning a latch yields a handle
/// to the **same** underlying state — useful for sharing between a lifecycle
/// and its owning handle.
#[derive(Debug, Clone, Default)]
pub struct ConnectionErrorLatch {
    terminal_error: SetOnce<ConnectionError>,
}

impl ConnectionErrorLatch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Latch a connection error (first-wins).
    ///
    /// If an error is already latched, the *existing* error is returned
    /// and `error` is discarded.  Otherwise `error` is recorded and
    /// returned.
    pub fn latch(&self, error: ConnectionError) -> ConnectionError {
        match self.terminal_error.peek() {
            Some(existing) => existing,
            None => {
                let _ = self.terminal_error.set(error.clone());
                error
            }
        }
    }

    /// Lazy variant of [`latch`](Self::latch): only calls `f` when no error
    /// is latched yet, avoiding unnecessary error construction.
    pub fn latch_with(&self, f: impl FnOnce() -> ConnectionError) -> ConnectionError {
        match self.terminal_error.peek() {
            Some(existing) => existing,
            None => {
                let error = f();
                let _ = self.terminal_error.set(error.clone());
                error
            }
        }
    }

    /// Return the latched error, if any.
    pub fn check(&self) -> Result<(), ConnectionError> {
        match self.terminal_error.peek() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Peek at the latched error without blocking.
    pub fn peek(&self) -> Option<ConnectionError> {
        self.terminal_error.peek()
    }

    /// Guard an async operation: check the latch first, then execute, latching
    /// any resulting error.
    pub async fn guard<T>(
        &self,
        fut: impl Future<Output = Result<T, ConnectionError>>,
    ) -> Result<T, ConnectionError> {
        self.check()?;
        fut.await.map_err(|e| self.latch(e))
    }
}
