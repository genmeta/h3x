use std::{future::Future, sync::Mutex};

use tokio::task::JoinSet;
use tracing::Instrument;

/// A thin wrapper around `Mutex<JoinSet<()>>` that automatically drains
/// completed task handles on every `spawn`, preventing unbounded accumulation.
pub(super) struct TaskSet {
    inner: Mutex<JoinSet<()>>,
}

impl TaskSet {
    /// Create a new, empty `TaskSet`.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(JoinSet::new()),
        }
    }

    /// Spawn a future onto the inner `JoinSet`, draining all completed task
    /// handles first so they don't accumulate indefinitely.
    ///
    /// The future is automatically instrumented with the current tracing span
    /// via [`.in_current_span()`](tracing::Instrument::in_current_span).
    pub fn spawn(&self, fut: impl Future<Output = ()> + Send + 'static) {
        let mut set = self.inner.lock().unwrap();
        // Drain all completed tasks before spawning a new one.
        while set.try_join_next().is_some() {}
        set.spawn(fut.in_current_span());
    }
}
