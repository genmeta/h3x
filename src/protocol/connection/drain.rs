//! Tracks live work without knowing whether it is opening, reading, or writing.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Drain {
    pub(super) active: AtomicUsize,
    finished: Notify,
}

pub(in crate::protocol) struct Guard(Arc<Drain>);
impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.finished.notify_one();
        }
    }
}

impl Drain {
    // Admission is checked under the GOAWAY lock before acquiring a guard.
    // Transfers acquire the next guard before releasing the previous one.
    pub(in crate::protocol) fn guard(self: &Arc<Self>) -> Guard {
        self.active.fetch_add(1, Ordering::Relaxed);
        Guard(self.clone())
    }

    pub(super) async fn wait(&self) {
        // A single shutdown waiter; notify_one retains a wake until the next poll.
        while self.active.load(Ordering::Acquire) != 0 {
            self.finished.notified().await;
        }
    }
}
