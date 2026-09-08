use std::{
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::{
    sync::{Mutex as AsyncMutex, watch},
    task::JoinSet,
};

use crate::Error;

/// Runtime work is joined independently of protocol connection completion.
pub(super) struct Tasks {
    stopping: watch::Sender<bool>,
    running: Mutex<JoinSet<()>>,
    joining: AsyncMutex<()>,
    failed: AtomicBool,
}
impl Default for Tasks {
    fn default() -> Self {
        Self {
            stopping: watch::channel(false).0,
            running: Mutex::new(JoinSet::new()),
            joining: AsyncMutex::new(()),
            failed: AtomicBool::new(false),
        }
    }
}
impl Tasks {
    pub(super) fn is_stopping(&self) -> bool {
        *self.stopping.borrow()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }

    pub(super) fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), Error> {
        let mut running = self.running.lock().unwrap();
        if self.is_stopping() {
            return Err(Error::Draining);
        }
        while let Some(result) = running.try_join_next() {
            if result.is_err() {
                self.failed.store(true, Ordering::Relaxed);
            }
        }
        running.spawn(task);
        Ok(())
    }

    pub(super) async fn shutdown(&self) -> Result<(), Error> {
        {
            let _running = self.running.lock().unwrap();
            self.stopping.send_replace(true);
        }
        // JoinSet has one polling waker; serialize concurrent shutdown waiters.
        let _joining = self.joining.lock().await;
        while let Some(result) =
            futures::future::poll_fn(|cx| self.running.lock().unwrap().poll_join_next(cx)).await
        {
            if result.is_err() {
                self.failed.store(true, Ordering::Relaxed);
            }
        }
        if self.failed.load(Ordering::Relaxed) {
            Err(Error::OwnerStopped)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    #[tokio::test]
    async fn shutdown_joins_cleanup_and_survives_cancelled_and_concurrent_waiters() {
        let tasks = Arc::new(Tasks::default());
        let mut stopping = tasks.subscribe();
        let (cleanup, wait) = tokio::sync::oneshot::channel();
        let (observed, ready) = tokio::sync::oneshot::channel();
        tasks
            .spawn(async move {
                stopping.wait_for(|value| *value).await.unwrap();
                observed.send(()).unwrap();
                wait.await.unwrap();
            })
            .unwrap();
        let first = tokio::spawn({
            let tasks = tasks.clone();
            async move { tasks.shutdown().await }
        });
        ready.await.unwrap();
        assert!(!first.is_finished());
        assert!(matches!(tasks.spawn(async {}), Err(Error::Draining)));
        first.abort();
        let _ = first.await;
        cleanup.send(()).unwrap();
        let (a, b) = tokio::join!(tasks.shutdown(), tasks.shutdown());
        a.unwrap();
        b.unwrap();
        assert!(tasks.running.lock().unwrap().is_empty());
    }
}
