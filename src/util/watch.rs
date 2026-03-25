use std::{
    fmt::Debug,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex, MutexGuard},
    task::{Context, Poll, ready},
};

use futures::Stream;
use tokio::sync::{Notify, futures::OwnedNotified};

#[derive(Debug, Clone)]
pub struct Watch<T> {
    state: Arc<SyncMutex<WatchState<T>>>,
    notify: Arc<Notify>,
}

#[derive(Debug)]
struct WatchState<T> {
    value: Option<T>,
    version: u64,
}

pub struct Value<'w, T> {
    guard: MutexGuard<'w, WatchState<T>>,
    notify: Arc<Notify>,
}

impl<'w, T> Value<'w, T> {
    pub fn set(&mut self, value: T) {
        self.replace(value);
    }

    pub fn get(&self) -> Option<&T> {
        self.guard.value.as_ref()
    }

    pub fn replace(&mut self, value: T) -> Option<T> {
        let old = self.guard.value.replace(value);
        self.guard.version = self.guard.version.wrapping_add(1);
        self.notify.notify_waiters();
        old
    }
}

impl<T> Watch<T> {
    pub fn new() -> Self {
        Self {
            state: Arc::new(SyncMutex::new(WatchState {
                value: None,
                version: 0,
            })),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn lock(&self) -> Value<'_, T> {
        Value {
            guard: self.state.lock().expect("lock is not poisoned"),
            notify: self.notify.clone(),
        }
    }

    pub fn set(&self, value: T) -> Option<T> {
        self.lock().replace(value)
    }

    pub fn peek(&self) -> Option<T>
    where
        T: Clone,
    {
        let guard = self.state.lock().expect("lock is not poisoned");
        guard.value.clone()
    }

    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            notified: self.notify.clone().notified_owned(),
            notify: self.notify.clone(),
            state: self.state.clone(),
            seen_version: 0,
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Get<T> {
        #[pin]
        notified: OwnedNotified,
        state: Arc<SyncMutex<WatchState<T>>>
    }
}

impl<T: Clone> Future for Get<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        ready!(project.notified.poll(cx));
        Poll::Ready(
            project
                .state
                .lock()
                .expect("lock is not poisoned")
                .value
                .clone(),
        )
    }
}

pin_project_lite::pin_project! {
    pub struct Watcher<T> {
        #[pin]
        notified: OwnedNotified,
        notify: Arc<Notify>,
        state: Arc<SyncMutex<WatchState<T>>>,
        seen_version: u64,
    }
}

impl<T: Clone> Stream for Watcher<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut project = self.project();

        loop {
            {
                let state = project.state.lock().expect("lock is not poisoned");
                if state.version > *project.seen_version {
                    *project.seen_version = state.version;
                    if let Some(value) = state.value.clone() {
                        return Poll::Ready(Some(value));
                    }
                }
            }

            ready!(project.notified.as_mut().poll(cx));
            project
                .notified
                .set(project.notify.clone().notified_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::Watch;

    #[tokio::test]
    async fn set_before_watch_observes_current_value_immediately() {
        let watch = Watch::new();
        watch.set(7_u32);

        let watcher = watch.watch();
        let mut watcher = std::pin::pin!(watcher);
        let value = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            watcher.as_mut().next(),
        )
        .await
        .expect("watcher should immediately observe current value")
        .expect("watch stream should yield a value");

        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn watch_before_set_observes_future_update() {
        let watch = Watch::new();
        let watcher = watch.watch();
        let mut watcher = std::pin::pin!(watcher);

        let watch_setter = watch.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            watch_setter.set(11_u32);
        });

        let value = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            watcher.as_mut().next(),
        )
        .await
        .expect("watcher should observe a future update")
        .expect("watch stream should yield a value");

        assert_eq!(value, 11);
    }

    #[tokio::test]
    async fn rapid_updates_can_coalesce_to_latest_value() {
        let watch = Watch::new();
        let watcher = watch.watch();
        let mut watcher = std::pin::pin!(watcher);

        watch.set(1_u32);
        watch.set(2_u32);
        watch.set(3_u32);

        let value = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            watcher.as_mut().next(),
        )
        .await
        .expect("watcher should observe an update")
        .expect("watch stream should yield a value");

        assert_eq!(value, 3);
    }
}
