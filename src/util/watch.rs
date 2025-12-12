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
    value: Arc<SyncMutex<Option<T>>>,
    notify: Arc<Notify>,
}

pub struct Value<'w, T> {
    guard: MutexGuard<'w, Option<T>>,
    notify: Arc<Notify>,
}

impl<'w, T> Value<'w, T> {
    pub fn set(&mut self, value: T) {
        self.replace(value);
    }

    pub fn get(&self) -> Option<&T> {
        self.guard.as_ref()
    }

    pub fn replace(&mut self, value: T) -> Option<T> {
        let old = self.guard.replace(value);
        self.notify.notify_waiters();
        old
    }
}

impl<T> Watch<T> {
    pub fn new() -> Self {
        Self {
            value: Arc::new(SyncMutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn with(value: T) -> Self {
        Self {
            value: Arc::new(SyncMutex::new(Some(value))),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn lock(&self) -> Value<'_, T> {
        Value {
            guard: self.value.lock().unwrap(),
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
        let guard = self.value.lock().unwrap();
        guard.clone()
    }

    pub fn watch(&self) -> Watcher<T> {
        Watcher {
            notified: self.notify.clone().notified_owned(),
            value: self.value.clone(),
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Get<T> {
        #[pin]
        notified: OwnedNotified,
        value: Arc<SyncMutex<Option<T>>>
    }
}

impl<T: Clone> Future for Get<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let project = self.project();
        ready!(project.notified.poll(cx));
        Poll::Ready(project.value.lock().unwrap().clone())
    }
}

pin_project_lite::pin_project! {
    pub struct Watcher<T> {
        #[pin]
        notified: OwnedNotified,
        value: Arc<SyncMutex<Option<T>>>
    }
}

impl<T: Clone> Stream for Watcher<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let project = self.project();
        ready!(project.notified.poll(cx));
        Poll::Ready(project.value.lock().unwrap().clone())
    }
}
