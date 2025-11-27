use std::{
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll, ready},
};

use tokio::sync::{Notify, futures::OwnedNotified};

pub struct SetOnce<T> {
    value: Arc<SyncMutex<Option<T>>>,
    notify: Arc<Notify>,
}

impl<T> SetOnce<T> {
    pub fn new() -> Self {
        Self {
            value: Arc::new(SyncMutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        self.set_with(|| value).map_err(|f| f())
    }

    pub fn set_with<F: FnOnce() -> T>(&self, f: F) -> Result<(), F> {
        let mut guard = self.value.lock().unwrap();
        if guard.is_some() {
            return Err(f);
        }
        *guard = Some(f());
        self.notify.notify_waiters();
        drop(guard);
        Ok(())
    }

    pub fn peek(&self) -> Option<T>
    where
        T: Clone,
    {
        let guard = self.value.lock().unwrap();
        guard.clone()
    }

    pub fn get(&self) -> Get<T> {
        Get {
            notified: self.notify.clone().notified_owned(),
            value: self.value.clone(),
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Get<T> {
        #[pin]
        notified: OwnedNotified,
        value: Arc<SyncMutex<Option<T>>>,
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
