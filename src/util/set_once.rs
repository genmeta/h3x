use std::{
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll, ready},
};

use tokio::sync::{Notify, futures::OwnedNotified};

#[derive(Debug)]
pub struct SetOnce<T> {
    value: Arc<SyncMutex<Option<T>>>,
    notify: Arc<Notify>,
}

impl<T> Clone for SetOnce<T> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<T> Default for SetOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SetOnce<T> {
    pub fn new() -> Self {
        Self {
            value: Arc::new(SyncMutex::new(None)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Returns `true` if the value has been set.
    pub fn is_set(&self) -> bool {
        self.value.lock().expect("lock is not poisoned").is_some()
    }

    pub fn set(&self, value: T) -> Result<(), T> {
        self.set_with(|| value).map_err(|f| f())
    }

    pub fn set_with<F: FnOnce() -> T>(&self, f: F) -> Result<(), F> {
        let mut guard = self.value.lock().expect("lock is not poisoned");
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
        let guard = self.value.lock().expect("lock is not poisoned");
        guard.clone()
    }

    pub fn get(&self) -> Get<T> {
        Get {
            notified: self.notify.clone().notified_owned(),
            set_once: self.clone(),
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Get<T> {
        #[pin]
        notified: OwnedNotified,
        set_once: SetOnce<T>,
    }
}

impl<T: Clone> Future for Get<T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut project = self.project();
        loop {
            project.notified.as_mut().enable();

            match project.set_once.peek() {
                Some(value) => return Poll::Ready(Some(value)),
                None => ready!(project.notified.as_mut().poll(cx)),
            }

            let notify = project.set_once.notify.clone();
            project.notified.set(notify.notified_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use futures::FutureExt;

    use super::*;

    #[test]
    fn default_starts_unset_and_set_stores_value() {
        let value = SetOnce::default();

        assert!(!value.is_set());
        assert_eq!(value.peek(), None);

        assert_eq!(value.set(7), Ok(()));
        assert!(value.is_set());
        assert_eq!(value.peek(), Some(7));
        assert_eq!(value.get().now_or_never(), Some(Some(7)));
    }

    #[test]
    fn second_set_returns_rejected_value_without_replacing_existing() {
        let value = SetOnce::new();

        assert_eq!(value.set("first"), Ok(()));
        assert_eq!(value.set("second"), Err("second"));
        assert_eq!(value.peek(), Some("first"));
    }

    #[test]
    fn set_with_does_not_call_factory_after_value_is_set() {
        let value = SetOnce::new();
        assert_eq!(value.set(1), Ok(()));

        let called = Cell::new(false);
        let factory = || {
            called.set(true);
            2
        };

        let rejected = value
            .set_with(factory)
            .expect_err("factory should be returned when already set");
        assert!(!called.get());
        assert_eq!(rejected(), 2);
        assert!(called.get());
        assert_eq!(value.peek(), Some(1));
    }

    #[tokio::test]
    async fn pending_get_observes_value_set_from_clone() {
        let value = SetOnce::new();
        assert_eq!(value.get().now_or_never(), None);

        let setter = value.clone();
        let get = value.get();

        assert_eq!(setter.set(11), Ok(()));
        assert_eq!(get.await, Some(11));
    }

    #[test]
    fn get_survives_notification_before_value_is_set() {
        let value = SetOnce::new();
        let mut get = Box::pin(value.get());

        assert_eq!(get.as_mut().now_or_never(), None);
        value.notify.notify_waiters();
        assert_eq!(get.as_mut().now_or_never(), None);

        assert_eq!(value.set(13), Ok(()));
        assert_eq!(get.now_or_never(), Some(Some(13)));
    }
}
