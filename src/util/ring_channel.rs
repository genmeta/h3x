use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll, ready},
};

use futures::Stream;
use tokio::sync::{Notify, futures::OwnedNotified};

pub struct RingChannel<T> {
    ring: Arc<SyncMutex<VecDeque<T>>>,
    notify: Arc<Notify>,
}

impl<T> Clone for RingChannel<T> {
    fn clone(&self) -> Self {
        Self {
            ring: self.ring.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<T> RingChannel<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            ring: Arc::new(SyncMutex::new(VecDeque::with_capacity(capacity))),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn capacity(&self) -> usize {
        self.ring.lock().expect("lock is not poisoned").capacity()
    }

    pub fn send(&self, item: T) -> Option<T> {
        let mut overflow = None;
        {
            let mut guard = self.ring.lock().expect("lock is not poisoned");
            if guard.len() == guard.capacity() {
                overflow = guard.pop_front();
            }
            guard.push_back(item);
        }
        self.notify.notify_one();
        overflow
    }

    pub fn receive(&self) -> Receiver<T> {
        Receiver {
            notified: self.notify.clone().notified_owned(),
            channel: self.clone(),
        }
    }
}

pin_project_lite::pin_project! {
    pub struct Receiver<T> {
        #[pin]
        notified: OwnedNotified,
        channel: RingChannel<T>,
    }
}

impl<T> Future for Receiver<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut project = self.project();

        loop {
            project.notified.as_mut().enable();

            match project.channel.ring.lock().expect("lock is not poisoned").pop_front() {
                Some(item) => return Poll::Ready(item),
                None => ready!(project.notified.as_mut().poll(cx)),
            };

            let notify = project.channel.notify.clone();
            project.notified.set(notify.notified_owned());
        }
    }
}

impl<T> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll(cx).map(Some)
    }
}
