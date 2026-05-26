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

            match project
                .channel
                .ring
                .lock()
                .expect("lock is not poisoned")
                .pop_front()
            {
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;
    use tracing::Instrument;

    use super::*;

    #[test]
    fn ring_channel_capacity_is_retained() {
        let channel: RingChannel<i32> = RingChannel::new(7);
        assert_eq!(channel.capacity(), 7);
    }

    #[tokio::test]
    async fn ring_channel_send_and_receive_fifo_order() {
        let channel: RingChannel<i32> = RingChannel::new(2);
        channel.send(1);
        channel.send(2);

        let first = timeout(Duration::from_millis(50), channel.receive())
            .await
            .unwrap();
        let second = timeout(Duration::from_millis(50), channel.receive())
            .await
            .unwrap();

        assert_eq!(first, 1);
        assert_eq!(second, 2);
    }

    #[tokio::test]
    async fn ring_channel_send_returns_overflow_item_when_full() {
        let channel: RingChannel<&'static str> = RingChannel::new(1);
        assert_eq!(channel.send("first"), None);
        assert_eq!(channel.send("second"), Some("first"));

        let value = timeout(Duration::from_millis(50), channel.receive())
            .await
            .unwrap();
        assert_eq!(value, "second");
    }

    #[tokio::test]
    async fn ring_channel_clone_shares_ring_storage_with_send_receiver() {
        let channel: RingChannel<i32> = RingChannel::new(4);
        let sender = channel.clone();

        sender.send(13);

        let value = timeout(Duration::from_millis(50), channel.receive())
            .await
            .unwrap();
        assert_eq!(value, 13);
    }

    #[tokio::test]
    async fn ring_channel_receiver_waits_for_send_without_spin() {
        let channel: RingChannel<i32> = RingChannel::new(4);
        let receiver = channel.receive();

        let receive = tokio::spawn(
            async move { timeout(Duration::from_millis(100), receiver).await.unwrap() }
                .in_current_span(),
        );

        tokio::time::sleep(Duration::from_millis(10)).await;
        channel.send(99);

        let value = receive.await.unwrap();
        assert_eq!(value, 99);
    }

    #[tokio::test]
    async fn ring_channel_receive_times_out_without_send() {
        let receiver: Receiver<i32> = RingChannel::new(2).receive();

        let result = timeout(Duration::from_millis(20), receiver).await;
        assert!(result.is_err());
    }
}
