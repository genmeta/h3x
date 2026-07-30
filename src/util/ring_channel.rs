use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex as SyncMutex},
    task::{Context, Poll, ready},
};

use futures::Stream;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, futures::OwnedNotified};

pub struct RingChannel<T> {
    ring: Arc<SyncMutex<VecDeque<(T, OwnedSemaphorePermit)>>>,
    notify: Arc<Notify>,
    slots: Arc<Semaphore>,
    capacity: usize,
}

impl<T> Clone for RingChannel<T> {
    fn clone(&self) -> Self {
        Self {
            ring: self.ring.clone(),
            notify: self.notify.clone(),
            slots: self.slots.clone(),
            capacity: self.capacity,
        }
    }
}

impl<T> RingChannel<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "ring channel capacity must be greater than zero"
        );
        Self {
            ring: Arc::new(SyncMutex::new(VecDeque::with_capacity(capacity))),
            notify: Arc::new(Notify::new()),
            slots: Arc::new(Semaphore::new(capacity)),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Enqueue an item, waiting until the receiver releases a capacity slot.
    pub async fn send(&self, item: T) {
        let permit = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("ring channel capacity semaphore is never closed");
        {
            let mut guard = self.ring.lock().expect("lock is not poisoned");
            guard.push_back((item, permit));
        }
        self.notify.notify_one();
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
                Some((item, _permit)) => return Poll::Ready(item),
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

    use futures::{FutureExt, StreamExt};
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
        channel.send(1).await;
        channel.send(2).await;

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
    async fn ring_channel_send_waits_for_capacity_without_evicting() {
        let channel: RingChannel<&'static str> = RingChannel::new(1);
        channel.send("first").await;

        let sender = channel.clone();
        let blocked_send = tokio::spawn(async move { sender.send("second").await });
        tokio::task::yield_now().await;
        assert!(!blocked_send.is_finished());

        let first = timeout(Duration::from_millis(50), channel.receive())
            .await
            .unwrap();
        assert_eq!(first, "first");

        timeout(Duration::from_millis(50), blocked_send)
            .await
            .expect("send should resume after capacity is released")
            .expect("send task should not panic");
        assert_eq!(channel.receive().await, "second");
    }

    #[tokio::test]
    async fn ring_channel_clone_shares_ring_storage_with_send_receiver() {
        let channel: RingChannel<i32> = RingChannel::new(4);
        let sender = channel.clone();

        sender.send(13).await;

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
        channel.send(99).await;

        let value = receive.await.unwrap();
        assert_eq!(value, 99);
    }

    #[tokio::test]
    async fn ring_channel_receive_times_out_without_send() {
        let receiver: Receiver<i32> = RingChannel::new(2).receive();

        let result = timeout(Duration::from_millis(20), receiver).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ring_channel_preserves_all_items_across_backpressure() {
        let channel: RingChannel<i32> = RingChannel::new(2);

        channel.send(1).await;
        channel.send(2).await;

        let sender = channel.clone();
        let blocked_send = tokio::spawn(async move { sender.send(3).await });
        tokio::task::yield_now().await;
        assert!(!blocked_send.is_finished());

        let receiver = channel.receive();
        let mut receiver = std::pin::pin!(receiver);
        assert_eq!(receiver.as_mut().next().await, Some(1));
        blocked_send.await.expect("send task should not panic");
        assert_eq!(receiver.as_mut().next().await, Some(2));
        assert_eq!(receiver.as_mut().next().await, Some(3));
        assert_eq!(receiver.as_mut().next().now_or_never(), None);
    }

    #[tokio::test]
    async fn cancelled_blocked_send_releases_its_queue_position() {
        let channel: RingChannel<i32> = RingChannel::new(1);
        channel.send(1).await;

        let sender = channel.clone();
        let blocked_send = tokio::spawn(async move { sender.send(2).await });
        tokio::task::yield_now().await;
        assert!(!blocked_send.is_finished());
        blocked_send.abort();
        assert!(
            blocked_send
                .await
                .expect_err("send should be cancelled")
                .is_cancelled()
        );

        assert_eq!(channel.receive().await, 1);
        timeout(Duration::from_millis(50), channel.send(3))
            .await
            .expect("cancelled send must not leak capacity");
        assert_eq!(channel.receive().await, 3);
    }

    #[tokio::test]
    async fn pending_receiver_recovers_from_consumed_notification() {
        let channel: RingChannel<i32> = RingChannel::new(1);
        let pending_receiver = channel.receive();
        assert_eq!(pending_receiver.now_or_never(), None);

        let waiting_receiver = channel.receive();
        let mut waiting_receiver = std::pin::pin!(waiting_receiver);
        assert_eq!(waiting_receiver.as_mut().next().now_or_never(), None);

        channel.send(1).await;
        let consumed_by_other_receiver = channel.receive().await;
        assert_eq!(consumed_by_other_receiver, 1);

        channel.send(2).await;
        assert_eq!(waiting_receiver.as_mut().next().await, Some(2));
    }
}
