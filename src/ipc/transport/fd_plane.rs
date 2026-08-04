use std::{
    collections::{HashMap, VecDeque},
    future::{Future, IntoFuture},
    os::fd::OwnedFd,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use futures::ready;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot, watch};

use super::{DeliverFdsError, FdVec, QueueFdsError, TakeFdsError, WaitFdsError, driver::FdSender};
use crate::varint::{VARINT_MAX, VarInt};

// Bound descriptor ownership retained between sendmsg and the receiver ACK.
// The ACK round trip is local and only gates bridge setup, not stream I/O.
pub(super) const MAX_IN_FLIGHT_FD_DELIVERIES: usize = 32;
const MAX_PENDING_FD_CANCELLATIONS: usize = 1024;

#[derive(Debug)]
pub(crate) struct FdPlaneCore {
    next_id: AtomicU64,
    receivers: Mutex<ReceiverState>,
    deliveries: Mutex<DeliveryState>,
    delivery_permits: Arc<Semaphore>,
}

#[derive(Debug)]
struct ReceiverState {
    slots: HashMap<VarInt, oneshot::Sender<Result<FdVec, WaitFdsError>>>,
    closed: bool,
}

#[derive(Debug, Default)]
struct DeliveryState {
    entries: HashMap<VarInt, Arc<DeliveryEntry>>,
    pending_cancellations: VecDeque<VarInt>,
    closed: bool,
}

#[derive(Debug)]
struct DeliveryEntry {
    phase: watch::Sender<DeliveryPhase>,
    _phase_rx: watch::Receiver<DeliveryPhase>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeliveryPhase {
    Open,
    Sent,
    Acked,
    Cancelled,
}

impl FdPlaneCore {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            receivers: Mutex::new(ReceiverState {
                slots: HashMap::new(),
                closed: false,
            }),
            deliveries: Mutex::new(DeliveryState::default()),
            delivery_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_FD_DELIVERIES)),
        }
    }

    #[allow(deprecated)] // `try_update` is unavailable on the crate's MSRV.
    fn next_id(&self) -> Result<VarInt, WaitFdsError> {
        let id_raw =
            match self
                .next_id
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    let next = current.checked_add(1)?;
                    if next >= VARINT_MAX { None } else { Some(next) }
                }) {
                Ok(id_raw) => id_raw,
                Err(_) => return Err(WaitFdsError::IdExhausted),
            };

        match VarInt::from_u64(id_raw) {
            Ok(id) => Ok(id),
            Err(_) => Err(WaitFdsError::IdExhausted),
        }
    }

    fn reserve(
        &self,
        id: VarInt,
    ) -> Result<oneshot::Receiver<Result<FdVec, WaitFdsError>>, WaitFdsError> {
        let mut state = self.receivers.lock().expect("fd receiver state poisoned");
        if state.closed {
            return Err(WaitFdsError::Closed);
        }
        if state.slots.contains_key(&id) {
            return Err(WaitFdsError::AlreadyWaiting { id });
        }
        let (tx, rx) = oneshot::channel();
        state.slots.insert(id, tx);
        Ok(rx)
    }

    pub(crate) fn arrive_fds(&self, id: VarInt, fds: FdVec) {
        let mut state = self.receivers.lock().expect("fd receiver state poisoned");
        if state.closed {
            return;
        }
        if let Some(waiter) = state.slots.remove(&id) {
            let _ = waiter.send(Ok(fds));
        }
    }

    fn cancel_receiver(&self, id: VarInt) {
        let mut state = self.receivers.lock().expect("fd receiver state poisoned");
        state.slots.remove(&id);
    }

    pub(crate) fn mark_cancelled(&self, id: VarInt) {
        let entry = {
            let mut deliveries = self.deliveries.lock().expect("fd delivery state poisoned");
            if deliveries.closed {
                return;
            }
            if let Some(entry) = deliveries.entries.get(&id) {
                Some(entry.clone())
            } else if deliveries.pending_cancellations.len() >= MAX_PENDING_FD_CANCELLATIONS {
                // Evicting an old tombstone could revive a delayed RPC request.
                // Reject all delivery work rather than allowing that cancellation bypass.
                None
            } else {
                let (phase, _phase_rx) = watch::channel(DeliveryPhase::Cancelled);
                let entry = Arc::new(DeliveryEntry { phase, _phase_rx });
                deliveries.entries.insert(id, entry.clone());
                deliveries.pending_cancellations.push_back(id);
                Some(entry)
            }
        };

        let Some(entry) = entry else {
            self.close();
            return;
        };
        entry.phase.send_if_modified(|phase| match phase {
            DeliveryPhase::Open | DeliveryPhase::Sent => {
                *phase = DeliveryPhase::Cancelled;
                true
            }
            DeliveryPhase::Acked | DeliveryPhase::Cancelled => false,
        });
    }

    pub(crate) fn mark_acked(&self, id: VarInt) {
        let entry = {
            let deliveries = self.deliveries.lock().expect("fd delivery state poisoned");
            if deliveries.closed {
                return;
            }
            deliveries.entries.get(&id).cloned()
        };
        let Some(entry) = entry else { return };
        entry.phase.send_if_modified(|phase| match phase {
            DeliveryPhase::Open | DeliveryPhase::Sent => {
                *phase = DeliveryPhase::Acked;
                true
            }
            DeliveryPhase::Acked | DeliveryPhase::Cancelled => false,
        });
    }

    fn entry(&self, id: VarInt) -> Arc<DeliveryEntry> {
        let mut deliveries = self.deliveries.lock().expect("fd delivery state poisoned");
        if deliveries.closed {
            let (phase, _phase_rx) = watch::channel(DeliveryPhase::Cancelled);
            return Arc::new(DeliveryEntry { phase, _phase_rx });
        }
        if let Some(entry) = deliveries.entries.get(&id).cloned() {
            deliveries
                .pending_cancellations
                .retain(|pending| *pending != id);
            return entry;
        }

        let (phase, _phase_rx) = watch::channel(DeliveryPhase::Open);
        let entry = Arc::new(DeliveryEntry { phase, _phase_rx });
        deliveries.entries.insert(id, entry.clone());
        entry
    }

    fn remove_delivery(&self, id: VarInt) {
        let mut deliveries = self.deliveries.lock().expect("fd delivery state poisoned");
        deliveries.entries.remove(&id);
        deliveries
            .pending_cancellations
            .retain(|pending| *pending != id);
    }

    pub(crate) fn close(&self) {
        let mut receivers = self.receivers.lock().expect("fd receiver state poisoned");
        if receivers.closed {
            return;
        }
        receivers.closed = true;
        for (_, waiter) in receivers.slots.drain() {
            let _ = waiter.send(Err(WaitFdsError::Closed));
        }
        drop(receivers);

        let deliveries: Vec<_> = {
            let mut state = self.deliveries.lock().expect("fd delivery state poisoned");
            state.closed = true;
            state.pending_cancellations.clear();
            state.entries.drain().map(|(_, entry)| entry).collect()
        };
        for delivery in deliveries {
            let _ = delivery.phase.send(DeliveryPhase::Cancelled);
        }
        self.delivery_permits.close();
    }
}

#[derive(Clone, Debug)]
pub struct FdTransfer {
    sender: FdSender,
    plane: Arc<FdPlaneCore>,
}

impl FdTransfer {
    pub(crate) fn new(sender: FdSender, plane: Arc<FdPlaneCore>) -> Self {
        Self { sender, plane }
    }

    pub fn receive(&self) -> FdReceiver {
        let id = match self.plane.next_id() {
            Ok(id) => id,
            Err(error) => {
                return FdReceiver::ready(self.sender.clone(), VarInt::from_u32(0), error);
            }
        };
        match self.plane.reserve(id) {
            Ok(rx) => FdReceiver {
                id,
                sender: self.sender.clone(),
                plane: Arc::downgrade(&self.plane),
                rx: Some(rx),
                ready: None,
                active: true,
            },
            Err(error) => FdReceiver::ready(self.sender.clone(), id, error),
        }
    }

    pub fn delivery(&self, id: VarInt) -> FdDelivery {
        FdDelivery {
            id,
            sender: self.sender.clone(),
            plane: Arc::downgrade(&self.plane),
            entry: Some(self.plane.entry(id)),
            active: true,
        }
    }
}

#[derive(Debug)]
pub struct FdReceiver {
    id: VarInt,
    sender: FdSender,
    plane: Weak<FdPlaneCore>,
    rx: Option<oneshot::Receiver<Result<FdVec, WaitFdsError>>>,
    ready: Option<Result<FdVec, WaitFdsError>>,
    active: bool,
}

impl FdReceiver {
    fn ready(sender: FdSender, id: VarInt, error: WaitFdsError) -> Self {
        Self {
            id,
            sender,
            plane: Weak::new(),
            rx: None,
            ready: Some(Err(error)),
            active: false,
        }
    }

    pub fn id(&self) -> VarInt {
        self.id
    }

    fn disarm(&mut self) {
        self.active = false;
        self.rx = None;
    }
}

impl Drop for FdReceiver {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(plane) = self.plane.upgrade() {
            plane.cancel_receiver(self.id);
        }
        let _ = self.sender.cancel_fds(self.id);
        self.active = false;
    }
}

pub struct FdReceiverFuture {
    receiver: FdReceiver,
}

impl Future for FdReceiverFuture {
    type Output = Result<ReceivedFds, WaitFdsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(result) = self.receiver.ready.take() {
            self.receiver.disarm();
            return Poll::Ready(result.map(ReceivedFds::new));
        }

        let Some(rx) = self.receiver.rx.as_mut() else {
            self.receiver.disarm();
            return Poll::Ready(Err(WaitFdsError::ChannelClosed));
        };

        let fds = match ready!(Pin::new(rx).poll(cx)) {
            Ok(Ok(fds)) => fds,
            Ok(Err(error)) => {
                self.receiver.disarm();
                return Poll::Ready(Err(error));
            }
            Err(_) => {
                self.receiver.disarm();
                return Poll::Ready(Err(WaitFdsError::ChannelClosed));
            }
        };

        if let Err(source) = self.receiver.sender.ack_fds(self.receiver.id) {
            self.receiver.disarm();
            return Poll::Ready(Err(WaitFdsError::Ack { source }));
        }
        self.receiver.disarm();
        Poll::Ready(Ok(ReceivedFds::new(fds)))
    }
}

impl IntoFuture for FdReceiver {
    type Output = Result<ReceivedFds, WaitFdsError>;
    type IntoFuture = FdReceiverFuture;

    fn into_future(self) -> Self::IntoFuture {
        FdReceiverFuture { receiver: self }
    }
}

#[derive(Debug)]
pub struct ReceivedFds {
    fds: FdVec,
}

impl ReceivedFds {
    fn new(fds: FdVec) -> Self {
        Self { fds }
    }

    pub fn len(&self) -> usize {
        self.fds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }

    pub fn into_fds(self) -> FdVec {
        self.fds
    }

    pub fn into_one(self) -> Result<OwnedFd, TakeFdsError> {
        if self.fds.len() != 1 {
            return Err(TakeFdsError::Count {
                expected: 1,
                actual: self.fds.len(),
            });
        }
        Ok(self.fds.into_iter().next().expect("fd count checked"))
    }

    pub fn into_pair(self) -> Result<(OwnedFd, OwnedFd), TakeFdsError> {
        if self.fds.len() != 2 {
            return Err(TakeFdsError::Count {
                expected: 2,
                actual: self.fds.len(),
            });
        }
        let mut fds = self.fds.into_iter();
        let first = fds.next().expect("fd count checked");
        let second = fds.next().expect("fd count checked");
        Ok((first, second))
    }
}

#[derive(Debug)]
pub struct FdDelivery {
    id: VarInt,
    sender: FdSender,
    plane: Weak<FdPlaneCore>,
    entry: Option<Arc<DeliveryEntry>>,
    active: bool,
}

impl FdDelivery {
    pub fn id(&self) -> VarInt {
        self.id
    }

    pub async fn cancelled(&mut self) -> bool {
        let Some(entry) = &self.entry else {
            return true;
        };
        let mut phase = entry.phase.subscribe();
        loop {
            let current = *phase.borrow_and_update();
            match current {
                DeliveryPhase::Cancelled => return true,
                DeliveryPhase::Acked => return false,
                DeliveryPhase::Open | DeliveryPhase::Sent => {
                    if phase.changed().await.is_err() {
                        return true;
                    }
                }
            }
        }
    }

    pub fn is_cancelled(&self) -> bool {
        let Some(entry) = &self.entry else {
            return true;
        };
        *entry.phase.borrow() == DeliveryPhase::Cancelled
    }

    /// Reserve capacity for this delivery before allocating the descriptors.
    pub async fn reserve(self) -> Result<ReservedFdDelivery, DeliverFdsError> {
        let Some(entry) = self.entry.as_ref().cloned() else {
            return Err(DeliverFdsError::Cancelled);
        };
        let Some(plane) = self.plane.upgrade() else {
            return Err(DeliverFdsError::ChannelClosed);
        };
        let Ok(permit) = plane.delivery_permits.clone().acquire_owned().await else {
            return Err(DeliverFdsError::ChannelClosed);
        };

        let current = *entry.phase.borrow();
        match current {
            DeliveryPhase::Open => Ok(ReservedFdDelivery {
                delivery: self,
                _permit: permit,
            }),
            DeliveryPhase::Cancelled => Err(DeliverFdsError::Cancelled),
            DeliveryPhase::Sent | DeliveryPhase::Acked => Err(DeliverFdsError::UnexpectedAck),
        }
    }

    pub async fn deliver(self, fds: FdVec) -> Result<FdDelivered, DeliverFdsError> {
        self.reserve().await?.deliver(fds).await
    }
}

/// Capacity reserved for one FD delivery and its acknowledgement wait.
#[derive(Debug)]
pub struct ReservedFdDelivery {
    delivery: FdDelivery,
    _permit: OwnedSemaphorePermit,
}

impl ReservedFdDelivery {
    pub fn id(&self) -> VarInt {
        self.delivery.id()
    }

    pub async fn deliver(mut self, fds: FdVec) -> Result<FdDelivered, DeliverFdsError> {
        let Some(entry) = self.delivery.entry.as_ref().cloned() else {
            return Err(DeliverFdsError::Cancelled);
        };

        if !entry.phase.send_if_modified(|phase| {
            if *phase == DeliveryPhase::Open {
                *phase = DeliveryPhase::Sent;
                true
            } else {
                false
            }
        }) {
            return match *entry.phase.borrow() {
                DeliveryPhase::Cancelled => Err(DeliverFdsError::Cancelled),
                DeliveryPhase::Open | DeliveryPhase::Sent | DeliveryPhase::Acked => {
                    Err(DeliverFdsError::UnexpectedAck)
                }
            };
        }

        // Keep the original descriptors process-reachable until the receiver
        // confirms that SCM_RIGHTS externalization has completed.
        let _fds = self
            .delivery
            .sender
            .send_fds(self.delivery.id, fds)
            .map_err(|source| DeliverFdsError::Queue { source })?;

        let mut phase = entry.phase.subscribe();
        loop {
            let current = *phase.borrow_and_update();
            match current {
                DeliveryPhase::Acked => {
                    self.delivery.active = false;
                    if let Some(plane) = self.delivery.plane.upgrade() {
                        plane.remove_delivery(self.delivery.id);
                    }
                    return Ok(FdDelivered {
                        id: self.delivery.id,
                    });
                }
                DeliveryPhase::Cancelled => return Err(DeliverFdsError::Cancelled),
                DeliveryPhase::Open | DeliveryPhase::Sent => {
                    if phase.changed().await.is_err() {
                        return Err(DeliverFdsError::ChannelClosed);
                    }
                }
            }
        }
    }
}

impl Drop for FdDelivery {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(plane) = self.plane.upgrade() {
            plane.remove_delivery(self.id);
        }
    }
}

#[derive(Debug)]
pub struct FdDelivered {
    id: VarInt,
}

impl FdDelivered {
    pub fn id(&self) -> VarInt {
        self.id
    }
}

impl From<QueueFdsError> for DeliverFdsError {
    fn from(source: QueueFdsError) -> Self {
        Self::Queue { source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmatched_cancellation_overflow_closes_fd_plane() {
        let plane = FdPlaneCore::new();
        let active = plane.entry(VarInt::from_u32(2_000));

        for id in 0..MAX_PENDING_FD_CANCELLATIONS {
            plane.mark_cancelled(VarInt::try_from(id).expect("test id fits varint"));
        }
        plane.mark_cancelled(
            VarInt::try_from(MAX_PENDING_FD_CANCELLATIONS).expect("test id fits varint"),
        );

        let deliveries = plane.deliveries.lock().expect("fd delivery state poisoned");
        assert!(deliveries.closed);
        assert!(deliveries.pending_cancellations.is_empty());
        assert!(deliveries.entries.is_empty());
        drop(deliveries);
        assert_eq!(*active.phase.borrow(), DeliveryPhase::Cancelled);
        assert!(plane.delivery_permits.is_closed());
        assert!(matches!(
            plane.reserve(VarInt::from_u32(3_000)),
            Err(WaitFdsError::Closed)
        ));

        let late = plane.entry(VarInt::from_u32(4_000));
        assert_eq!(*late.phase.borrow(), DeliveryPhase::Cancelled);
    }

    #[test]
    fn creating_delivery_consumes_pending_cancellation_tombstone() {
        let plane = FdPlaneCore::new();
        let id = VarInt::from_u32(17);
        plane.mark_cancelled(id);

        let entry = plane.entry(id);
        assert_eq!(*entry.phase.borrow(), DeliveryPhase::Cancelled);

        let deliveries = plane.deliveries.lock().expect("fd delivery state poisoned");
        assert!(deliveries.pending_cancellations.is_empty());
        assert!(deliveries.entries.contains_key(&id));
    }
}
