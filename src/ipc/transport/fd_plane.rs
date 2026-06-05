use std::{
    collections::HashMap,
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
use tokio::sync::oneshot;

use super::{DeliverFdsError, FdVec, QueueFdsError, TakeFdsError, WaitFdsError, driver::FdSender};
use crate::varint::{VARINT_MAX, VarInt};

#[derive(Debug)]
pub(crate) struct FdPlaneCore {
    next_id: AtomicU64,
    receivers: Mutex<ReceiverState>,
}

#[derive(Debug)]
struct ReceiverState {
    slots: HashMap<VarInt, oneshot::Sender<Result<FdVec, WaitFdsError>>>,
    closed: bool,
}

impl FdPlaneCore {
    pub(crate) fn new() -> Self {
        Self {
            next_id: AtomicU64::new(0),
            receivers: Mutex::new(ReceiverState {
                slots: HashMap::new(),
                closed: false,
            }),
        }
    }

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

    fn remove_receiver(&self, id: VarInt) {
        let mut state = self.receivers.lock().expect("fd receiver state poisoned");
        state.slots.remove(&id);
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
                return FdReceiver::ready(VarInt::from_u32(0), error);
            }
        };
        match self.plane.reserve(id) {
            Ok(rx) => FdReceiver {
                id,
                plane: Arc::downgrade(&self.plane),
                rx: Some(rx),
                ready: None,
                active: true,
            },
            Err(error) => FdReceiver::ready(id, error),
        }
    }

    pub fn delivery(&self, id: VarInt) -> FdDelivery {
        FdDelivery {
            id,
            sender: self.sender.clone(),
        }
    }
}

#[derive(Debug)]
pub struct FdReceiver {
    id: VarInt,
    plane: Weak<FdPlaneCore>,
    rx: Option<oneshot::Receiver<Result<FdVec, WaitFdsError>>>,
    ready: Option<Result<FdVec, WaitFdsError>>,
    active: bool,
}

impl FdReceiver {
    fn ready(id: VarInt, error: WaitFdsError) -> Self {
        Self {
            id,
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
            plane.remove_receiver(self.id);
        }
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
}

impl FdDelivery {
    pub fn id(&self) -> VarInt {
        self.id
    }

    pub async fn deliver(self, fds: FdVec) -> Result<FdDelivered, DeliverFdsError> {
        if let Err(source) = self.sender.send_fds(self.id, fds) {
            return Err(DeliverFdsError::Queue { source });
        }
        Ok(FdDelivered { id: self.id })
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
