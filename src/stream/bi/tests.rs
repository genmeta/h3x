use std::sync::atomic::AtomicUsize;

use futures::task::{ArcWake, waker};
use qbase::varint::VarInt;

use super::*;
use crate::{ErrorCode, Settings};

#[derive(Clone, Default)]
struct Io(Arc<Mutex<Vec<u64>>>);

impl StopSending for Io {
    fn stop(&mut self, code: u64) {
        self.0.lock().unwrap().push(code);
    }
}

impl CancelStream for Io {
    fn cancel(&mut self, code: u64) {
        self.0.lock().unwrap().push(code);
    }
}

impl Io {
    fn codes(&self) -> Vec<u64> {
        self.0.lock().unwrap().clone()
    }
}

type Streams = ArcBiStreams<Io, Io>;

fn insert(streams: &Streams, id: u64) -> (H3ReadStream<Io>, H3WriteStream<Io>, Io, Io) {
    let recv = Io::default();
    let send = Io::default();
    let (read, write) = streams.insert(
        &mut streams.lock().unwrap(),
        id,
        recv.clone(),
        send.clone(),
        qpack(),
    );
    (read, write, recv, send)
}

fn sid(id: u64) -> StreamId {
    StreamId::from(VarInt::try_from(id).unwrap())
}

fn qpack() -> ArcQpack {
    let qpack = ArcQpack::new(&Settings::default()).unwrap();
    qpack
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .decoder
        .on_instruction(|_| Ok(()));
    qpack
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl ArcWake for WakeCount {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn empty_registry_drains_only_after_local_goaway_and_wakes_waiter() {
    let streams = Streams::new(Role::Server);
    let mut drain = streams.drain();
    let count = Arc::new(WakeCount::default());
    let waker = waker(count.clone());
    let mut cx = Context::from_waker(&waker);
    streams.lock().unwrap().try_wake();
    assert!(Pin::new(&mut drain).poll(&mut cx).is_pending());
    streams.lock().unwrap().goaway(&qpack()).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(Pin::new(&mut drain).poll(&mut cx).is_ready());
    assert!(Pin::new(&mut streams.drain()).poll(&mut cx).is_ready());
}

#[test]
fn cancelling_either_direction_cancels_both_and_completes_drain() {
    for read_first in [true, false] {
        let streams = Streams::new(Role::Server);
        streams.lock().unwrap().accept(sid(0)).unwrap();
        let (mut read, write, recv, send) = insert(&streams, 0);
        let mut drain = streams.drain();
        let count = Arc::new(WakeCount::default());
        let waker = waker(count.clone());
        let mut cx = Context::from_waker(&waker);
        streams.lock().unwrap().goaway(&qpack()).unwrap();
        assert!(Pin::new(&mut drain).poll(&mut cx).is_pending());
        if read_first {
            read.stop(42);
        } else {
            (&write).cancel(42);
        }
        {
            let guard = streams.lock().unwrap();
            assert!(guard.reads.is_empty());
            assert!(guard.writes.is_empty());
        }
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(Pin::new(&mut drain).poll(&mut cx).is_ready());
        drop((read, write));
        assert_eq!(recv.codes(), [42]);
        assert_eq!(send.codes(), [42]);
    }
}

#[test]
fn stopping_read_with_no_error_preserves_write_direction() {
    let streams = Streams::new(Role::Server);
    streams.lock().unwrap().accept(sid(0)).unwrap();
    let (mut read, write, recv, send) = insert(&streams, 0);

    read.stop(ErrorCode::NoError.as_u64());

    {
        let guard = streams.lock().unwrap();
        assert!(guard.reads.is_empty());
        assert!(guard.writes.contains_key(&0));
    }
    assert_eq!(recv.codes(), [ErrorCode::NoError.as_u64()]);
    assert!(send.codes().is_empty());

    drop(write);
    assert!(streams.lock().unwrap().writes.is_empty());
}

#[test]
fn cancelling_write_with_no_error_preserves_read_direction() {
    let streams = Streams::new(Role::Client);
    let (read, write, recv, send) = insert(&streams, 0);

    (&write).cancel(ErrorCode::NoError.as_u64());

    {
        let guard = streams.lock().unwrap();
        assert!(guard.reads.contains_key(&0));
        assert!(guard.writes.is_empty());
    }
    assert!(recv.codes().is_empty());
    assert_eq!(send.codes(), [ErrorCode::NoError.as_u64()]);

    drop(read);
    assert!(streams.lock().unwrap().reads.is_empty());
}

#[test]
fn dropping_application_handles_only_unregisters_each_direction() {
    let streams = Streams::new(Role::Client);
    let clone = streams.clone();
    let (read, write, recv, send) = insert(&streams, 0);
    assert_eq!(read.stream_id(), 0);
    assert_eq!(write.stream_id(), 0);
    drop(read);
    assert!(clone.lock().unwrap().reads.is_empty());
    assert_eq!(clone.lock().unwrap().writes.len(), 1);
    drop(write);
    assert!(clone.lock().unwrap().writes.is_empty());
    assert!(recv.codes().is_empty());
    assert!(send.codes().is_empty());
}

#[test]
fn rejection_is_inclusive_directional_sorted_and_deduplicated() {
    let streams = Streams::new(Role::Client);
    let handles: Vec<_> = [12, 1, 0, 8, 4, 9]
        .into_iter()
        .map(|id| (id, insert(&streams, id)))
        .collect();
    let mut guard = streams.lock().unwrap();
    guard.reject_from(4, &qpack()).unwrap();
    guard.reject_from(4, &qpack()).unwrap();
    for (id, (_, _, recv, send)) in &handles {
        let rejected = *id >= 4 && id % 4 == 0;
        assert_eq!(guard.reads.contains_key(id), !rejected);
        assert_eq!(guard.writes.contains_key(id), !rejected);
        let expected = if rejected {
            vec![ErrorCode::RequestRejected.as_u64()]
        } else {
            vec![]
        };
        assert_eq!(recv.codes(), expected);
        assert_eq!(send.codes(), expected);
    }
    drop(guard);
}

#[test]
fn local_goaway_freezes_acceptance_and_preserves_admitted_streams() {
    for (role, first) in [(Role::Server, 0), (Role::Client, 1)] {
        let streams = Streams::new(role);
        let _admitted = insert(&streams, first + 4);
        let _rejected = insert(&streams, first + 8);
        let mut guard = streams.lock().unwrap();
        guard.accept(sid(first + 4)).unwrap();
        guard.accept(sid(first)).unwrap();
        let mut notification = Box::pin(guard.local_goaway());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(notification.as_mut().poll(&mut cx).is_pending());
        guard.goaway(&qpack()).unwrap();
        assert_eq!(
            notification.as_mut().poll(&mut cx),
            Poll::Ready(sid(first + 8))
        );
        assert_eq!(
            guard.local_not_goway().unwrap_err().code,
            ErrorCode::RequestRejected
        );
        assert!(guard.accept(sid(first)).is_err());
        assert!(guard.remote_no_goway().is_ok());
        assert!(guard.reads.contains_key(&(first + 4)));
        assert!(!guard.reads.contains_key(&(first + 8)));
        guard.goaway(&qpack()).unwrap();
        let mut late = Box::pin(guard.local_goaway());
        assert_eq!(late.as_mut().poll(&mut cx), Poll::Ready(sid(first + 8)));
    }
}

#[test]
fn remote_goaway_blocks_opening_without_starting_local_drain() {
    let streams = Streams::new(Role::Client);
    let _accepted = insert(&streams, 0);
    let _rejected = insert(&streams, 4);
    let mut drain = streams.drain();
    let mut guard = streams.lock().unwrap();
    let mut notification = Box::pin(guard.recv_goway());
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(notification.as_mut().poll(&mut cx).is_pending());
    guard.on_goaway(sid(4), qpack()).unwrap();
    assert!(notification.as_mut().poll(&mut cx).is_ready());
    assert_eq!(
        guard.remote_no_goway().unwrap_err().code,
        ErrorCode::RequestRejected
    );
    assert!(guard.local_not_goway().is_ok());
    assert!(guard.reads.contains_key(&0));
    assert!(!guard.reads.contains_key(&4));
    guard.on_goaway(sid(0), qpack()).unwrap();
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    assert!(Pin::new(&mut drain).poll(&mut cx).is_pending());
}

#[test]
fn close_clears_registries_propagates_error_and_completes_drain() {
    let streams = Streams::new(Role::Server);
    streams.lock().unwrap().accept(sid(4)).unwrap();
    let handles: Vec<_> = [0, 4].into_iter().map(|id| insert(&streams, id)).collect();
    let mut drain = streams.drain();
    let mut guard = streams.lock().unwrap();
    guard.goaway(&qpack()).unwrap();
    guard.close(ErrorCode::InternalError.reason("test close"));
    guard.close(ErrorCode::InternalError.reason("repeat close"));
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(Pin::new(&mut drain).poll(&mut cx).is_ready());
    drop(guard);
    for (read, write, recv, send) in handles {
        drop((read, write));
        assert_eq!(recv.codes(), [ErrorCode::InternalError.as_u64()]);
        assert_eq!(send.codes(), [ErrorCode::InternalError.as_u64()]);
    }
}
