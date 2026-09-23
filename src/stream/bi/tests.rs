use std::{
    io,
    pin::Pin,
    sync::{Barrier, atomic::AtomicUsize},
    task::{Context, Poll},
};

use futures::task::{ArcWake, waker};
use qbase::varint::VarInt;
use tokio::io::{AsyncRead, ReadBuf};

use super::*;
use crate::{Error, ErrorCode, ReadRequest, ReadResponse, Settings, TransportError};

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
    insert_with_qpack(streams, id, qpack())
}

fn insert_with_qpack(
    streams: &Streams,
    id: u64,
    qpack: ArcQpack,
) -> (H3ReadStream<Io>, H3WriteStream<Io>, Io, Io) {
    let recv = Io::default();
    let send = Io::default();
    let (read, write) = streams.insert(
        &mut streams.lock().unwrap(),
        id,
        recv.clone(),
        send.clone(),
        qpack,
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
        assert_eq!(recv.codes(), [ErrorCode::InternalError.as_u64()]);
        assert_eq!(send.codes(), [ErrorCode::InternalError.as_u64()]);
    }
}

#[test]
fn concurrent_direction_aborts_converge_without_duplicate_transport_cancellation() {
    let streams = Streams::new(Role::Server);
    streams.lock().unwrap().accept(sid(0)).unwrap();
    let feedback = Arc::new(AtomicUsize::new(0));
    let qpack = ArcQpack::new(&Settings::default()).unwrap();
    qpack
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .decoder
        .on_instruction({
            let feedback = feedback.clone();
            move |batch| {
                feedback.fetch_add(batch.len(), Ordering::SeqCst);
                Ok(())
            }
        });
    let (mut read, write, recv, send) = insert_with_qpack(&streams, 0, qpack.clone());
    let mut drain = streams.drain();
    let wake_count = Arc::new(WakeCount::default());
    let waker = waker(wake_count.clone());
    let mut cx = Context::from_waker(&waker);
    streams.lock().unwrap().goaway(&qpack).unwrap();
    assert!(Pin::new(&mut drain).poll(&mut cx).is_pending());

    let barrier = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let read_barrier = barrier.clone();
        scope.spawn(move || {
            read_barrier.wait();
            read.stop(42);
        });
        scope.spawn(move || {
            barrier.wait();
            (&write).cancel(42);
        });
    });

    let guard = streams.lock().unwrap();
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    drop(guard);
    assert_eq!(recv.codes(), [ErrorCode::InternalError.as_u64()]);
    assert_eq!(send.codes(), [ErrorCode::InternalError.as_u64()]);
    assert_eq!(wake_count.0.load(Ordering::SeqCst), 1);
    assert!(Pin::new(&mut drain).poll(&mut cx).is_ready());
    assert!(qpack.lock().unwrap().is_ok());

    // Repeated stream-cancellation feedback remains non-fatal.
    let feedback_before_duplicates = feedback.load(Ordering::SeqCst);
    qpack.cancel_decode(vec![0]).unwrap();
    qpack.cancel_decode(vec![0]).unwrap();
    assert_eq!(
        feedback.load(Ordering::SeqCst),
        feedback_before_duplicates + 2
    );
    assert!(qpack.lock().unwrap().is_ok());
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
fn no_error_cancels_qpack_decode_only_when_reading_stops() {
    for stop_read in [true, false] {
        let streams = Streams::new(Role::Client);
        let qpack = qpack();
        let feedback = Arc::new(Mutex::new(Vec::new()));
        let captured = feedback.clone();
        qpack
            .with_state(|state| {
                state.decoder.on_instruction(move |batch| {
                    captured.lock().unwrap().push(format!("{batch:?}"));
                    Ok(())
                });
                Ok(())
            })
            .unwrap();
        let (mut read, write, _, _) = insert_with_qpack(&streams, 0, qpack.clone());

        if stop_read {
            read.stop(ErrorCode::NoError.as_u64());
        } else {
            (&write).cancel(ErrorCode::NoError.as_u64());
        }

        let expected = if stop_read {
            vec!["[StreamCancellation(0)]"]
        } else {
            vec![]
        };
        assert_eq!(*feedback.lock().unwrap(), expected);
        assert!(qpack.error().is_none());
    }
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
fn application_handles_do_not_keep_the_registry_alive() {
    let streams = Streams::new(Role::Client);
    let registry = Arc::downgrade(&streams.inner);
    let (_read, _write, _, _) = insert(&streams, 0);

    drop(streams);

    assert!(registry.upgrade().is_none());
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
}

#[test]
fn goaway_batches_more_cancellations_than_the_feedback_queue_capacity() {
    let streams = Streams::new(Role::Client);
    let qpack = ArcQpack::new(&Settings::default()).unwrap();
    let (feedback_tx, mut feedback_rx) =
        tokio::sync::mpsc::channel(crate::qpack::MAX_PENDING_INSTRUCTION);
    qpack
        .with_state(|state| {
            state.decoder.on_instruction(move |batch| {
                feedback_tx
                    .try_send(batch)
                    .map_err(crate::qpack::instruction_send_error)
            });
            Ok(())
        })
        .unwrap();

    let handles = (0..=17)
        .map(|index| {
            let id = index * 4;
            (id, insert_with_qpack(&streams, id, qpack.clone()))
        })
        .collect::<Vec<_>>();

    let mut guard = streams.lock().unwrap();
    guard.on_goaway(sid(4), qpack.clone()).unwrap();
    assert!(guard.reads.contains_key(&0));
    assert!(guard.writes.contains_key(&0));
    assert_eq!(guard.reads.len(), 1);
    assert_eq!(guard.writes.len(), 1);
    drop(guard);

    let batch = feedback_rx.try_recv().unwrap();
    assert_eq!(batch.len(), 17);
    let mut cancellations = batch
        .iter()
        .map(|instruction| format!("{instruction:?}"))
        .collect::<Vec<_>>();
    cancellations.sort();
    let mut expected = (1..=17)
        .map(|index| format!("StreamCancellation({})", index * 4))
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(cancellations, expected);
    assert!(feedback_rx.try_recv().is_err());
    assert!(qpack.error().is_none());
    assert!(handles[0].1.2.codes().is_empty());
    assert!(handles[0].1.3.codes().is_empty());
}

struct ResetReader {
    bytes: &'static [u8],
    offset: usize,
}

struct FinReader {
    bytes: Vec<u8>,
    offset: usize,
}

impl AsyncRead for FinReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = (self.bytes.len() - self.offset).min(buf.remaining());
        if count != 0 {
            buf.put_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
        }
        Poll::Ready(Ok(()))
    }
}

impl StopSending for FinReader {
    fn stop(&mut self, _: u64) {}
}

impl TransportError for FinReader {
    fn map_error(error: io::Error) -> Error {
        Error::from_stream_io(error)
    }
}

impl AsyncRead for ResetReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.bytes.len() {
            return Poll::Ready(Err(io::Error::other("peer reset the stream")));
        }
        let count = (self.bytes.len() - self.offset).min(buf.remaining());
        buf.put_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl StopSending for ResetReader {
    fn stop(&mut self, _: u64) {}
}

impl TransportError for ResetReader {
    fn map_error(_: io::Error) -> Error {
        ErrorCode::RequestCancelled.stream("peer reset the stream")
    }
}

#[tokio::test]
async fn reset_during_headers_emits_qpack_stream_cancellation() {
    let streams = ArcBiStreams::<ResetReader, Io>::new(Role::Server);
    let qpack = ArcQpack::new(&Settings::default()).unwrap();
    let feedback = Arc::new(Mutex::new(Vec::new()));
    let captured = feedback.clone();
    qpack
        .with_state(|state| {
            state.decoder.on_instruction(move |batch| {
                captured.lock().unwrap().push(format!("{batch:?}"));
                Ok(())
            });
            Ok(())
        })
        .unwrap();
    let send = Io::default();
    let (read, write) = streams.insert(
        &mut streams.lock().unwrap(),
        0,
        // HEADERS length is 3, but only one payload byte arrives before RESET.
        ResetReader {
            bytes: &[0x01, 0x03, 0x00],
            offset: 0,
        },
        send.clone(),
        qpack.clone(),
    );

    let result: crate::Result<crate::Request<crate::R>> = read.read_request(qpack).await;
    let Err(error) = result else {
        panic!("RESET during HEADERS must fail the request")
    };
    assert_eq!(error.code, ErrorCode::RequestCancelled);
    assert_eq!(
        feedback.lock().unwrap().as_slice(),
        ["[StreamCancellation(0)]"]
    );
    assert_eq!(send.codes(), [ErrorCode::RequestCancelled.as_u64()]);
    assert!(streams.lock().unwrap().reads.is_empty());
    assert!(streams.lock().unwrap().writes.is_empty());
    drop(write);
}

#[tokio::test]
async fn eof_before_request_headers_cancels_the_response_direction() {
    let streams = ArcBiStreams::<FinReader, Io>::new(Role::Server);
    let qpack = qpack();
    let send = Io::default();
    let (read, write) = streams.insert(
        &mut streams.lock().unwrap(),
        0,
        FinReader {
            bytes: Vec::new(),
            offset: 0,
        },
        send.clone(),
        qpack.clone(),
    );

    let result: crate::Result<crate::Request<crate::R>> = read.read_request(qpack.clone()).await;
    let Err(error) = result else {
        panic!("EOF before request HEADERS must fail the request")
    };
    assert_eq!(error.code, ErrorCode::RequestIncomplete);
    assert_eq!(send.codes(), [ErrorCode::RequestIncomplete.as_u64()]);
    let guard = streams.lock().unwrap();
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    drop(guard);
    assert!(qpack.error().is_none());
    drop(write);
}

#[tokio::test]
async fn eof_after_informational_headers_cancels_the_request_direction() {
    // Literal-only QPACK field section containing `:status: 103`.
    let mut block = vec![0, 0, 0x27, 0];
    block.extend_from_slice(b":status");
    block.extend_from_slice(&[3, b'1', b'0', b'3']);
    let mut wire = vec![1, block.len() as u8];
    wire.extend(block);

    let streams = ArcBiStreams::<FinReader, Io>::new(Role::Client);
    let qpack = qpack();
    let send = Io::default();
    let (read, write) = streams.insert(
        &mut streams.lock().unwrap(),
        0,
        FinReader {
            bytes: wire,
            offset: 0,
        },
        send.clone(),
        qpack.clone(),
    );

    let result: crate::Result<crate::Response<crate::R>> =
        read.read_response(http::Method::GET, qpack.clone()).await;
    let Err(error) = result else {
        panic!("EOF before final response HEADERS must fail the request")
    };
    assert_eq!(error.code, ErrorCode::RequestIncomplete);
    assert_eq!(send.codes(), [ErrorCode::RequestIncomplete.as_u64()]);
    let guard = streams.lock().unwrap();
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    drop(guard);
    assert!(qpack.error().is_none());
    drop(write);
}

#[test]
fn local_goaway_freezes_acceptance_and_preserves_registered_streams() {
    for (role, first) in [(Role::Server, 0), (Role::Client, 1)] {
        let streams = Streams::new(role);
        let _admitted = insert(&streams, first + 4);
        let _rejected = insert(&streams, first + 8);
        let mut guard = streams.lock().unwrap();
        guard.accept(sid(first + 4)).unwrap();
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
        assert!(guard.accept(sid(first + 8)).is_err());
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
    drop(guard);
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
    guard.close(ErrorCode::InternalError.connection("test close"));
    guard.close(ErrorCode::InternalError.connection("repeat close"));
    assert!(guard.reads.is_empty());
    assert!(guard.writes.is_empty());
    drop(guard);
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(Pin::new(&mut drain).poll(&mut cx).is_ready());
    for (read, write, recv, send) in handles {
        drop((read, write));
        assert_eq!(recv.codes(), [ErrorCode::InternalError.as_u64()]);
        assert_eq!(send.codes(), [ErrorCode::InternalError.as_u64()]);
    }
}
