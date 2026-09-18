use std::{
    future::pending,
    io,
    pin::Pin,
    sync::{
        Weak,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
};

use qbase::sid::{Dir, StreamId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::{Error, Role};

struct Io;

impl AsyncRead for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StopSending for Io {
    fn stop(&mut self, _: u64) {}
}

impl CancelStream for Io {
    fn cancel(&mut self, _: u64) {}
}

struct TestTransport {
    streams: Weak<Mutex<BiStreams<Io, Io>>>,
    polls: AtomicUsize,
    pending: bool,
}

impl TestTransport {
    fn poll_stream(&self, id: u64) -> Poll<Result<(u64, (Io, Io))>> {
        assert!(self.streams.upgrade().unwrap().try_lock().is_err());
        self.polls.fetch_add(1, Ordering::Relaxed);
        if self.pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok((id, (Io, Io))))
        }
    }
}

impl Transport for TestTransport {
    type StreamReader = Io;
    type StreamWriter = Io;

    fn role(&self) -> Role {
        Role::Client
    }

    async fn open_bi(&self) -> Result<Option<(u64, (Io, Io))>> {
        poll_fn(|_| self.poll_stream(0)).await.map(Some)
    }

    async fn accept_bi(&self) -> Result<(u64, (Io, Io))> {
        poll_fn(|_| self.poll_stream(1)).await
    }

    async fn open_uni(&self) -> Result<Option<(u64, Io)>> {
        unreachable!()
    }
    async fn accept_uni(&self) -> Result<(u64, Io)> {
        unreachable!()
    }
    fn close(&self, _: String, _: u64) -> Result<()> {
        Ok(())
    }
    async fn terminated(&self) -> Error {
        pending().await
    }
}

fn connection(pending: bool) -> H3Connection<TestTransport> {
    let streams = Arc::new(Mutex::new(BiStreams::new(Role::Client)));
    let settings = Arc::new(Settings::default());
    let qpack = ArcQpack::new(&settings).unwrap();
    let control = Arc::new(control::Control::new(settings));
    H3Connection {
        transport: Arc::new(TestTransport {
            streams: Arc::downgrade(&streams),
            polls: AtomicUsize::new(0),
            pending,
        }),
        qpack,
        control,
        bi_streams: streams,
    }
}

#[test]
fn pending_open_releases_lock_and_checks_goaway_before_repolling() {
    let connection = connection(true);
    let mut opening = pin!(connection.open_bi());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(opening.as_mut().poll(&mut cx).is_pending());
    connection
        .bi_streams
        .try_lock()
        .unwrap()
        .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
    assert!(
        matches!(opening.as_mut().poll(&mut cx), Poll::Ready(Err(error))
        if error.code == ErrorCode::H3_REQUEST_REJECTED)
    );
    assert_eq!(connection.transport.polls.load(Ordering::Relaxed), 1);
}

#[test]
fn pending_accept_releases_lock_and_checks_goaway_before_repolling() {
    let connection = connection(true);
    let mut accepting = pin!(connection.accept_bi());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(accepting.as_mut().poll(&mut cx).is_pending());
    connection.bi_streams.try_lock().unwrap().local_goaway();
    assert!(
        matches!(accepting.as_mut().poll(&mut cx), Poll::Ready(Err(error))
        if error.code == ErrorCode::H3_REQUEST_REJECTED)
    );
    assert_eq!(connection.transport.polls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn ready_streams_are_polled_under_lock_and_registered() {
    let connection = connection(false);
    let opened = connection.open_bi().await.unwrap();
    let accepted = connection.accept_bi().await.unwrap();
    let drained = {
        let mut guard = connection.bi_streams.lock().unwrap();
        assert!(guard.can_accept().is_ok());
        assert_eq!(
            guard.receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0)),
            vec![0]
        );
        assert_eq!(
            guard.local_goaway().0,
            StreamId::new(Role::Server, Dir::Bi, 1)
        );
        guard.drained()
    };
    let mut drained = pin!(drained);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(drained.as_mut().poll(&mut cx).is_pending());
    drop(accepted);
    drained.await;
    drop(opened);
}

#[test]
fn goaway_freezes_admission_before_shutdown_future_is_polled() {
    let connection = connection(true);
    let shutdown = connection.clone().goaway();
    assert!(connection.bi_streams.lock().unwrap().can_accept().is_err());
    drop(shutdown);
}
