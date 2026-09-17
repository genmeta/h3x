use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use h3x::{ErrorCode, H3Connection, Result, Role, Transport};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex},
    sync::Notify,
    task::Id,
};

#[derive(Default)]
struct Probe {
    accept_tasks: Mutex<HashSet<Id>>,
    read_tasks: Mutex<HashSet<Id>>,
    live: AtomicUsize,
    closed: Mutex<Option<h3x::Error>>,
    ended: Notify,
    readers: Mutex<Vec<Waker>>,
    dropped_before_close: AtomicBool,
}

struct Reader(DuplexStream, Arc<Probe>);

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.1.read_tasks.lock().unwrap().insert(tokio::task::id());
        // Model the Transport contract: termination wakes pending stream I/O.
        let probe = self.1.clone();
        let mut readers = probe.readers.lock().unwrap();
        if let Some(error) = probe.closed.lock().unwrap().clone() {
            return Poll::Ready(Err(error.into()));
        }
        readers.push(cx.waker().clone());
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl StopSending for Reader {
    fn stop(&mut self, _: u64) {
        self.0 = duplex(1).0;
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        if self.1.closed.lock().unwrap().is_none() {
            self.1.dropped_before_close.store(true, Ordering::SeqCst);
        }
        self.1.live.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Writer(tokio::io::Sink);
impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl CancelStream for Writer {
    fn cancel(&mut self, _: u64) {}
}

struct Incoming {
    streams: Mutex<VecDeque<Reader>>,
    probe: Arc<Probe>,
}

impl Transport for Incoming {
    type StreamReader = Reader;
    type StreamWriter = Writer;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Reader, Writer))>> {
        Err(self.terminated().await)
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
        Err(self.terminated().await)
    }
    async fn open_uni(&self) -> Result<Option<(u64, Writer)>> {
        Ok(Some((2, Writer(tokio::io::sink()))))
    }
    async fn accept_uni(&self) -> Result<(u64, Reader)> {
        self.probe
            .accept_tasks
            .lock()
            .unwrap()
            .insert(tokio::task::id());
        let stream = self.streams.lock().unwrap().pop_front();
        match stream {
            Some(stream) => Ok((3, stream)),
            None => Err(self.terminated().await),
        }
    }
    fn close(&self, reason: String, code: u64) -> Result<()> {
        let error = match code {
            0x100 => ErrorCode::H3_NO_ERROR,
            0x103 => ErrorCode::H3_STREAM_CREATION_ERROR,
            0x108 => ErrorCode::H3_ID_ERROR,
            _ => ErrorCode::H3_INTERNAL_ERROR,
        };
        self.probe
            .closed
            .lock()
            .unwrap()
            .get_or_insert(error.with_reason(reason));
        self.probe.ended.notify_waiters();
        for reader in self.probe.readers.lock().unwrap().drain(..) {
            reader.wake();
        }
        Ok(())
    }
    async fn terminated(&self) -> h3x::Error {
        loop {
            let changed = self.probe.ended.notified();
            if let Some(error) = self.probe.closed.lock().unwrap().clone() {
                return error;
            }
            changed.await;
        }
    }
}

async fn setup(prefixes: &[&[u8]]) -> (H3Connection<Incoming>, Arc<Probe>, Vec<DuplexStream>) {
    let probe = Arc::new(Probe::default());
    let mut streams = VecDeque::new();
    let mut peers = Vec::new();
    for prefix in prefixes {
        let (mut peer, recv) = duplex(32);
        peer.write_all(prefix).await.unwrap();
        probe.live.fetch_add(1, Ordering::SeqCst);
        streams.push_back(Reader(recv, probe.clone()));
        peers.push(peer);
    }
    (
        H3Connection::new(
            Incoming {
                streams: Mutex::new(streams),
                probe: probe.clone(),
            },
            Default::default(),
        )
        .await
        .unwrap(),
        probe,
        peers,
    )
}

async fn bounded(work: impl Future<Output = ()>) {
    tokio::time::timeout(Duration::from_secs(2), work)
        .await
        .unwrap();
}

#[tokio::test]
async fn each_unidirectional_stream_has_a_task_and_transport_close_fails_reads() {
    let mut prefixes = vec![&[0x40][..]; 32];
    // Incomplete type prefixes must not block admission, and each distinct
    // critical stream type must be allowed on the same connection.
    prefixes.extend([&[0][..], &[2][..], &[3][..]]);
    let (connection, probe, _peers) = setup(&prefixes).await;
    bounded(async {
        while probe.read_tasks.lock().unwrap().len() != prefixes.len() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        probe
            .read_tasks
            .lock()
            .unwrap()
            .is_disjoint(&probe.accept_tasks.lock().unwrap())
    );
    drop(connection);
    assert!(probe.closed.lock().unwrap().is_none());
    *probe.closed.lock().unwrap() =
        Some(ErrorCode::H3_NO_ERROR.with_reason("test transport finished"));
    probe.ended.notify_waiters();
    for reader in probe.readers.lock().unwrap().drain(..) {
        reader.wake();
    }
    bounded(async {
        while probe.live.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(!probe.dropped_before_close.load(Ordering::SeqCst));
}

#[tokio::test]
async fn stream_task_errors_close_before_dropping_receivers() {
    for (prefixes, expected) in [
        (
            vec![&[0x40][..], &[0, 4, 0, 7, 1, 1][..]],
            ErrorCode::H3_ID_ERROR,
        ),
        (
            vec![&[0][..], &[0][..]],
            ErrorCode::H3_STREAM_CREATION_ERROR,
        ),
        (
            vec![&[2][..], &[2][..]],
            ErrorCode::H3_STREAM_CREATION_ERROR,
        ),
        (
            vec![&[3][..], &[3][..]],
            ErrorCode::H3_STREAM_CREATION_ERROR,
        ),
    ] {
        let (connection, probe, _peers) = setup(&prefixes).await;
        bounded(async {
            while probe.live.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(connection);
        assert_eq!(
            probe
                .closed
                .lock()
                .unwrap()
                .as_ref()
                .map(|error| error.code),
            Some(expected)
        );
        assert!(!probe.dropped_before_close.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn qpack_failure_closes_connection_and_cancels_pending_receivers() {
    for fail_before_tasks_start in [true, false] {
        let prefixes = [&[0x40][..], &[0][..], &[2][..], &[3][..]];
        let (connection, probe, _peers) = setup(&prefixes).await;
        if !fail_before_tasks_start {
            bounded(async {
                while probe.read_tasks.lock().unwrap().len() != prefixes.len() {
                    tokio::task::yield_now().await;
                }
            })
            .await;
        }
        let error = ErrorCode::H3_INTERNAL_ERROR.with_reason("QPACK failed independently of I/O");
        connection.qpack().on_error(error.clone());
        bounded(async {
            while probe.closed.lock().unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert_eq!(*probe.closed.lock().unwrap(), Some(error.clone()));
        assert_eq!(
            connection
                .qpack()
                .on_error(ErrorCode::H3_EXCESSIVE_LOAD.with_reason("later error")),
            error
        );
        drop(connection);
        bounded(async {
            while probe.live.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(!probe.dropped_before_close.load(Ordering::SeqCst));
    }
}
