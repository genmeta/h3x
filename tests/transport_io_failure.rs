use std::{
    future::pending,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use h3x::{Error, ErrorCode, H3Connection, Result, Role, Settings, Transport};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};

struct Writer(watch::Sender<bool>);
impl Drop for Writer {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}
impl CancelStream for Writer {
    fn cancel(&mut self, _: u64) {}
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
struct Reader;
impl StopSending for Reader {
    fn stop(&mut self, _: u64) {}
}
impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
struct IoFailureTransport {
    failure: watch::Sender<Option<Error>>,
    writers: Arc<std::sync::Mutex<Vec<watch::Receiver<bool>>>>,
}
impl Transport for IoFailureTransport {
    type StreamReader = Reader;
    type StreamWriter = Writer;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(&self) -> Result<Option<(u64, (Reader, Writer))>> {
        pending().await
    }
    async fn accept_bi(&self) -> Result<(u64, (Reader, Writer))> {
        pending().await
    }
    async fn open_uni(&self) -> Result<Option<(u64, Writer)>> {
        let (dropped, receiver) = watch::channel(false);
        self.writers.lock().unwrap().push(receiver);
        Ok(Some((2, Writer(dropped))))
    }
    async fn accept_uni(&self) -> Result<(u64, Reader)> {
        let mut failure = self.failure.subscribe();
        let error = failure
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .clone()
            .unwrap();
        Err(error)
    }
    fn close(&self, reason: String, code: u64) -> Result<()> {
        let _ = (reason, code);
        Ok(())
    }
}

#[tokio::test]
async fn accept_error_wakes_goaway_and_idle_critical_writers() {
    let (failure, _) = watch::channel(None);
    let writers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let connection = H3Connection::new(
        IoFailureTransport {
            failure: failure.clone(),
            writers: writers.clone(),
        },
        Settings::default(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while writers.lock().unwrap().len() < 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let goaway = connection.clone().goaway();
    let expected = ErrorCode::H3_INTERNAL_ERROR.reason("accept observed connection failure");
    failure.send_replace(Some(expected.clone()));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), goaway)
            .await
            .unwrap(),
        Err(expected)
    );
    let receivers = std::mem::take(&mut *writers.lock().unwrap());
    for mut receiver in receivers {
        tokio::time::timeout(
            Duration::from_secs(1),
            receiver.wait_for(|dropped| *dropped),
        )
        .await
        .unwrap()
        .unwrap();
    }
}

#[tokio::test]
async fn pool_returns_factory_error_and_retries_on_next_get() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let builds = Arc::new(AtomicUsize::new(0));
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        move |_: u8| {
            let builds = builds.clone();
            async move {
                if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err("factory failed");
                }
                H3Connection::new(
                    IoFailureTransport {
                        failure: watch::channel(None).0,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                )
                .map_err(|_| "H3 initialization failed")
            }
        }
    });

    assert!(matches!(pool.get(&1).await, Err("factory failed")));
    let connection = pool.get(&1).await.unwrap();
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    drop(connection);
}

#[tokio::test]
async fn pool_removal_allows_inflight_build_without_replacing_new_entry() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let builds = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        let started = started.clone();
        let resume = resume.clone();
        move |_: u8| {
            let builds = builds.clone();
            let started = started.clone();
            let resume = resume.clone();
            async move {
                if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                    started.notify_one();
                    resume.notified().await;
                }
                H3Connection::new(
                    IoFailureTransport {
                        failure: watch::channel(None).0,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                )
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        let old_get = tokio::spawn({
            let pool = pool.clone();
            async move { pool.get(&1).await }
        });
        started.notified().await;
        assert!(pool.remove(&1));
        let replacement = pool.get(&1).await.unwrap();
        resume.notify_one();
        let old = old_get.await.unwrap().unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);

        // Completing the removed build must not repopulate the cache.
        // Terminating it must not evict the replacement either.
        drop(old.goaway());
        tokio::task::yield_now().await;
        pool.get(&1).await.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        drop(replacement);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn pool_serializes_builds_and_replaces_goaway_connections() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let builds = Arc::new(AtomicUsize::new(0));
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        move |_: u8| {
            let builds = builds.clone();
            async move {
                builds.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                H3Connection::new(
                    IoFailureTransport {
                        failure: watch::channel(None).0,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                )
            }
        }
    });
    let (first, second) = tokio::join!(pool.get(&1), pool.get(&1));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    drop(first.goaway());
    // Eviction is asynchronous: let the connection observer process GOAWAY.
    tokio::task::yield_now().await;
    let replacement = pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    // An old observer must not evict the replacement generation.
    tokio::task::yield_now().await;
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert!(pool.remove(&1));
    assert!(!pool.remove(&1));
    drop((second, replacement));
}
