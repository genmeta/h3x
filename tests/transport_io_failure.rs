use std::{
    future::pending,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use h3x::{Error, ErrorCode, H3Connection, Result, Role, Settings, Transport, TransportError};
use qbase::{error::AppError, frame::ResetStreamError, varint::VarInt};
use qrecovery::{recv::StopSending, send::CancelStream, streams::error::StreamError};
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

impl TransportError for Writer {
    fn map_error(error: std::io::Error) -> Error {
        map_dquic_error(error)
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

impl TransportError for Reader {
    fn map_error(error: std::io::Error) -> Error {
        map_dquic_error(error)
    }
}

// This belongs to the dquic adapter, not to h3x's protocol/error modules.
fn map_dquic_error(error: std::io::Error) -> Error {
    let mut source = error
        .get_ref()
        .map(|cause| cause as &(dyn std::error::Error + 'static));
    while let Some(cause) = source {
        if let Some(error) = cause.downcast_ref::<StreamError>() {
            return match error {
                StreamError::Connection(qbase::error::Error::App(error)) => {
                    ErrorCode::try_from(error.error_code())
                        .unwrap_or(ErrorCode::NoError)
                        .connection(error.reason())
                }
                StreamError::Connection(error) => {
                    ErrorCode::InternalError.connection(error.to_string())
                }
                StreamError::Reset(error) => ErrorCode::try_from(error.error_code())
                    .unwrap_or(ErrorCode::NoError)
                    .stream("peer reset the stream"),
                StreamError::Finished => todo!(),
            };
        }
        source = cause.source();
    }
    Error::from_stream_io(error)
}

#[test]
fn dquic_adapter_classifies_reset_and_connection_errors() {
    let code = VarInt::try_from(ErrorCode::RequestCancelled.as_u64()).unwrap();
    let reset = std::io::Error::from(StreamError::Reset(ResetStreamError::new(
        code,
        VarInt::from_u32(0),
    )));
    let reset = Reader::map_error(reset);
    assert!(matches!(reset, Error::Stream(_)));
    assert_eq!(reset.code, ErrorCode::RequestCancelled);

    let connection = std::io::Error::from(StreamError::Connection(qbase::error::Error::App(
        AppError::new(code, "connection closed"),
    )));
    let connection = Reader::map_error(connection);
    assert!(matches!(connection, Error::Connection(_)));
    assert_eq!(connection.code, ErrorCode::RequestCancelled);
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
        |_| {},
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
    let expected = ErrorCode::InternalError.connection("accept observed connection failure");
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
        move |_: u8, callback| {
            let builds = builds.clone();
            async move {
                if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(ErrorCode::InternalError.connection("factory failed"));
                }
                H3Connection::new(
                    IoFailureTransport {
                        failure: watch::channel(None).0,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                    callback,
                )
                .map_err(|_| ErrorCode::InternalError.connection("H3 initialization failed"))
            }
        }
    });

    assert_eq!(pool.get(&1).await.err().unwrap().reason, "factory failed");
    let _connection = pool.get(&1).await.unwrap();
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
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
        move |_: u8, callback| {
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
                    callback,
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
        let _replacement = pool.get(&1).await.unwrap();
        resume.notify_one();
        let old = old_get.await.unwrap().unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);

        // Completing the removed build must not repopulate the cache.
        // Terminating it must not evict the replacement either.
        drop(old.goaway());
        tokio::task::yield_now().await;
        pool.get(&1).await.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
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
        move |_: u8, callback| {
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
                    callback,
                )
            }
        }
    });
    let (first, second) = tokio::join!(pool.get(&1), pool.get(&1));
    let first = first.unwrap();
    let _second = second.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    drop(first.goaway());
    // Eviction is asynchronous: let the connection observer process GOAWAY.
    tokio::task::yield_now().await;
    let _replacement = pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    // An old observer must not evict the replacement generation.
    tokio::task::yield_now().await;
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    assert!(pool.remove(&1));
    assert!(!pool.remove(&1));
}

#[tokio::test]
async fn old_transport_failure_preserves_replacement_and_removal_is_idempotent() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let builds = Arc::new(AtomicUsize::new(0));
    let (first_failure, _) = watch::channel(None);
    let (exited, mut exit_count) = watch::channel(0usize);
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        let first_failure = first_failure.clone();
        move |_: u8, callback| {
            let build = builds.fetch_add(1, Ordering::SeqCst);
            let failure = if build == 0 {
                first_failure.clone()
            } else {
                watch::channel(None).0
            };
            let exited = exited.clone();
            async move {
                H3Connection::new(
                    IoFailureTransport {
                        failure,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                    move |connection| {
                        callback(connection);
                        exited.send_modify(|count| *count += 1);
                    },
                )
            }
        }
    });

    let first = pool.get(&1).await.unwrap();
    assert!(pool.remove(&1));
    let replacement = pool.get(&1).await.unwrap();
    first_failure.send_replace(Some(
        ErrorCode::InternalError.connection("connection idle timeout"),
    ));
    tokio::time::timeout(
        Duration::from_secs(1),
        exit_count.wait_for(|count| *count == 1),
    )
    .await
    .unwrap()
    .unwrap();
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);

    // Reusing the callback after replacement must still target only its original slot.
    drop(first);
    let callback = pool.on_unreusable(1);
    callback(&replacement);
    callback(&replacement);
    assert!(!pool.remove(&1));
    pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn idle_transport_failure_evicts_cached_outbound_without_business_io() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let builds = Arc::new(AtomicUsize::new(0));
    let (failure, _) = watch::channel(None);
    let (exited, mut exit_count) = watch::channel(0usize);
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        let failure = failure.clone();
        move |_: u8, callback| {
            let first = builds.fetch_add(1, Ordering::SeqCst) == 0;
            let failure = if first {
                failure.clone()
            } else {
                watch::channel(None).0
            };
            let exited = exited.clone();
            async move {
                H3Connection::new(
                    IoFailureTransport {
                        failure,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                    move |connection| {
                        callback(connection);
                        exited.send_modify(|count| *count += 1);
                    },
                )
            }
        }
    });

    let _failed = pool.get(&1).await.unwrap();
    failure.send_replace(Some(
        ErrorCode::InternalError.connection("connection idle timeout"),
    ));
    tokio::time::timeout(
        Duration::from_secs(1),
        exit_count.wait_for(|count| *count == 1),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!pool.remove(&1));
    let _replacement = pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn outbound_exit_before_factory_returns_fails_get_without_caching() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let builds = Arc::new(AtomicUsize::new(0));
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        move |_: u8, callback| {
            let first = builds.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                let error = first.then(|| ErrorCode::InternalError.connection("no viable path"));
                let (exited, mut exit_count) = watch::channel(0usize);
                let connection = H3Connection::new(
                    IoFailureTransport {
                        failure: watch::channel(error).0,
                        writers: Arc::new(std::sync::Mutex::new(Vec::new())),
                    },
                    Settings::default(),
                    move |connection| {
                        callback(connection);
                        exited.send_modify(|count| *count += 1);
                    },
                )?;
                if first {
                    tokio::time::timeout(
                        Duration::from_secs(1),
                        exit_count.wait_for(|count| *count == 1),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                }
                Ok::<_, Error>(connection)
            }
        }
    });

    let error = pool.get(&1).await.err().unwrap();
    assert_eq!(error.reason, "no viable path");
    assert!(!pool.remove(&1));
    let _replacement = pool.get(&1).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn inbound_termination_preserves_outbound_and_rejects_late_insertion() {
    let pool = h3x::Pool::new(|_: u8, callback| async move {
        H3Connection::new(
            IoFailureTransport {
                failure: watch::channel(None).0,
                writers: Arc::new(std::sync::Mutex::new(Vec::new())),
            },
            Settings::default(),
            callback,
        )
    });
    let outbound = pool.get(&1).await.unwrap();
    let (failure, _) = watch::channel(None);
    let (exited, mut exit_count) = watch::channel(0usize);
    let callback = pool.on_unreusable(1);
    let inbound = H3Connection::new(
        IoFailureTransport {
            failure: failure.clone(),
            writers: Arc::new(std::sync::Mutex::new(Vec::new())),
        },
        Settings::default(),
        move |connection| {
            callback(connection);
            exited.send_modify(|count| *count += 1);
        },
    )
    .unwrap();
    assert!(pool.insert(1, inbound.clone()).is_ok());
    failure.send_replace(Some(ErrorCode::InternalError.connection("no viable path")));
    tokio::time::timeout(
        Duration::from_secs(1),
        exit_count.wait_for(|count| *count == 1),
    )
    .await
    .unwrap()
    .unwrap();
    let cached = pool.drain();
    assert_eq!(cached.len(), 1);
    assert!(std::ptr::eq(cached[0].transport(), outbound.transport()));
    assert!(pool.insert(1, inbound).is_err());
}

fn healthy_connection(
    callback: h3x::UnreusableCallback<IoFailureTransport>,
) -> H3Connection<IoFailureTransport> {
    H3Connection::new(
        IoFailureTransport {
            failure: watch::channel(None).0,
            writers: Arc::new(std::sync::Mutex::new(Vec::new())),
        },
        Settings::default(),
        callback,
    )
    .unwrap()
}

#[tokio::test]
async fn accepted_connections_are_reusable_during_build_and_survive_its_result() {
    // Exercise successful, failed, and already-draining factory results, with
    // either room for the built connection or a cache filled by accepted peers.
    for outcome in 0..3 {
        for accepted_count in 1..=2 {
            let resume = Arc::new(tokio::sync::Notify::new());
            let pool = h3x::Pool::new({
                let resume = resume.clone();
                move |_: u8, callback| {
                    let resume = resume.clone();
                    async move {
                        resume.notified().await;
                        if outcome == 1 {
                            return Err(ErrorCode::InternalError.connection("factory failed"));
                        }
                        let connection = healthy_connection(callback);
                        if outcome == 2 {
                            drop(connection.clone().goaway());
                        }
                        Ok(connection)
                    }
                }
            });
            let building = pool.get(&1);
            tokio::pin!(building);
            assert!(futures::poll!(&mut building).is_pending());
            let waiting = pool.get(&1);
            tokio::pin!(waiting);
            assert!(futures::poll!(&mut waiting).is_pending());
            let mut accepted = Vec::new();
            for _ in 0..accepted_count {
                let connection = healthy_connection(pool.on_unreusable(1));
                assert!(pool.insert(1, connection.clone()).is_ok());
                accepted.push(connection);
            }
            let reused = pool.get(&1).await.unwrap();
            assert!(std::ptr::eq(reused.transport(), accepted[0].transport()));
            resume.notify_one();
            let built = building.await.unwrap();
            let waited = waiting.await.unwrap();
            assert!(std::ptr::eq(waited.transport(), accepted[0].transport()));
            if outcome == 0 {
                assert!(!std::ptr::eq(built.transport(), accepted[0].transport()));
            } else {
                assert!(std::ptr::eq(built.transport(), accepted[0].transport()));
            }
            let cached = pool.drain();
            assert_eq!(cached.len(), if outcome == 0 { 2 } else { accepted_count });
            if outcome == 0 && accepted_count == 1 {
                assert!(std::ptr::eq(cached[1].transport(), built.transport()));
            }
            for (cached, accepted) in cached.iter().zip(&accepted) {
                assert!(std::ptr::eq(cached.transport(), accepted.transport()));
            }
        }
    }
}

#[tokio::test]
async fn accepted_connection_exit_does_not_start_a_second_concurrent_build() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let builds = Arc::new(AtomicUsize::new(0));
    let resume = Arc::new(tokio::sync::Notify::new());
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        let resume = resume.clone();
        move |_: u8, callback| {
            let builds = builds.clone();
            let resume = resume.clone();
            async move {
                builds.fetch_add(1, Ordering::SeqCst);
                resume.notified().await;
                Ok::<_, Error>(healthy_connection(callback))
            }
        }
    });
    let first = pool.get(&1);
    tokio::pin!(first);
    assert!(futures::poll!(&mut first).is_pending());
    let (exited, mut exit) = watch::channel(false);
    let callback = pool.on_unreusable(1);
    let accepted = healthy_connection(Box::new(move |connection| {
        callback(connection);
        exited.send_replace(true);
    }));
    assert!(pool.insert(1, accepted.clone()).is_ok());
    drop(accepted.goaway());
    tokio::time::timeout(Duration::from_secs(1), exit.wait_for(|exited| *exited))
        .await
        .unwrap()
        .unwrap();
    let second = pool.get(&1);
    tokio::pin!(second);
    assert!(futures::poll!(&mut second).is_pending());
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    resume.notify_one();
    let first = first.await.unwrap();
    let second = second.await.unwrap();
    assert!(std::ptr::eq(first.transport(), second.transport()));
    assert_eq!(builds.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_build_releases_waiter_and_different_keys_build_independently() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let builds = Arc::new(AtomicUsize::new(0));
    let pool = h3x::Pool::new({
        let builds = builds.clone();
        move |key: u8, callback| {
            let builds = builds.clone();
            async move {
                let build = builds.fetch_add(1, Ordering::SeqCst);
                if key == 1 && build == 0 {
                    pending::<()>().await;
                }
                Ok::<_, Error>(healthy_connection(callback))
            }
        }
    });
    let mut cancelled = Box::pin(pool.get(&1));
    assert!(futures::poll!(&mut cancelled).is_pending());
    let mut waiting = Box::pin(pool.get(&1));
    assert!(futures::poll!(&mut waiting).is_pending());
    let independent = pool.get(&2).await.unwrap();
    assert_eq!(builds.load(Ordering::SeqCst), 2);
    drop(cancelled);
    let retried = waiting.await.unwrap();
    assert!(!std::ptr::eq(retried.transport(), independent.transport()));
    assert_eq!(builds.load(Ordering::SeqCst), 3);
    assert_eq!(pool.drain().len(), 2);
}

#[tokio::test]
async fn drain_detaches_pending_build_and_its_callback_from_replacement() {
    let resume = Arc::new(tokio::sync::Notify::new());
    let pool = h3x::Pool::new({
        let resume = resume.clone();
        move |_: u8, callback| {
            let resume = resume.clone();
            async move {
                resume.notified().await;
                Ok::<_, Error>(healthy_connection(callback))
            }
        }
    });
    let building = pool.get(&1);
    tokio::pin!(building);
    assert!(futures::poll!(&mut building).is_pending());
    assert!(pool.drain().is_empty());
    let replacement = healthy_connection(pool.on_unreusable(1));
    assert!(pool.insert(1, replacement.clone()).is_ok());
    resume.notify_one();
    let old = building.await.unwrap();
    drop(old.goaway());
    tokio::task::yield_now().await;
    let cached = pool.drain();
    assert_eq!(cached.len(), 1);
    assert!(std::ptr::eq(cached[0].transport(), replacement.transport()));
}

#[tokio::test]
async fn factory_completion_failure_and_cancellation_wake_all_waiters() {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl futures::task::ArcWake for WakeCount {
        fn wake_by_ref(this: &Arc<Self>) {
            this.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    for outcome in 0..3 {
        let builds = Arc::new(AtomicUsize::new(0));
        let resume = Arc::new(tokio::sync::Notify::new());
        let pool = h3x::Pool::new({
            let builds = builds.clone();
            let resume = resume.clone();
            move |_: u8, callback| {
                let builds = builds.clone();
                let resume = resume.clone();
                async move {
                    if builds.fetch_add(1, Ordering::SeqCst) == 0 {
                        resume.notified().await;
                        if outcome == 1 {
                            return Err(ErrorCode::InternalError.connection("factory failed"));
                        }
                    }
                    Ok(healthy_connection(callback))
                }
            }
        });
        let mut building = Box::pin(pool.get(&1));
        assert!(futures::poll!(&mut building).is_pending());
        // Cancelling a waiter must not cancel or release the active builder.
        let mut abandoned = Box::pin(pool.get(&1));
        assert!(futures::poll!(&mut abandoned).is_pending());
        drop(abandoned);

        let mut waiters = Vec::new();
        for _ in 0..3 {
            let wakes = Arc::new(WakeCount::default());
            let waker = futures::task::waker_ref(&wakes);
            let mut context = Context::from_waker(&waker);
            let mut waiting = Box::pin(pool.get(&1));
            assert!(waiting.as_mut().poll(&mut context).is_pending());
            waiters.push((waiting, wakes));
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        if outcome == 2 {
            drop(building);
        } else {
            resume.notify_one();
            assert_eq!(building.await.is_ok(), outcome == 0);
        }
        // Check actual wakeups before polling again, so a missed notification
        // cannot be hidden by manually resuming the waiting futures.
        for (_, wakes) in &waiters {
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
        }
        let mut connections = Vec::new();
        for (waiting, _) in waiters {
            connections.push(waiting.await.unwrap());
        }
        assert!(
            connections
                .iter()
                .all(|connection| std::ptr::eq(connection.transport(), connections[0].transport()))
        );
        assert_eq!(
            builds.load(Ordering::SeqCst),
            if outcome == 0 { 1 } else { 2 }
        );
        assert_eq!(pool.drain().len(), 1);
    }
}
