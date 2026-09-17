//! Shared, identity-keyed connections with coalesced construction and managed draining.
use std::{
    collections::HashMap,
    fmt,
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{sync::watch, time::Instant};

use crate::{ErrorCode, H3Connection, Transport};

type ConnectFuture<T, E> = Pin<Box<dyn Future<Output = Result<H3Connection<T>, E>> + Send>>;
type Factory<K, T, E> = dyn Fn(K) -> ConnectFuture<T, E> + Send + Sync;

/// Result of obtaining a pooled connection.
pub type PoolResult<V, E = crate::Error> = Result<V, PoolError<E>>;

/// Errors shared by every waiter of a single connection attempt.
#[derive(Debug)]
pub enum PoolError<E> {
    /// Original factory failure, shared without requiring `E: Clone`.
    Connect(Arc<E>),
    /// The complete factory exceeded its configured deadline.
    ConnectTimeout,
    /// This build generation was explicitly revoked.
    Removed,
    /// The pool has begun permanent shutdown.
    Closed,
    /// The caller driving construction was cancelled or unwound.
    BuildCancelled,
    /// The connection could no longer admit requests at delivery.
    Unusable,
}

impl<E> Clone for PoolError<E> {
    fn clone(&self) -> Self {
        match self {
            Self::Connect(error) => Self::Connect(error.clone()),
            Self::ConnectTimeout => Self::ConnectTimeout,
            Self::Removed => Self::Removed,
            Self::Closed => Self::Closed,
            Self::BuildCancelled => Self::BuildCancelled,
            Self::Unusable => Self::Unusable,
        }
    }
}

impl<E: fmt::Display> fmt::Display for PoolError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "connection factory failed: {error}"),
            Self::ConnectTimeout => f.write_str("connection factory timed out"),
            Self::Removed => f.write_str("connection attempt removed"),
            Self::Closed => f.write_str("connection pool closed"),
            Self::BuildCancelled => f.write_str("connection builder cancelled"),
            Self::Unusable => f.write_str("connection is no longer reusable"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PoolError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Deadlines applied to construction and retirement.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Deadline for the entire factory, including authentication and H3 initialization.
    pub connect_timeout: Duration,
    /// Time allowed for each retired connection; `None` permits unbounded draining.
    pub drain_timeout: Option<Duration>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            drain_timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// A shared pool. Equal keys authorize reuse of the same authenticated connection.
///
/// The factory must complete QUIC authentication, verify ALPN `h3`, and initialize
/// H3 before returning. It must reclaim unreturned resources on failure or cancellation.
/// A returned connection must not already be managed by another pool.
///
/// Construction runs inside the first `get`, not a detached task: cancelling that
/// caller cancels the attempt for all its waiters. Calls require a Tokio runtime.
/// Dropping the last pool owner forces managed connections closed; use `shutdown`
/// to wait for graceful cleanup.
pub struct Pool<K, T: Transport, E = crate::Error> {
    inner: Arc<PoolInner<K, T, E>>,
}

struct PoolInner<K, T: Transport, E> {
    factory: Box<Factory<K, T, E>>,
    config: PoolConfig,
    state: Mutex<PoolState<K, T, E>>,
    shutdown_complete: watch::Sender<bool>,
}

struct PoolState<K, T: Transport, E> {
    accepting: bool,
    connecting: HashMap<K, Arc<Connecting<T, E>>>,
    connections: HashMap<K, H3Connection<T>>,
    draining: HashMap<K, Vec<Draining<T>>>,
    active_builds: usize,
}

struct Connecting<T: Transport, E> {
    result: watch::Sender<Option<PoolResult<H3Connection<T>, E>>>,
}

impl<T: Transport, E> Connecting<T, E> {
    fn finish(&self, result: PoolResult<H3Connection<T>, E>) {
        self.result.send_if_modified(|value| {
            if value.is_some() {
                return false;
            }
            *value = Some(result);
            true
        });
    }

    async fn wait(&self) -> PoolResult<H3Connection<T>, E> {
        let mut receiver = self.result.subscribe();
        let result = receiver
            .wait_for(Option::is_some)
            .await
            .expect("sender retained");
        result.as_ref().unwrap().clone()
    }
}

struct Draining<T: Transport> {
    connection: H3Connection<T>,
    deadline: Option<Instant>,
}

impl<K, T: Transport, E> Clone for Pool<K, T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<K, T, E> Pool<K, T, E>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    T: Transport,
    E: std::error::Error + Send + Sync + 'static,
{
    pub fn new<F, Fut>(factory: F) -> Self
    where
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<H3Connection<T>, E>> + Send + 'static,
    {
        Self::with_config(factory, PoolConfig::default())
    }

    pub fn with_config<F, Fut>(factory: F, config: PoolConfig) -> Self
    where
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<H3Connection<T>, E>> + Send + 'static,
    {
        Self {
            inner: Arc::new(PoolInner {
                factory: Box::new(move |key| Box::pin(factory(key))),
                config,
                state: Mutex::new(PoolState {
                    accepting: true,
                    connecting: HashMap::new(),
                    connections: HashMap::new(),
                    draining: HashMap::new(),
                    active_builds: 0,
                }),
                shutdown_complete: watch::channel(false).0,
            }),
        }
    }

    /// Reuse or construct a connection. This does not retry or replay requests.
    pub async fn get(&self, key: &K) -> PoolResult<H3Connection<T>, E> {
        let (record, creator) = {
            let mut state = self.inner.state.lock().unwrap();
            if !state.accepting {
                return Err(PoolError::Closed);
            }
            if let Some(connection) = state.connections.get(key) {
                if connection.is_reusable() {
                    return Ok(connection.clone());
                }
                self.inner.retire(&mut state, key);
            }
            if let Some(record) = state.connecting.get(key) {
                (record.clone(), false)
            } else {
                let record = Arc::new(Connecting {
                    result: watch::channel(None).0,
                });
                state.connecting.insert(key.clone(), record.clone());
                state.active_builds += 1;
                (record, true)
            }
        };
        if creator {
            // Declare before the factory future so cancellation drops its resources
            // before decrementing active_builds (including panic during factory call).
            let _guard = BuildGuard {
                inner: &self.inner,
                key,
                record: &record,
            };
            let result = {
                let future = (self.inner.factory)(key.clone());
                tokio::select! {
                    biased;
                    revoked = record.wait() => revoked,
                    result = tokio::time::timeout(self.inner.config.connect_timeout, future) => {
                        match result {
                            Ok(result) => result.map_err(|error| PoolError::Connect(Arc::new(error))),
                            Err(_) => Err(PoolError::ConnectTimeout),
                        }
                    }
                }
            };
            let mut rejected = None;
            {
                let mut state = self.inner.state.lock().unwrap();
                let current = state
                    .connecting
                    .get(key)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &record));
                let result = match result {
                    Ok(connection) => {
                        if !state.accepting || !current || !connection.is_reusable() {
                            let _ = connection.transport.close(
                                "unpublished pool connection".into(),
                                ErrorCode::H3_NO_ERROR.as_u64(),
                            );
                            rejected = Some(connection);
                            Err(if !state.accepting {
                                PoolError::Closed
                            } else if !current {
                                PoolError::Removed
                            } else {
                                PoolError::Unusable
                            })
                        } else {
                            self.inner.observe(key.clone(), connection.clone());
                            state.connections.insert(key.clone(), connection.clone());
                            Ok(connection)
                        }
                    }
                    Err(error) => Err(error),
                };
                if current {
                    state.connecting.remove(key);
                }
                record.finish(result);
            }
            if let Some(connection) = rejected {
                let error = connection.transport.terminated().await;
                connection.on_terminated(error);
            }
        }
        let connection = record.wait().await?;
        if connection.is_reusable() {
            Ok(connection)
        } else {
            Err(PoolError::Unusable)
        }
    }

    /// Revoke the current build or remove the connection from reuse and start GOAWAY.
    /// Existing handles can still open streams until peer GOAWAY or transport close.
    /// Returns false when only older, already draining connections remain.
    pub fn remove(&self, key: &K) -> bool {
        let mut state = self.inner.state.lock().unwrap();
        if let Some(record) = state.connecting.remove(key) {
            record.finish(Err(PoolError::Removed));
            true
        } else {
            self.inner.retire(&mut state, key)
        }
    }

    /// Permanently stop allocation and wait for builds and connection cleanup.
    /// Cancellation only cancels this waiter; shutdown continues independently.
    pub async fn shutdown(&self) {
        {
            let mut state = self.inner.state.lock().unwrap();
            state.accepting = false;
            for (_, record) in state.connecting.drain() {
                record.finish(Err(PoolError::Closed));
            }
            let keys: Vec<_> = state.connections.keys().cloned().collect();
            for key in keys {
                self.inner.retire(&mut state, &key);
            }
            self.inner.check_shutdown(&state);
        }
        let mut complete = self.inner.shutdown_complete.subscribe();
        let _ = complete.wait_for(|done| *done).await;
    }
}

impl<K, T, E> PoolInner<K, T, E>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    T: Transport,
    E: std::error::Error + Send + Sync + 'static,
{
    fn retire(&self, state: &mut PoolState<K, T, E>, key: &K) -> bool {
        let Some(connection) = state.connections.remove(key) else {
            return false;
        };
        // Removing the entry under the pool lock retires each generation once.
        connection.cursor.local_goaway();
        tokio::spawn({
            let connection = connection.clone();
            async move {
                tokio::select! {
                    biased;
                    _ = connection.transport.terminated() => {},
                    result = connection.clone().goaway() => {
                        if let Err(error) = result {
                            let _ = connection.transport.close(error.reason, error.code.as_u64());
                        }
                    }
                }
            }
        });
        state
            .draining
            .entry(key.clone())
            .or_default()
            .push(Draining {
                connection,
                deadline: self
                    .config
                    .drain_timeout
                    .map(|timeout| Instant::now() + timeout),
            });
        true
    }

    fn observe(self: &Arc<Self>, key: K, connection: H3Connection<T>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            connection.unusable().await;
            let deadline = {
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let mut state = inner.state.lock().unwrap();
                if state
                    .connections
                    .get(&key)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.transport, &connection.transport))
                {
                    inner.retire(&mut state, &key);
                }
                let Some(entry) = state.draining.get(&key).and_then(|entries| {
                    entries.iter().find(|entry| {
                        Arc::ptr_eq(&entry.connection.transport, &connection.transport)
                    })
                }) else {
                    return;
                };
                entry.deadline
            };
            let error = if let Some(deadline) = deadline {
                match tokio::time::timeout_at(deadline, connection.transport.terminated()).await {
                    Ok(error) => error,
                    Err(_) => {
                        let _ = connection.transport.close(
                            "pool drain deadline reached".into(),
                            ErrorCode::H3_NO_ERROR.as_u64(),
                        );
                        connection.transport.terminated().await
                    }
                }
            } else {
                connection.transport.terminated().await
            };
            connection.on_terminated(error);
            if let Some(inner) = weak.upgrade() {
                let mut state = inner.state.lock().unwrap();
                if let Some(entries) = state.draining.get_mut(&key) {
                    entries.retain(|entry| {
                        !Arc::ptr_eq(&entry.connection.transport, &connection.transport)
                    });
                    if entries.is_empty() {
                        state.draining.remove(&key);
                    }
                }
                inner.check_shutdown(&state);
            }
        });
    }

    fn check_shutdown(&self, state: &PoolState<K, T, E>) {
        if !state.accepting
            && state.active_builds == 0
            && state.connecting.is_empty()
            && state.connections.is_empty()
            && state.draining.is_empty()
        {
            self.shutdown_complete.send_replace(true);
        }
    }
}

struct BuildGuard<'a, K, T, E>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    T: Transport,
    E: std::error::Error + Send + Sync + 'static,
{
    inner: &'a Arc<PoolInner<K, T, E>>,
    key: &'a K,
    record: &'a Arc<Connecting<T, E>>,
}

impl<K, T, E> Drop for BuildGuard<'_, K, T, E>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    T: Transport,
    E: std::error::Error + Send + Sync + 'static,
{
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap();
        if state
            .connecting
            .get(self.key)
            .is_some_and(|entry| Arc::ptr_eq(entry, self.record))
        {
            state.connecting.remove(self.key);
        }
        self.record.finish(Err(PoolError::BuildCancelled));
        state.active_builds -= 1;
        self.inner.check_shutdown(&state);
    }
}

impl<K, T: Transport, E> Drop for PoolInner<K, T, E> {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for record in state.connecting.values() {
            record.finish(Err(PoolError::Closed));
        }
        for connection in state.connections.values().chain(
            state
                .draining
                .values()
                .flatten()
                .map(|entry| &entry.connection),
        ) {
            let _ = connection.transport.close(
                "connection pool dropped".into(),
                ErrorCode::H3_NO_ERROR.as_u64(),
            );
        }
    }
}
