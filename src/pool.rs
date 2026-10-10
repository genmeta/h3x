//! Shared, identity-keyed connections, independent of how they were established.
use std::{
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::{Arc, Mutex},
};

use dashmap::{DashMap, mapref::entry::Entry as MapEntry};
use tokio::sync::watch;

use crate::{ErrorCode, H3Connection, Transport, UnreusableCallback};

type ConnectFuture<T, E> = Pin<Box<dyn Future<Output = Result<H3Connection<T>, E>> + Send>>;
type Factory<K, T, E> = dyn Fn(K, UnreusableCallback<T>) -> ConnectFuture<T, E> + Send + Sync;
const MAX_CONNECTIONS: usize = 2;

// Pool admission must check protocol state as well as the asynchronous eviction
// callback: the driver may not have delivered that callback yet.
fn connection_error<T: Transport>(connection: &H3Connection<T>) -> Option<crate::Error> {
    if let Some(error) = connection.qpack().error() {
        return Some(error);
    }
    let streams = connection.bi_streams.lock().unwrap();
    if streams.local_not_goway().is_err() || streams.remote_no_goway().is_err() {
        Some(ErrorCode::RequestRejected.connection("connection is draining"))
    } else {
        None
    }
}

pub struct Pool<K: Eq + Hash, T: Transport, E = crate::Error> {
    inner: Arc<PoolInner<K, T, E>>,
}

struct PoolInner<K: Eq + Hash, T: Transport, E> {
    factory: Box<Factory<K, T, E>>,
    entries: DashMap<K, Arc<Mutex<Entry<T>>>>,
}

struct Entry<T: Transport> {
    ready: Vec<H3Connection<T>>,
    // Only the caller running the factory owns the sender. Closing it wakes
    // every waiter, including when that caller is cancelled or panics.
    connecting: Option<watch::Receiver<()>>,
}

impl<T: Transport> Entry<T> {
    fn new() -> Self {
        Self {
            ready: Vec::new(),
            connecting: None,
        }
    }

    fn reusable(&mut self) -> Option<H3Connection<T>> {
        self.ready
            .retain(|connection| connection_error(connection).is_none());
        self.ready.first().cloned()
    }

    fn insert(&mut self, connection: H3Connection<T>) -> Result<(), H3Connection<T>> {
        self.ready
            .retain(|connection| connection_error(connection).is_none());
        if connection_error(&connection).is_some()
            || self.ready.len() == MAX_CONNECTIONS
            || self
                .ready
                .iter()
                .any(|current| Arc::ptr_eq(&current.transport, &connection.transport))
        {
            return Err(connection);
        }
        self.ready.push(connection);
        Ok(())
    }
}

impl<K: Eq + Hash, T: Transport, E> Clone for Pool<K, T, E> {
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
    E: 'static,
{
    pub fn new<F, Fut>(factory: F) -> Self
    where
        F: Fn(K, UnreusableCallback<T>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<H3Connection<T>, E>> + Send + 'static,
    {
        Self {
            inner: Arc::new(PoolInner {
                factory: Box::new(move |key, callback| Box::pin(factory(key, callback))),
                entries: DashMap::new(),
            }),
        }
    }

    /// Reuse the first healthy connection, regardless of its origin.
    /// Only one factory runs per entry; accepted connections may enter while it runs.
    pub async fn get(&self, key: &K) -> Result<H3Connection<T>, E>
    where
        E: From<crate::Error>,
    {
        let entry = self
            .inner
            .entries
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(Entry::new())))
            .clone();
        let finished = loop {
            let mut waiting = {
                let mut entry = entry.lock().unwrap();
                if let Some(connection) = entry.reusable() {
                    return Ok(connection);
                }
                match &entry.connecting {
                    // No values are sent: an open channel means the factory is running.
                    Some(waiting) if waiting.has_changed().is_ok() => waiting.clone(),
                    _ => {
                        let (finished, waiting) = watch::channel(());
                        entry.connecting = Some(waiting);
                        break finished;
                    }
                }
            };
            // No lock is held while waiting. Channel closure is sticky, so a
            // factory completing before this await cannot lose the wakeup.
            let _ = waiting.changed().await;
        };
        let result = match (self.inner.factory)(key.clone(), self.on_unreusable(key.clone())).await
        {
            Ok(connection) => {
                // Publish into this entry only. remove/drain can detach it while building.
                // If accepted connections filled the cache, the caller owns this result.
                let _ = entry.lock().unwrap().insert(connection.clone());
                if let Some(error) = connection_error(&connection) {
                    self.remove_connection(key, &connection);
                    entry
                        .lock()
                        .unwrap()
                        .reusable()
                        .ok_or_else(|| E::from(error))
                } else {
                    Ok(connection)
                }
            }
            Err(error) => entry.lock().unwrap().reusable().ok_or(error),
        };
        drop(finished);
        // An early driver exit cannot remove a building entry. Clean it up now,
        // unless another get still holds it and may retry construction.
        if let MapEntry::Occupied(current) = self.inner.entries.entry(key.clone())
            && Arc::ptr_eq(current.get(), &entry)
            && Arc::strong_count(current.get()) == 2
            && entry.lock().unwrap().ready.is_empty()
        {
            current.remove();
        }
        result
    }

    /// Install before constructing an accepted connection. Both origins use this callback.
    /// Only the matching connection is removed; replacements and other connections survive.
    pub fn on_unreusable(&self, key: K) -> UnreusableCallback<T> {
        let weak = Arc::downgrade(&self.inner);
        Box::new(move |connection| {
            if let Some(inner) = weak.upgrade() {
                Self { inner }.remove_connection(&key, connection);
            }
        })
    }

    /// Cache an established, authenticated connection with the pool's callback installed.
    /// Unusable, duplicate, or excess connections are returned for the caller to manage.
    pub fn insert(&self, key: K, connection: H3Connection<T>) -> Result<(), H3Connection<T>> {
        if connection_error(&connection).is_some() {
            return Err(connection);
        }
        self.inner
            .entries
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(Entry::new())))
            .lock()
            .unwrap()
            .insert(connection)
    }

    /// Remove entries and return all cached connections for caller-managed shutdown.
    /// In-flight builds may still complete outside the pool; this is not a shutdown barrier.
    pub fn drain(&self) -> Vec<H3Connection<T>> {
        let keys = self
            .inner
            .entries
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| self.inner.entries.remove(&key))
            .flat_map(|(_, entry)| entry.lock().unwrap().ready.clone())
            .collect()
    }

    /// Remove an entry from reuse. Existing handles and in-flight calls remain valid.
    pub fn remove(&self, key: &K) -> bool {
        self.inner.entries.remove(key).is_some()
    }

    /// Remove only the matching connection, preserving replacements and pending construction.
    pub fn remove_connection(&self, key: &K, connection: &H3Connection<T>) -> bool {
        let MapEntry::Occupied(entry) = self.inner.entries.entry(key.clone()) else {
            return false;
        };
        let mut state = entry.get().lock().unwrap();
        let before = state.ready.len();
        state
            .ready
            .retain(|current| !Arc::ptr_eq(&current.transport, &connection.transport));
        let removed = state.ready.len() != before;
        let empty = state.ready.is_empty();
        drop(state);
        if empty && Arc::strong_count(entry.get()) == 1 {
            entry.remove();
        }
        removed
    }
}
