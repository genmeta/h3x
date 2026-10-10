//! Shared, identity-keyed connections with one outbound and one inbound slot.
use std::{future::Future, hash::Hash, pin::Pin, sync::Arc};

use dashmap::{DashMap, mapref::entry::Entry};
use tokio::sync::OnceCell;

use crate::{H3Connection, Transport, UnreusableCallback};

type ConnectFuture<T, E> = Pin<Box<dyn Future<Output = Result<H3Connection<T>, E>> + Send>>;
type Factory<K, T, E> = dyn Fn(K, UnreusableCallback<T>) -> ConnectFuture<T, E> + Send + Sync;
// The first slot serializes outbound construction; the second holds one accepted connection.
type ConnectionSlots<T> = (Arc<OnceCell<H3Connection<T>>>, Option<H3Connection<T>>);

pub struct Pool<K: Eq + Hash, T: Transport, E = crate::Error> {
    inner: Arc<PoolInner<K, T, E>>,
}

struct PoolInner<K: Eq + Hash, T: Transport, E> {
    factory: Box<Factory<K, T, E>>,
    connections: DashMap<K, ConnectionSlots<T>>,
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
                connections: DashMap::new(),
            }),
        }
    }

    /// Reuse either established direction for opening or accepting streams;
    /// construct an outbound connection only when neither slot is ready.
    /// Construction is serialized per key.
    pub async fn get(&self, key: &K) -> Result<H3Connection<T>, E> {
        let outbound = {
            let mut entry = self
                .inner
                .connections
                .entry(key.clone())
                .or_insert_with(|| (Arc::new(OnceCell::new()), None));
            if let Some(connection) = entry.0.get() {
                if connection.is_reusable() {
                    return Ok(connection.clone());
                }
                entry.0 = Arc::new(OnceCell::new());
            }
            if let Some(connection) = &entry.1 {
                if connection.is_reusable() {
                    return Ok(connection.clone());
                }
                entry.1 = None;
            }
            entry.0.clone()
        };
        match outbound
            .get_or_try_init(|| async {
                (self.inner.factory)(key.clone(), self.outbound_callback(key.clone(), &outbound))
                    .await
            })
            .await
        {
            Ok(connection) => Ok(connection.clone()),
            Err(error) => {
                if let Some(connection) = self
                    .inner
                    .connections
                    .get(key)
                    .and_then(|entry| entry.1.clone().filter(H3Connection::is_reusable))
                {
                    Ok(connection)
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Create a callback to pass to `H3Connection::new` before inserting an inbound connection.
    /// Only the matching connection is removed; replacements and the other direction survive.
    pub fn on_unreusable(&self, key: K) -> UnreusableCallback<T> {
        let weak = Arc::downgrade(&self.inner);
        Box::new(move |connection| {
            if let Some(inner) = weak.upgrade() {
                Self { inner }.remove_connection(&key, connection);
            }
        })
    }

    /// Register one accepted connection constructed with `self.on_unreusable(key.clone())`.
    /// An already unusable connection is returned without entering the pool.
    /// A later accepted connection
    /// is returned to its caller to serve and close outside the reuse pool.
    pub fn insert(&self, key: K, connection: H3Connection<T>) -> Result<(), H3Connection<T>> {
        {
            let mut entry = self
                .inner
                .connections
                .entry(key.clone())
                .or_insert_with(|| (Arc::new(OnceCell::new()), None));
            if !connection.is_reusable() {
                return Err(connection);
            }
            if entry
                .1
                .as_ref()
                .is_some_and(|current| !current.is_reusable())
            {
                entry.1 = None;
            }
            if entry.1.is_some()
                || entry
                    .0
                    .get()
                    .is_some_and(|outbound| Arc::ptr_eq(&outbound.transport, &connection.transport))
            {
                return Err(connection);
            }
            entry.1 = Some(connection.clone());
        }
        Ok(())
    }

    /// Remove both ready slots and return their handles for shutdown.
    pub fn drain(&self) -> Vec<H3Connection<T>> {
        let keys = self
            .inner
            .connections
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        keys.into_iter()
            .filter_map(|key| self.inner.connections.remove(&key))
            .flat_map(|(_, (outbound, inbound))| outbound.get().cloned().into_iter().chain(inbound))
            .collect()
    }

    /// Remove both slots for a key from reuse. Existing handles remain valid.
    pub fn remove(&self, key: &K) -> bool {
        self.inner.connections.remove(key).is_some()
    }

    /// Remove only the matching connection, leaving the other direction intact.
    /// A later replacement and a rejected duplicate are left untouched.
    pub fn remove_connection(&self, key: &K, connection: &H3Connection<T>) -> bool {
        let Entry::Occupied(mut entry) = self.inner.connections.entry(key.clone()) else {
            return false;
        };
        let slots = entry.get_mut();
        let mut removed = false;
        if slots
            .1
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.transport, &connection.transport))
        {
            slots.1 = None;
            removed = true;
        }
        if slots
            .0
            .get()
            .is_some_and(|current| Arc::ptr_eq(&current.transport, &connection.transport))
        {
            slots.0 = Arc::new(OnceCell::new());
            removed = true;
        }
        if removed
            && slots.1.is_none()
            && slots.0.get().is_none()
            && Arc::strong_count(&slots.0) == 1
        {
            entry.remove();
        }
        removed
    }

    fn outbound_callback(
        &self,
        key: K,
        slot: &Arc<OnceCell<H3Connection<T>>>,
    ) -> UnreusableCallback<T> {
        let weak = Arc::downgrade(&self.inner);
        let slot = Arc::downgrade(slot);
        Box::new(move |_| {
            if let Some(inner) = weak.upgrade()
                && let Some(slot) = slot.upgrade()
                && let Entry::Occupied(mut entry) = inner.connections.entry(key.clone())
                && Arc::ptr_eq(&entry.get().0, &slot)
            {
                if entry.get().1.is_some() {
                    entry.get_mut().0 = Arc::new(OnceCell::new());
                } else {
                    entry.remove();
                }
            }
        })
    }
}
