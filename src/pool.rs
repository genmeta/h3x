//! Shared, identity-keyed connections with serialized construction per entry.
use std::{future::Future, hash::Hash, pin::Pin, sync::Arc};

use dashmap::DashMap;
use tokio::sync::OnceCell;

use crate::{H3Connection, Transport};

type ConnectFuture<T, E> = Pin<Box<dyn Future<Output = Result<H3Connection<T>, E>> + Send>>;
type Factory<K, T, E> = dyn Fn(K) -> ConnectFuture<T, E> + Send + Sync;

pub struct Pool<K: Eq + Hash, T: Transport, E = crate::Error> {
    inner: Arc<PoolInner<K, T, E>>,
}

struct PoolInner<K: Eq + Hash, T: Transport, E> {
    factory: Box<Factory<K, T, E>>,
    connections: DashMap<K, Arc<OnceCell<H3Connection<T>>>>,
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
        F: Fn(K) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<H3Connection<T>, E>> + Send + 'static,
    {
        Self {
            inner: Arc::new(PoolInner {
                factory: Box::new(move |key| Box::pin(factory(key))),
                connections: DashMap::new(),
            }),
        }
    }

    /// Reuse or construct a connection, serializing construction for this entry.
    /// No DashMap shard lock is held across an await.
    pub async fn get(&self, key: &K) -> Result<H3Connection<T>, E> {
        let entry = self
            .inner
            .connections
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let connection = entry
            .get_or_try_init(|| async {
                let connection = (self.inner.factory)(key.clone()).await?;
                self.observe(key.clone(), entry.clone(), connection.clone());
                Ok::<_, E>(connection)
            })
            .await?;
        Ok(connection.clone())
    }

    /// Remove the entry from reuse. Existing handles and requests remain valid.
    /// Gets holding the removed entry may still complete and return its connection.
    /// They do not reinsert it or modify a replacement entry.
    pub fn remove(&self, key: &K) -> bool {
        self.inner.connections.remove(key).is_some()
    }

    fn observe(&self, key: K, entry: Arc<OnceCell<H3Connection<T>>>, connection: H3Connection<T>) {
        let weak = Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            connection.terminated().await;
            if let Some(inner) = weak.upgrade() {
                inner
                    .connections
                    .remove_if(&key, |_, current| Arc::ptr_eq(current, &entry));
            }
        });
    }
}
