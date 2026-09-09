use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::sync::watch;

use super::native::{Connected, Connection, Key, Runtime};
use crate::{Endpoint, Error};

/// Bounded connection cache. Runtime owns identity, networking and service tasks.
#[derive(Default)]
pub struct Pool {
    entries: Mutex<HashMap<Key, Entry>>,
}
#[derive(Clone)]
pub(super) enum Entry {
    Connecting {
        waiters: watch::Receiver<Option<Connected>>,
    },
    Ready(Arc<Connection>),
}
impl Entry {
    pub(super) fn is_live(&self) -> bool {
        match self {
            Self::Connecting { waiters } => waiters.has_changed().is_ok(),
            Self::Ready(connection) => !connection.is_draining(),
        }
    }
}
impl Pool {
    /// Convenience access to the process runtime's cache.
    pub async fn get(local: Option<Arc<Endpoint>>, target: &str) -> Result<Arc<Connection>, Error> {
        Runtime::get(local, target).await
    }
}

pub(super) type Publisher = watch::Sender<Option<Connected>>;

const MAX_ENTRIES: usize = 1024;
const MAX_PENDING: usize = 64;

impl Pool {
    pub(super) fn reserve(&self, key: &Key) -> Result<(Entry, Option<Publisher>), Error> {
        let mut entries = self.entries.lock().unwrap();
        // ponytail: scan at most 1024 entries; index expiry only if profiling requires it.
        entries.retain(|_, entry| entry.is_live());
        if let Some(entry) = entries.get(key) {
            return Ok((entry.clone(), None));
        }
        if entries.len() >= MAX_ENTRIES
            || entries
                .values()
                .filter(|e| matches!(e, Entry::Connecting { .. }))
                .count()
                >= MAX_PENDING
        {
            return Err(Error::Capacity);
        }
        let (publish, waiters) = watch::channel(None);
        let entry = Entry::Connecting { waiters };
        entries.insert(key.clone(), entry.clone());
        Ok((entry, Some(publish)))
    }

    pub(super) fn complete(&self, key: Key, result: &Connected) {
        let mut entries = self.entries.lock().unwrap();
        match result {
            Ok(connection) => {
                entries.insert(key, Entry::Ready(connection.clone()));
            }
            Err(_) => {
                entries.remove(&key);
            }
        }
    }

    pub(super) fn admit(&self, key: Key, connection: Arc<Connection>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, entry| entry.is_live());
        if entries.contains_key(&key) || entries.len() >= MAX_ENTRIES || connection.is_draining() {
            return false;
        }
        entries.insert(key, Entry::Ready(connection));
        true
    }

    pub(super) fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalized_targets_preserve_constraints_and_local_identity_partitioning() {
        let target = super::super::identity::normalize_name("peer.test.").unwrap();
        assert_eq!(target, "peer.test");
        for target in [
            "peer.test:443",
            "https://peer.test",
            "*.test",
            "peer.test/path",
            "peer.test?key=x",
            "peer.test#key",
        ] {
            assert!(
                super::super::identity::normalize_name(target).is_err(),
                "{target}"
            );
        }
        let pool = Pool::default();
        let mut publishers = Vec::new();
        for local in [
            None,
            Some("alice.test".to_owned()),
            Some("bob.test".to_owned()),
        ] {
            let key = (local, target.clone());
            publishers.push(pool.reserve(&key).unwrap().1.unwrap());
            assert!(pool.reserve(&key).unwrap().1.is_none());
        }
        assert_eq!(pool.entries.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn shared_dial_capacity_and_failed_dial_cleanup() {
        let pool = Pool::default();
        let key = (None, "bob.dhttp.net".to_owned());
        let (_, publish) = pool.reserve(&key).unwrap();
        let publish = publish.unwrap();
        let (entry, duplicate) = pool.reserve(&key).unwrap();
        assert!(duplicate.is_none());
        let Entry::Connecting { mut waiters } = entry else {
            panic!("dial is pending")
        };
        publish.send_replace(Some(Err(Error::TimedOut)));
        assert!(matches!(
            waiters.wait_for(Option::is_some).await.unwrap().as_ref(),
            Some(Err(Error::TimedOut))
        ));
        pool.complete(key.clone(), &Err(Error::TimedOut));
        let (_, retry) = pool.reserve(&key).unwrap();
        assert!(retry.is_some());
        let mut senders = vec![retry.unwrap()];
        for i in 1..MAX_PENDING {
            senders.push(
                pool.reserve(&(None, format!("peer{i}.dhttp.net")))
                    .unwrap()
                    .1
                    .unwrap(),
            );
        }
        assert!(matches!(
            pool.reserve(&(None, "extra.dhttp.net".to_owned())),
            Err(Error::Capacity)
        ));
        drop(senders);
        assert!(pool.reserve(&(None, "extra.dhttp.net".to_owned())).is_ok());
    }
}
