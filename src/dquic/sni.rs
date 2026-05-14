//! Per-SNI server state used by [`Network`](super::Network) to fan out
//! incoming connections across many [`QuicEndpoint`](super::QuicEndpoint)
//! instances.
//!
//! A [`ServerBinding`] is cheap to clone: each clone shares the same
//! mpmc [`async_channel`] tail, so multiple endpoints that registered the
//! same SNI cooperatively drain inbound connections. Dropping the last
//! strong reference unregisters the SNI entry from the network.

use std::sync::{Arc, Weak};

use dashmap::DashMap;
use dhttp_identity::Name;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::dquic::{
    binds::BindPattern,
    connection::Connection,
    identity::Identity,
};

/// Per-SNI entry stored behind a `Weak` in the network's registry.
///
/// Holds an mpmc channel so multiple [`ServerBinding`] clones share the
/// same inbound connection queue.
pub(crate) struct ServerEntry {
    pub(crate) identity: Arc<Identity>,
    pub(crate) certified_key: Arc<CertifiedKey>,
    pub(crate) incomings_tx: async_channel::Sender<Arc<Connection>>,
    pub(crate) incomings_rx: async_channel::Receiver<Arc<Connection>>,
    /// Shared server-side QUIC/TLS configuration for this entry.
    pub(crate) config: Arc<ServerConfig>,
    /// Shared guard — cloned into every `ServerBinding`. When the last
    /// clone drops, the entry is removed from `sni_registry`.
    pub(crate) guard: Arc<RegistryGuard>,
    /// Bind patterns associated with this server entry.
    pub(crate) bind: Arc<Vec<BindPattern>>,
}

/// RAII guard that removes an SNI entry from the registry when the last
/// [`ServerBinding`] referencing it is dropped.
pub(crate) struct RegistryGuard {
    pub(crate) name: Name<'static>,
    pub(crate) registry: Weak<DashMap<Name<'static>, Weak<ServerEntry>>>,
    pub(crate) self_entry: Weak<ServerEntry>,
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade()
            && let Some(kv) = registry.get(&self.name)
            && let Some(current_entry) = kv.value().upgrade()
            && Weak::ptr_eq(&self.self_entry, &Arc::downgrade(&current_entry))
        {
            drop(kv);
            registry.remove(&self.name);
        }
    }
}

/// Shared server-side QUIC/TLS context. At most one instance exists per
/// [`Network`](super::Network) at any time; identical instances are shared
/// across all registered SNIs, and conflicting configurations are rejected
/// at `bind_server` time.
pub(crate) struct ServerConfig {
    pub(crate) config: crate::dquic::server::ServerQuicConfig,
    pub(crate) rustls_config: Arc<rustls::ServerConfig>,
}

/// Public handle returned by [`Network::bind_server`](super::Network::bind_server).
///
/// Cloning is cheap and yields a new receiver on the **same** mpmc queue —
/// concurrently calling `recv` from multiple clones fans out inbound
/// connections across the clones without duplicating work.
pub struct ServerBinding {
    pub(crate) entry: Arc<ServerEntry>,
}

impl Clone for ServerBinding {
    fn clone(&self) -> Self {
        Self {
            entry: self.entry.clone(),
        }
    }
}

impl std::fmt::Debug for ServerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBinding")
            .field("name", &self.entry.identity.name)
            .finish_non_exhaustive()
    }
}

impl ServerBinding {
    /// Return the server name this binding was registered under.
    pub fn name(&self) -> &Name<'static> {
        &self.entry.identity.name
    }

    /// Receive the next accepted connection for this SNI.
    ///
    /// Returns `None` once the network is shut down or has no remaining
    /// senders.
    pub async fn recv(&self) -> Option<Arc<Connection>> {
        self.entry.incomings_rx.recv().await.ok()
    }
}

/// rustls `ResolvesServerCert` backed by the network's SNI registry.
///
/// SNI names are matched ASCII case-insensitively per RFC 6066 §3.
#[derive(Clone)]
pub(crate) struct SniCertResolver {
    pub(crate) registry: Weak<DashMap<Name<'static>, Weak<ServerEntry>>>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let registry = self.registry.upgrade()?;
        let sni = client_hello.server_name()?;
        let sni_lower = sni.to_ascii_lowercase();
        registry
            .get::<str>(&sni_lower)
            .and_then(|item| item.value().upgrade())
            .map(|entry| entry.certified_key.clone())
    }
}
