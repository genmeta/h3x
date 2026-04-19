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
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use super::identity::{NamedIdentity, ServerName};
use crate::dquic::prelude::Connection;

/// Per-SNI entry stored behind a `Weak` in the network's registry.
///
/// Holds an mpmc channel so multiple [`ServerBinding`] clones share the
/// same inbound connection queue.
pub(crate) struct SniEntry {
    pub(crate) named_identity: Arc<NamedIdentity>,
    pub(crate) certified_key: Arc<CertifiedKey>,
    pub(crate) incomings_tx: async_channel::Sender<Arc<Connection>>,
    pub(crate) incomings_rx: async_channel::Receiver<Arc<Connection>>,
    /// Keeps the shared server slot alive for the lifetime of this entry.
    pub(crate) _slot: Arc<ServerSlotInner>,
    /// Shared guard — cloned into every `ServerBinding`. When the last
    /// clone drops, the entry is removed from `sni_registry`.
    pub(crate) guard: Arc<SniGuard>,
}

/// RAII guard that removes an SNI entry from the registry when the last
/// [`ServerBinding`] referencing it is dropped.
pub(crate) struct SniGuard {
    pub(crate) name: ServerName,
    pub(crate) registry: Weak<DashMap<ServerName, Weak<SniEntry>>>,
}

impl Drop for SniGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.remove(&self.name);
        }
    }
}

/// Shared server-side QUIC/TLS context. At most one instance exists per
/// [`Network`](super::Network) at any time; identical instances are shared
/// across all registered SNIs, and conflicting configurations are rejected
/// at `bind_server` time.
pub(crate) struct ServerSlotInner {
    pub(crate) config: super::config::ServerQuicConfig,
    pub(crate) rustls_config: Arc<rustls::ServerConfig>,
}

/// Public handle returned by [`Network::bind_server`](super::Network::bind_server).
///
/// Cloning is cheap and yields a new receiver on the **same** mpmc queue —
/// concurrently calling `recv` from multiple clones fans out inbound
/// connections across the clones without duplicating work.
pub struct ServerBinding {
    /// Server name this binding was registered under.
    pub name: ServerName,
    pub(crate) entry: Arc<SniEntry>,
    pub(crate) _guard: Arc<SniGuard>,
}

impl Clone for ServerBinding {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            entry: self.entry.clone(),
            _guard: self._guard.clone(),
        }
    }
}

impl std::fmt::Debug for ServerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBinding")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl ServerBinding {
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
    pub(crate) registry: Weak<DashMap<ServerName, Weak<SniEntry>>>,
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
        // DashMap keys are ASCII-normalised only if callers do so; we iterate
        // to match case-insensitively.
        for item in registry.iter() {
            if item.key().eq_ignore_ascii_case(sni)
                && let Some(entry) = item.value().upgrade()
            {
                return Some(entry.certified_key.clone());
            }
        }
        None
    }
}
