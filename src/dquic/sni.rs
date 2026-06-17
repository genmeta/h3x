//! Per-SNI server state used by [`QuicBindDriver`](super::QuicBindDriver) to
//! fan out incoming connections across many
//! [`QuicEndpoint`](super::QuicEndpoint) instances.
//!
//! A [`ServerBinding`] is cheap to clone: each clone shares the same
//! mpmc [`async_channel`] tail, so multiple endpoints that registered the
//! same SNI cooperatively drain inbound connections. Dropping the last
//! strong reference unregisters the SNI entry from the QUIC driver.

use std::sync::{Arc, Weak};

use dashmap::DashMap;
use dhttp_identity::name::Name;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::dquic::{binds::BindPattern, connection::Connection, identity::Identity};

/// Per-SNI entry stored behind a `Weak` in the QUIC driver's registry.
///
/// Holds an mpmc channel so multiple [`ServerBinding`] clones share the
/// same inbound connection queue.
pub(crate) struct ServerEntry {
    pub(crate) identity: Arc<Identity>,
    pub(crate) certified_key: Arc<CertifiedKey>,
    pub(crate) incomings_tx: async_channel::Sender<Arc<Connection>>,
    pub(crate) incomings_rx: async_channel::Receiver<Arc<Connection>>,
    /// Shared server-side QUIC/TLS configuration for this entry.
    #[allow(
        dead_code,
        reason = "held to keep the shared server configuration alive for this SNI entry"
    )]
    pub(crate) config: Arc<ServerConfig>,
    /// Shared guard — dropped with the entry to remove it from `sni_registry`.
    #[allow(
        dead_code,
        reason = "held for RAII SNI unregister when the last entry reference drops"
    )]
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
        if let Some(registry) = self.registry.upgrade() {
            registry.remove_if(&self.name, |_name, entry| {
                Weak::ptr_eq(&self.self_entry, entry)
            });
        }
    }
}

/// Shared server-side QUIC/TLS context. At most one instance exists per
/// [`QuicBindDriver`](super::QuicBindDriver) at any time; identical instances
/// are shared across all registered SNIs, and conflicting configurations are
/// rejected at `bind_server` time.
pub(crate) struct ServerConfig {
    pub(crate) config: crate::dquic::server::ServerQuicConfig,
    pub(crate) rustls_config: Arc<rustls::ServerConfig>,
    pub(crate) handshake_backlog: Arc<tokio::sync::Semaphore>,
}

/// Public handle returned by
/// [`QuicBindDriver::bind_server`](super::QuicBindDriver::bind_server).
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

/// rustls `ResolvesServerCert` backed by the QUIC driver's SNI registry.
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

#[cfg(test)]
mod tests {
    use dquic::prelude::handy::{ToCertificate, ToPrivateKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::dquic::{
        identity::{self, Identity},
        server::ServerQuicConfig,
    };

    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn make_identity(name: &str) -> Arc<Identity> {
        let certs: Vec<CertificateDer<'static>> = SERVER_CERT.to_certificate();
        let key: PrivateKeyDer<'static> = SERVER_KEY.to_private_key();
        Arc::new(Identity {
            name: name.parse().expect("valid identity name"),
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        })
    }

    fn make_server_entry(
        registry: &Arc<DashMap<Name<'static>, Weak<ServerEntry>>>,
        name: &str,
    ) -> Arc<ServerEntry> {
        let identity = make_identity(name);
        let certified_key = identity::build_certified_key(&identity).expect("test key should load");
        let entry_name = identity.name.clone();
        let (incomings_tx, incomings_rx) = async_channel::bounded(1);
        let config = Arc::new(ServerConfig {
            config: ServerQuicConfig::default(),
            rustls_config: Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(SniCertResolver {
                        registry: Weak::new(),
                    })),
            ),
            handshake_backlog: Arc::new(tokio::sync::Semaphore::new(1)),
        });

        Arc::new_cyclic(|self_entry| ServerEntry {
            identity: identity.clone(),
            certified_key,
            incomings_tx,
            incomings_rx,
            config,
            guard: Arc::new(RegistryGuard {
                name: entry_name.clone(),
                registry: Arc::downgrade(registry),
                self_entry: self_entry.clone(),
            }),
            bind: Arc::new(Vec::new()),
        })
    }

    #[tokio::test]
    async fn server_binding_exposes_name_debug_and_closed_receive() {
        let registry = Arc::new(DashMap::new());
        let entry = make_server_entry(&registry, "test.example.com");
        let binding = ServerBinding {
            entry: entry.clone(),
        };
        let cloned = binding.clone();

        assert_eq!(binding.name().as_str(), "test.example.com");
        assert!(
            format!("{binding:?}").contains("test.example.com"),
            "debug output should include binding name",
        );
        assert!(Arc::ptr_eq(&binding.entry, &cloned.entry));

        entry.incomings_tx.close();
        assert!(binding.recv().await.is_none());
    }

    #[test]
    fn registry_guard_removes_current_entry_on_last_drop() {
        let registry = Arc::new(DashMap::new());
        let name: Name<'static> = "test.example.com".parse().expect("valid name");
        let entry = make_server_entry(&registry, "test.example.com");
        registry.insert(name.clone(), Arc::downgrade(&entry));

        assert!(registry.get(&name).is_some());
        drop(entry);
        assert!(registry.get(&name).is_none());
    }

    #[test]
    fn registry_guard_keeps_replaced_entry() {
        let registry = Arc::new(DashMap::new());
        let name: Name<'static> = "test.example.com".parse().expect("valid name");
        let first = make_server_entry(&registry, "test.example.com");
        registry.insert(name.clone(), Arc::downgrade(&first));
        let second = make_server_entry(&registry, "test.example.com");
        registry.insert(name.clone(), Arc::downgrade(&second));

        drop(first);
        let current = registry
            .get(&name)
            .and_then(|entry| entry.value().upgrade())
            .expect("replacement entry should remain");
        assert!(Arc::ptr_eq(&current, &second));

        drop(current);
        drop(second);
        assert!(registry.get(&name).is_none());
    }

    #[test]
    fn sni_resolver_debug_is_non_exhaustive() {
        let resolver = SniCertResolver {
            registry: Weak::new(),
        };
        assert_eq!(format!("{resolver:?}"), "SniCertResolver { .. }");
    }
}
