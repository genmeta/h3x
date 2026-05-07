//! Process-shared QUIC network infrastructure.
//!
//! [`Network`] owns the long-lived components needed to send and receive QUIC
//! packets on a set of network interfaces, **and** the SNI fan-out registry
//! used to route newly-accepted connections to per-identity
//! [`QuicEndpoint`](super::QuicEndpoint) listeners.
//!
//! A [`Network`] is always used via [`Arc<Network>`]: clone the [`Arc`] to
//! share the infrastructure between many endpoints. The builder returns an
//! [`Arc`] directly via [`Network::builder().build()`](Network::builder).
//!
//! ## SNI dispatch
//!
//! The builder installs a *connectionless packet dispatcher* on the network's
//! [`QuicRouter`]. When an Initial / 0-RTT packet arrives without matching
//! an existing connection, the dispatcher constructs a fresh server
//! [`Connection`](crate::dquic::prelude::Connection) using the shared
//! [`ServerQuicConfig`](super::ServerQuicConfig) stored in the network's
//! `server_slot`, waits for the handshake to reveal the ClientHello SNI, and
//! fans the connection into the matching [`ServerBinding`]'s mpmc queue.
//!
//! Because the underlying rustls `ServerConfig` must be chosen *before* SNI
//! is known, the network stores **one** `ServerQuicConfig` at a time. The
//! first call to [`Network::bind_server`] initialises the slot; subsequent
//! calls with an identical (or `Arc::ptr_eq`) configuration succeed, while
//! a conflicting configuration is rejected with
//! [`BindServerError::ServerConfigConflict`]. When the last [`ServerBinding`]
//! referring to the slot drops, the slot clears and a different configuration
//! may be used on the next bind.
//!
//! ## Binds registry
//!
//! [`Network::bind`] registers a [`BindPattern`] with reference counting.
//! Repeated calls with the same pattern increment the count; when every
//! returned [`BindHandle`] is dropped or [`BindHandle::unbind`] is called,
//! the count reaches zero and the bound interfaces are released.
//! A single background reconcile task (started at build time)
//! watches for device changes and keeps every pattern's bound interfaces in
//! sync.

use std::{
    collections::{HashMap, hash_map},
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
};

use dashmap::DashMap;
use snafu::Snafu;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

pub use super::sni::ServerBinding;
use super::{
    binds::BindPattern,
    identity::{Identity, ServerName},
    server::ServerQuicConfig,
    sni::{self, RegistryGuard, ServerConfig, ServerEntry, SniCertResolver},
};
use crate::dquic::{
    prelude::{
        AuthClient, ClientAgentVerifyResult, ClientNameVerifyResult, Connection, LocalAgent,
        RemoteAgent, Resolve,
        handy::{DEFAULT_IO_FACTORY, SystemResolver},
        qconnection::builder::ConnectionFoundation,
    },
    qbase::packet::Packet,
    qinterface::{
        BindInterface,
        bind_uri::BindUri,
        component::{
            location::Locations,
            route::{QuicRouter, Way},
        },
        device::Devices,
        io::ProductIO,
        manager::InterfaceManager,
    },
    qtraversal::route::ReceiveAndDeliverPacketComponent,
};

pub(crate) type SniRegistry = Arc<DashMap<ServerName, Weak<ServerEntry>>>;

/// Error returned by [`Network::bind_server`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BindServerError {
    /// Another [`Identity`] is already registered for the same SNI.
    #[snafu(display("sni {name} is already bound to a different identity"))]
    SniInUse {
        /// SNI that is already registered.
        name: ServerName,
    },
    /// The network already has a server configuration that is incompatible
    /// with the one provided. Drop every existing [`ServerBinding`] before
    /// binding with a different configuration.
    #[snafu(display("network already holds an incompatible server configuration"))]
    ServerConfigConflict,
    /// Loading the identity's private key into rustls failed.
    #[snafu(display("failed to load server private key"))]
    LoadKey {
        /// Underlying rustls error.
        source: rustls::Error,
    },
    /// rustls rejected the selected protocol version.
    #[snafu(display("failed to select TLS protocol version"))]
    Version {
        /// Underlying rustls error.
        source: rustls::Error,
    },
}

/// Shared QUIC network infrastructure.
///
/// Used exclusively via [`Arc<Network>`]. [`Network::builder().build()`](Network::builder)
/// returns an [`Arc`] directly after installing the SNI dispatcher on the router.
pub struct Network {
    #[expect(dead_code)]
    stun_resolver: Arc<dyn Resolve + Send + Sync>,
    #[expect(dead_code)]
    stun_server: Option<Arc<str>>,
    devices: &'static Devices,
    io_factory: Arc<dyn ProductIO + 'static>,
    iface_manager: Arc<InterfaceManager>,
    quic_router: Arc<QuicRouter>,
    locations: Arc<Locations>,
    bind_registry: Mutex<HashMap<BindPattern, BindsEntry>>,
    sni_registry: SniRegistry,
    server_slot: RwLock<Weak<sni::ServerConfig>>,
    dispatcher_installed: OnceLock<()>,
    _reconcile: OnceLock<AbortOnDropHandle<()>>,
}

struct BindsEntry {
    refcount: usize,
    /// Live bindings keyed by [`BindUri::identity_key`]. Holds strong
    /// [`BindInterface`] references so that the interfaces (and their
    /// installed components) stay alive. The inner lock is separate from
    /// the outer `bind_registry` mutex so the reconcile task can perform
    /// async bind/unbind without holding the registry lock.
    bound: Mutex<HashMap<String, (BindUri, BindInterface)>>,
}

/// RAII handle returned by [`Network::bind`].
///
/// The handle holds a reference-counted spot in the bind registry.
/// When all handles for a pattern are dropped, the bound interfaces
/// are released.
///
/// Prefer calling [`BindHandle::unbind`] to release synchronously.
/// If the handle is dropped without calling `unbind()`, the release
/// is spawned as a background task.
pub struct BindHandle {
    network: Arc<Network>,
    pattern: BindPattern,
    released: bool,
}

// ---------------------------------------------------------------------------
// Builder (bon)
// ---------------------------------------------------------------------------

#[bon::bon]
impl Network {
    #[builder(start_fn(name = builder, vis = "pub"), builder_type(vis = "pub"))]
    fn new(
        #[builder(default = Arc::new(SystemResolver))] stun_resolver: Arc<
            dyn Resolve + Send + Sync,
        >,
        stun_server: Option<Arc<str>>,
        #[builder(default = Devices::global())] devices: &'static Devices,
        #[builder(default = Arc::new(DEFAULT_IO_FACTORY))] io_factory: Arc<dyn ProductIO + 'static>,
        #[builder(default = InterfaceManager::global().clone())] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = QuicRouter::global().clone())] quic_router: Arc<QuicRouter>,
        #[builder(default = Arc::new(Locations::new()))] locations: Arc<Locations>,
    ) -> Arc<Self> {
        let network = Arc::new(Network {
            stun_resolver,
            stun_server,
            devices,
            io_factory,
            iface_manager,
            quic_router,
            locations,
            bind_registry: Mutex::new(HashMap::new()),
            sni_registry: Arc::new(DashMap::new()),
            server_slot: RwLock::new(Weak::new()),
            dispatcher_installed: OnceLock::new(),
            _reconcile: OnceLock::new(),
        });

        // Install the SNI dispatcher on the quic router. Only succeeds once;
        // subsequent builds on the same globally-shared router silently fail.
        let dispatcher_net = network.clone();
        let installed = network
            .quic_router
            .on_connectless_packets(move |packet, way| {
                Self::dispatch_initial_packet(dispatcher_net.clone(), packet, way)
            });
        tracing::debug!(installed, "sni dispatcher installation");
        let _ = network.dispatcher_installed.set(());

        // Start the background reconcile task that keeps bound interfaces
        // in sync with device changes.
        let reconcile_net = network.clone();
        let handle = tokio::spawn(
            async move {
                reconcile_net.run_reconcile().await;
            }
            .in_current_span(),
        );
        let _ = network._reconcile.set(AbortOnDropHandle::new(handle));

        network
    }
}

// ---------------------------------------------------------------------------
// Network methods
// ---------------------------------------------------------------------------

impl Network {
    /// Inject the network's shared components into a connection foundation
    /// builder.
    ///
    /// The caller continues to chain role-specific configuration after this
    /// call and finishes with `.with_cids(…)` / `.run()`.
    pub fn configure_connection<F, T>(
        &self,
        builder: ConnectionFoundation<F, T>,
    ) -> ConnectionFoundation<F, T> {
        builder
            .with_iface_manager(self.iface_manager.clone())
            .with_iface_factory(self.io_factory.clone())
            .with_quic_router(self.quic_router.clone())
            .with_locations(self.locations.clone())
    }

    /// Return a clone of the shared [`Locations`] component.
    pub fn locations(&self) -> Arc<Locations> {
        self.locations.clone()
    }

    /// Bind a specific [`BindUri`] directly without going through the
    /// pattern registry. Used internally by [`QuicEndpoint`] to acquire
    /// ephemeral client-side interfaces.
    pub(crate) async fn bind_iface(&self, bind_uri: BindUri) -> BindInterface {
        self.iface_manager
            .bind(bind_uri, self.io_factory.clone())
            .await
    }

    /// Register a server identity on the network's SNI fan-out.
    ///
    /// The first call initialises the shared server TLS context; later calls
    /// must use a compatible [`ServerQuicConfig`] (or the exact same
    /// `Arc`).  Returns a [`ServerBinding`] handle that receives accepted
    /// connections for this SNI.
    pub async fn bind_server(
        self: &Arc<Self>,
        identity: Arc<Identity>,
        server_config: ServerQuicConfig,
        bind_patterns: Arc<Vec<BindPattern>>,
    ) -> Result<ServerBinding, BindServerError> {
        use bind_server_error::*;

        let name = identity.name.clone();

        if let Some(kv) = self.sni_registry.get(&name)
            && let Some(existing) = kv.value().upgrade()
            && Arc::ptr_eq(&existing.identity, &identity)
        {
            let (_tx, rx) = async_channel::bounded(server_config.own.backlog);
            let binding = ServerBinding {
                entry: Arc::new(ServerEntry {
                    identity: existing.identity.clone(),
                    certified_key: existing.certified_key.clone(),
                    incomings_tx: existing.incomings_tx.clone(),
                    incomings_rx: rx,
                    config: existing.config.clone(),
                    guard: existing.guard.clone(),
                    bind_patterns: bind_patterns.clone(),
                }),
            };
            return Ok(binding);
        }

        let certified_key = identity.build_certified_key()?;

        use dashmap::mapref::entry::Entry;
        match self.sni_registry.entry(name.clone()) {
            Entry::Occupied(occupied) => match occupied.get().upgrade() {
                Some(existing) if Arc::ptr_eq(&existing.identity, &identity) => {
                    let binding = ServerBinding {
                        entry: Arc::new(ServerEntry {
                            identity: existing.identity.clone(),
                            certified_key: existing.certified_key.clone(),
                            incomings_tx: existing.incomings_tx.clone(),
                            incomings_rx: async_channel::bounded(server_config.own.backlog).1,
                            config: existing.config.clone(),
                            guard: existing.guard.clone(),
                            bind_patterns: bind_patterns.clone(),
                        }),
                    };
                    return Ok(binding);
                }
                Some(_) => {
                    drop(occupied);
                    self.sni_registry.remove(&name);
                }
                None => {
                    drop(occupied);
                    self.sni_registry.remove(&name);
                }
            },
            Entry::Vacant(_) => {}
        }

        let slot = {
            let slot_guard = self.server_slot.read().unwrap();
            if let Some(slot) = slot_guard.upgrade() {
                if !slot.config.is_compatible_with(&server_config) {
                    return ServerConfigConflictSnafu.fail();
                }
                slot
            } else {
                drop(slot_guard);
                let mut slot_guard = self.server_slot.write().unwrap();
                if let Some(slot) = slot_guard.upgrade() {
                    if !slot.config.is_compatible_with(&server_config) {
                        return ServerConfigConflictSnafu.fail();
                    }
                    slot
                } else {
                    let sni_registry_weak = Arc::downgrade(&self.sni_registry);
                    let resolver = SniCertResolver {
                        registry: sni_registry_weak,
                    };
                    let rustls_config =
                        Arc::new(server_config.build_rustls_server_config(resolver)?);
                    let slot = Arc::new(ServerConfig {
                        config: server_config.clone(),
                        rustls_config,
                    });
                    *slot_guard = Arc::downgrade(&slot);
                    slot
                }
            }
        };

        let (incomings_tx, incomings_rx) = async_channel::bounded(server_config.own.backlog);

        let guard = Arc::new(RegistryGuard {
            name: name.clone(),
            registry: Arc::downgrade(&self.sni_registry),
            self_entry: Weak::new(),
        });

        let entry = Arc::new_cyclic(|_weak_entry| ServerEntry {
            identity,
            certified_key,
            incomings_tx,
            incomings_rx,
            config: slot,
            guard: guard.clone(),
            bind_patterns: bind_patterns.clone(),
        });

        // Fix the guard's self_entry to point at the entry we just created.
        // Safety: guard's only strong reference is held here and in `entry`.
        // We use unsafe to get a mutable ref to the Arc's inner (unique).
        let guard_mut = unsafe { &mut *(Arc::as_ptr(&guard) as *mut RegistryGuard) };
        guard_mut.self_entry = Arc::downgrade(&entry);

        self.sni_registry
            .insert(name.clone(), Arc::downgrade(&entry));

        Ok(ServerBinding { entry })
    }

    /// Register a [`BindPattern`] and bind its matching interfaces.
    ///
    /// Returns a [`BindHandle`] that keeps the pattern alive. When all
    /// handles for a pattern are dropped (or [`BindHandle::unbind`] is
    /// called), the bound interfaces are released.
    pub async fn bind(self: &Arc<Self>, pattern: BindPattern) -> BindHandle {
        let bind_uris: Vec<BindUri> = {
            let iface_names: Vec<String> = self.devices.interfaces().keys().cloned().collect();
            let iface_strs: Vec<&str> = iface_names.iter().map(|s| s.as_str()).collect();
            pattern.to_bind_uris(iface_strs).collect()
        };

        // Collect URIs that need binding while holding both locks, so the
        // refcount is incremented before we drop the locks and perform async
        // bind operations.
        let needs_bind: Vec<BindUri> = {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            let entry = registry
                .entry(pattern.clone())
                .or_insert_with(|| BindsEntry {
                    refcount: 0,
                    bound: Mutex::new(HashMap::new()),
                });
            entry.refcount += 1;

            let bound = entry.bound.lock().expect("bound mutex poisoned");
            bind_uris
                .iter()
                .filter(|uri| !bound.contains_key(&uri.identity_key()))
                .cloned()
                .collect()
        }; // locks dropped before await

        // Perform async binds without holding any locks
        let mut new_ifaces: Vec<(String, BindUri, BindInterface)> =
            Vec::with_capacity(needs_bind.len());
        for uri in &needs_bind {
            let iface = self
                .iface_manager
                .bind(uri.clone(), self.io_factory.clone())
                .await;
            iface.insert_component_with(|iface| {
                ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                    .quic_router(self.quic_router.clone())
                    .init()
            });
            new_ifaces.push((uri.identity_key(), uri.clone(), iface));
        }

        // Re-acquire locks to store the new bindings
        if !new_ifaces.is_empty() {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            if let Some(entry) = registry.get_mut(&pattern) {
                let mut bound = entry.bound.lock().expect("bound mutex poisoned");
                for (key, uri, iface) in new_ifaces {
                    bound.insert(key, (uri, iface));
                }
            }
        }

        BindHandle {
            network: self.clone(),
            pattern,
            released: false,
        }
    }

    /// Release a previously registered [`BindPattern`] and its bound
    /// interfaces.
    pub(crate) async fn unbind(&self, pattern: &BindPattern) {
        let to_close: Vec<BindInterface> = {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            if let hash_map::Entry::Occupied(mut entry) = registry.entry(pattern.clone()) {
                entry.get_mut().refcount = entry.get().refcount.saturating_sub(1);
                if entry.get().refcount == 0 {
                    let removed = entry.remove();
                    removed
                        .bound
                        .into_inner()
                        .expect("bound mutex poisoned")
                        .into_values()
                        .map(|(_uri, iface)| iface)
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            }
        };

        for iface in to_close {
            iface.close().await.ok();
        }
    }

    /// Return all currently bound interfaces across all patterns.
    pub fn interfaces(&self) -> Vec<BindInterface> {
        let registry = self.bind_registry.lock().expect("bind_registry poisoned");
        registry
            .values()
            .flat_map(|entry| {
                let bound = entry.bound.lock().expect("bound mutex poisoned");
                bound
                    .values()
                    .map(|(_uri, iface)| iface.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Return the server names currently registered in the SNI registry.
    ///
    /// Only names with live [`ServerBinding`] handles are included; entries
    /// that have been dropped are automatically cleaned up by the [`RegistryGuard`]
    /// drop logic.
    pub fn registered_sni_names(&self) -> Vec<ServerName> {
        self.sni_registry
            .iter()
            .filter(|kv| kv.value().upgrade().is_some())
            .map(|kv| kv.key().clone())
            .collect()
    }

    /// Connectionless packet dispatcher installed on the [`QuicRouter`].
    ///
    /// Called for every Initial / 0-RTT packet that doesn't match an
    /// existing connection.  Spawns a new server [`Connection`] using the
    /// shared server slot, waits for the TLS handshake to reveal the SNI,
    /// and fans the connection into the matching [`ServerBinding`]'s queue.
    fn dispatch_initial_packet(network: Arc<Self>, packet: Packet, way: Way) {
        use crate::dquic::qbase::packet::{
            DataHeader,
            header::{self, GetDcid},
        };

        // === STEP 1: Filter — only Initial and 0-RTT packets ===
        let (bind_uri, pathway, link) = way;

        let data_packet = match &packet {
            Packet::Data(dp) => dp,
            Packet::VN(_) | Packet::Retry(_) => return,
        };

        let DataHeader::Long(long_header) = &data_packet.header else {
            return;
        };

        let (header::long::DataHeader::Initial(_) | header::long::DataHeader::ZeroRtt(_)) =
            long_header
        else {
            return;
        };

        let origin_dcid = *data_packet.dcid();

        // === STEP 2: Get slot synchronously (try_read, no await) ===
        let Some(slot) = network
            .server_slot
            .try_read()
            .ok()
            .and_then(|g| g.upgrade())
        else {
            return;
        };

        // === STEP 3: Build Connection synchronously — CID registered in QuicRouter NOW ===
        let sni_registry = network.sni_registry.clone();

        let foundation = Connection::new_server(slot.config.own.token_provider.clone())
            .with_parameters(slot.config.own.parameters.clone())
            .with_client_auther(Box::new((
                InterfaceAuthClient {
                    bind_uri: bind_uri.clone(),
                    sni_registry: sni_registry.clone(),
                },
                slot.config.own.client_auther.clone(),
            )))
            .with_tls_config((*slot.rustls_config).clone());

        let foundation = network.configure_connection(foundation);
        let foundation = foundation
            .with_streams_concurrency_strategy(slot.config.common.stream_strategy_factory.as_ref())
            .with_defer_idle_timeout(slot.config.common.defer_idle_timeout)
            .with_zero_rtt(slot.config.common.enable_0rtt);

        let conn = foundation
            .with_cids(origin_dcid)
            .with_qlog(slot.config.common.qlogger.clone())
            .run();

        let quic_router = network.quic_router.clone();

        // === STEP 4: Spawn only async work (deliver + wait for SNI + dispatch) ===
        tokio::spawn(
            async move {
                quic_router.deliver(packet, (bind_uri, pathway, link)).await;

                // server_name() waits for TLS handshake info — do NOT call
                // handshaked() here; for server role it blocks until a Data
                // packet arrives, which would deadlock the test until timeout.
                let sni = match conn.server_name().await {
                    Ok(name) => name,
                    Err(e) => {
                        let report = snafu::Report::from_error(&e);
                        tracing::debug!(
                            error = %report,
                            "failed to get server name"
                        );
                        return;
                    }
                };

                let sni_lower = sni.to_ascii_lowercase();
                if let Some(entry) = sni_registry
                    .get::<str>(&sni_lower)
                    .and_then(|item| item.value().upgrade())
                {
                    if entry.incomings_tx.send(conn).await.is_err() {
                        tracing::debug!(
                            name = %sni,
                            "sni channel closed"
                        );
                    }
                    return;
                }
                tracing::debug!(
                    name = %sni,
                    "no endpoint registered for SNI"
                );
            }
            .in_current_span(),
        );
    }
    /// Background task that reconciles bound interfaces with device changes.
    #[allow(clippy::type_complexity)]
    async fn run_reconcile(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let patterns: Vec<(BindPattern, HashMap<String, (BindUri, BindInterface)>)> = {
                let registry = self.bind_registry.lock().expect("bind_registry poisoned");
                registry
                    .iter()
                    .map(|(p, e)| {
                        let bound = e.bound.lock().expect("bound mutex poisoned");
                        (p.clone(), bound.clone())
                    })
                    .collect()
            };

            for (pattern, mut bound) in patterns {
                let iface_names: Vec<String> = self.devices.interfaces().keys().cloned().collect();
                let iface_strs: Vec<&str> = iface_names.iter().map(|s| s.as_str()).collect();
                let desired_uris: Vec<BindUri> = pattern.to_bind_uris(iface_strs).collect();

                let desired_keys: std::collections::HashSet<String> =
                    desired_uris.iter().map(|u| u.identity_key()).collect();
                bound.retain(|key, _| desired_keys.contains(key));

                for uri in &desired_uris {
                    let key = uri.identity_key();
                    if let std::collections::hash_map::Entry::Vacant(e) = bound.entry(key) {
                        let iface = self
                            .iface_manager
                            .bind(uri.clone(), self.io_factory.clone())
                            .await;
                        iface.insert_component_with(|iface| {
                            ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                                .quic_router(self.quic_router.clone())
                                .init()
                        });
                        e.insert((uri.clone(), iface));
                    }
                }

                if let Some(entry) = self
                    .bind_registry
                    .lock()
                    .expect("bind_registry poisoned")
                    .get(&pattern)
                {
                    *entry.bound.lock().expect("bound mutex poisoned") = bound;
                }
            }
        }
    }
}

/// AuthClient that filters connections based on whether the receiving
/// interface matches any of the server's registered BindPatterns.
struct InterfaceAuthClient {
    bind_uri: BindUri,
    sni_registry: SniRegistry,
}

impl AuthClient for InterfaceAuthClient {
    fn verify_client_name(
        &self,
        server_agent: &LocalAgent,
        _client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        let sni = server_agent.name();
        let sni_lower = sni.to_ascii_lowercase();
        let entry = self
            .sni_registry
            .get::<str>(&sni_lower)
            .and_then(|item| item.value().upgrade());

        match entry {
            None => ClientNameVerifyResult::SilentRefuse("no server registered for SNI".to_owned()),
            Some(entry) if entry.bind_patterns.is_empty() => ClientNameVerifyResult::Accept,
            Some(entry)
                if entry
                    .bind_patterns
                    .iter()
                    .any(|p| p.matches(&self.bind_uri)) =>
            {
                ClientNameVerifyResult::Accept
            }
            Some(_) => {
                ClientNameVerifyResult::SilentRefuse("bind pattern mismatch".to_owned())
            }
        }
    }

    fn verify_client_agent(
        &self,
        _server_agent: &LocalAgent,
        _client_agent: &RemoteAgent,
    ) -> ClientAgentVerifyResult {
        ClientAgentVerifyResult::Accept
    }
}

// ---------------------------------------------------------------------------
// BindHandle
// ---------------------------------------------------------------------------

impl BindHandle {
    /// Release the bind pattern synchronously.
    pub async fn unbind(&mut self) {
        if !self.released {
            self.network.unbind(&self.pattern).await;
            self.released = true;
        }
    }
}

impl Drop for BindHandle {
    fn drop(&mut self) {
        if !self.released {
            let network = self.network.clone();
            let pattern = self.pattern.clone();
            // Inherent termination: the spawned task exits after the unbind
            // completes. If the runtime is shutting down, the unbind is
            // best-effort.
            tokio::spawn(
                async move {
                    network.unbind(&pattern).await;
                }
                .in_current_span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::identity::Identity;

    fn make_identity(name: &str) -> Arc<Identity> {
        use dquic::prelude::handy::{ToCertificate, ToPrivateKey};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        let certs: Vec<CertificateDer<'static>> = SERVER_CERT.to_certificate();
        let key: PrivateKeyDer<'static> = SERVER_KEY.to_private_key();

        Arc::new(Identity {
            name: ServerName::new(name),
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        })
    }

    fn make_server_config() -> ServerQuicConfig {
        ServerQuicConfig::default()
    }

    #[tokio::test]
    async fn test_bind_server_overwrite() {
        let network = Network::builder().build();
        let identity_a = make_identity("test.example.com");
        let identity_b = make_identity("test.example.com");
        let config = make_server_config();

        let binding_a = network
            .bind_server(identity_a.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .bind_server(identity_b.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with different identity should succeed (overwrite)");

        assert_eq!(binding_a.name(), binding_b.name());
        assert_eq!(network.sni_registry.len(), 1);

        let entry = network
            .sni_registry
            .get(binding_b.name())
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the new entry");
        assert!(Arc::ptr_eq(&entry.identity, &identity_b));
    }

    #[tokio::test]
    async fn test_bind_server_same_identity_reuse() {
        let network = Network::builder().build();
        let identity = make_identity("test.example.com");
        let config = make_server_config();

        let binding_a = network
            .bind_server(identity.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .bind_server(identity.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with same identity should succeed (reuse)");

        assert_eq!(binding_a.name(), binding_b.name());
        assert_eq!(network.sni_registry.len(), 1);

        let entry_a = network
            .sni_registry
            .get(binding_a.name())
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the entry");
        let entry_b = network
            .sni_registry
            .get(binding_b.name())
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the entry");

        assert!(Arc::ptr_eq(&entry_a, &entry_b));
    }
}
