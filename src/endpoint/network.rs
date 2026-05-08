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
            location::{Locations, LocationsComponent},
            route::{QuicRouter, QuicRouterComponent, Way},
        },
        device::Devices,
        io::ProductIO,
        manager::InterfaceManager,
    },
    qtraversal::{
        nat::{client::StunClientsComponent, router::StunRouterComponent},
        route::{ForwardersComponent, ReceiveAndDeliverPacketComponent},
    },
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
    stun_resolver: Arc<dyn Resolve + Send + Sync>,
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
        #[builder(default = Arc::new(InterfaceManager::new()))] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = Arc::new(QuicRouter::new()))] quic_router: Arc<QuicRouter>,
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
    pub(crate) fn configure_connection<F, T>(
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
    pub(crate) fn locations(&self) -> Arc<Locations> {
        self.locations.clone()
    }

    /// Register a server identity on the network's SNI fan-out.
    ///
    /// The first call initialises the shared server TLS context; later calls
    /// must use a compatible [`ServerQuicConfig`] (or the exact same
    /// `Arc`).  Returns a [`ServerBinding`] handle that receives accepted
    /// connections for this SNI.
    pub(crate) async fn bind_server(
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
                _ => {
                    occupied.remove();
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
            pattern
                .to_bind_uris(self.devices.interfaces().keys().map(String::as_str))
                .filter(|uri| !bound.contains_key(&uri.identity_key()))
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
            self.init_iface_components(&iface);
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

    fn init_iface_components(&self, bind_iface: &BindInterface) {
        let uri = bind_iface.bind_uri();
        let stun_server = if let Some(server) = uri.stun_server() {
            Some(Arc::from(server.into_owned()))
        } else if let Some("false") = uri.prop(BindUri::STUN_PROP).as_deref() {
            None
        } else {
            self.stun_server.clone()
        };

        bind_iface.with_components_mut(|components, iface| {
            let router = components
                .init_with(|| QuicRouterComponent::new(self.quic_router.clone()))
                .router();

            if let Some(stun_server) = stun_server {
                let stun_router = components
                    .init_with(|| StunRouterComponent::new(iface.downgrade()))
                    .router();
                let loc = components
                    .init_with(|| {
                        LocationsComponent::new(iface.downgrade(), self.locations.clone())
                    })
                    .clone();
                let clients = components
                    .init_with(|| {
                        StunClientsComponent::new(
                            iface.downgrade(),
                            stun_router.clone(),
                            self.stun_resolver.clone(),
                            stun_server,
                            Vec::new(),
                            Some(loc),
                        )
                    })
                    .clone();
                let forwarder = components
                    .init_with(|| ForwardersComponent::new_client(clients))
                    .forwarder();
                components.init_with(|| {
                    ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                        .quic_router(router)
                        .stun_router(stun_router)
                        .forwarder(forwarder)
                        .init()
                });
            } else {
                components.init_with(|| {
                    LocationsComponent::new(iface.downgrade(), self.locations.clone())
                });
                components.init_with(|| {
                    ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                        .quic_router(router)
                        .init()
                });
            }
        });
    }

    /// Release a previously registered [`BindPattern`] and its bound
    /// interfaces.
    pub(crate) async fn unbind(&self, pattern: &BindPattern) {
        let bound = {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            if let hash_map::Entry::Occupied(mut entry) = registry.entry(pattern.clone()) {
                entry.get_mut().refcount = entry.get().refcount.saturating_sub(1);
                if entry.get().refcount == 0 {
                    entry.remove().bound
                } else {
                    return;
                }
            } else {
                return;
            }
        };

        for (_, (_, iface)) in bound.into_inner().expect("bound mutex poisoned") {
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
    #[allow(dead_code, reason = "used in test module")]
    pub(crate) fn registered_sni_names(&self) -> Vec<ServerName> {
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
        let conn = foundation
            .with_streams_concurrency_strategy(slot.config.common.stream_strategy_factory.as_ref())
            .with_defer_idle_timeout(slot.config.common.defer_idle_timeout)
            .with_zero_rtt(slot.config.common.enable_0rtt)
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
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;

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
                let desired_keys: std::collections::HashSet<String> = pattern
                    .to_bind_uris(self.devices.interfaces().keys().map(String::as_str))
                    .map(|u| u.identity_key())
                    .collect();
                bound.retain(|key, _| desired_keys.contains(key));

                for uri in
                    pattern.to_bind_uris(self.devices.interfaces().keys().map(String::as_str))
                {
                    let key = uri.identity_key();
                    if let std::collections::hash_map::Entry::Vacant(e) = bound.entry(key) {
                        let iface = self
                            .iface_manager
                            .bind(uri.clone(), self.io_factory.clone())
                            .await;
                        self.init_iface_components(&iface);
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
            Some(_) => ClientNameVerifyResult::SilentRefuse("bind pattern mismatch".to_owned()),
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
    use std::str::FromStr;

    use dquic::prelude::handy::NoopTokenRegistry;
    use rustls::ClientConfig as TlsClientConfig;

    use super::*;
    use crate::endpoint::{binds::BindPattern, identity::Identity};

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

    #[tokio::test]
    async fn test_network_build() {
        let network = Network::builder().build();
        let _cloned = network.clone();
    }

    #[tokio::test]
    async fn test_network_locations() {
        let network = Network::builder().build();
        let locations = network.locations();
        let _cloned = locations.clone();
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_empty() {
        let network = Network::builder().build();
        assert!(
            network.registered_sni_names().is_empty(),
            "fresh network should have no registered sni names"
        );
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_after_bind() {
        let network = Network::builder().build();
        let identity = make_identity("alpha");
        let config = make_server_config();

        let _binding = network
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        let names = network.registered_sni_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), "alpha");
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_after_drop() {
        let network = Network::builder().build();
        let identity = make_identity("alpha");
        let config = make_server_config();

        let binding = network
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        assert_eq!(network.registered_sni_names().len(), 1);
        drop(binding);
        assert!(
            network.registered_sni_names().is_empty(),
            "names should be empty after dropping the last binding"
        );
    }

    #[tokio::test]
    async fn test_network_bind_server_with_identical_config_arc_reuse() {
        let network = Network::builder().build();
        let identity_a = make_identity("a");
        let identity_b = make_identity("b");
        let config = make_server_config();

        let binding_a = network
            .bind_server(identity_a.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .bind_server(identity_b.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with same config should succeed");

        assert_eq!(binding_a.name().as_str(), "a");
        assert_eq!(binding_b.name().as_str(), "b");

        let names = network.registered_sni_names();
        assert_eq!(names.len(), 2, "both names should be registered");
        assert!(names.iter().any(|n| n.as_str() == "a"));
        assert!(names.iter().any(|n| n.as_str() == "b"));
    }

    #[test]
    fn test_bind_server_error_sni_in_use_display() {
        let err = BindServerError::SniInUse {
            name: ServerName::new("example.com"),
        };
        let display = format!("{err}");
        assert!(
            display.starts_with("sni "),
            "Display should start with lowercase: {display}"
        );
        assert!(
            display.contains("example.com"),
            "Display should contain SNI name: {display}"
        );
        assert!(
            !display.ends_with('.'),
            "Display should not end with period"
        );
    }

    #[test]
    fn test_bind_server_error_server_config_conflict_display() {
        let err = BindServerError::ServerConfigConflict;
        let display = format!("{err}");
        assert!(
            display.contains("incompatible"),
            "Display should contain 'incompatible': {display}"
        );
        assert!(
            display.starts_with("network"),
            "Display should start with lowercase: {display}"
        );
        assert!(
            !display.ends_with('.'),
            "Display should not end with period"
        );
    }

    #[test]
    fn test_bind_server_error_load_key_variant() {
        fn assert_load_key_variant(e: rustls::Error) -> BindServerError {
            BindServerError::LoadKey { source: e }
        }
        let _ = assert_load_key_variant;
    }

    #[test]
    fn test_bind_server_error_version_variant() {
        fn assert_version_variant(e: rustls::Error) -> BindServerError {
            BindServerError::Version { source: e }
        }
        let _ = assert_version_variant;
    }

    #[tokio::test]
    async fn test_server_binding_name() {
        let network = Network::builder().build();
        let identity = make_identity("example.com");
        let config = make_server_config();

        let binding = network
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        assert_eq!(binding.name().as_str(), "example.com");
    }

    #[tokio::test]
    async fn test_server_binding_clone_name() {
        let network = Network::builder().build();
        let identity = make_identity("example.com");
        let config = make_server_config();

        let binding = network
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        let cloned = binding.clone();
        assert_eq!(binding.name(), cloned.name());
        assert_eq!(cloned.name().as_str(), "example.com");
    }

    #[tokio::test]
    async fn test_network_configure_connection() {
        let network = Network::builder().build();
        let provider = TlsClientConfig::builder().crypto_provider().clone();
        let tls = TlsClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 should be supported")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        let builder =
            Connection::new_client("test.example.com".to_string(), Arc::new(NoopTokenRegistry))
                .with_tls_config(tls);

        let _foundation = network.configure_connection(builder);
    }

    #[test]
    fn test_bind_pattern_parsing() {
        let pattern = BindPattern::from_str("127.0.0.1:8080").expect("valid pattern");
        assert_eq!(pattern.port, Some(8080));
    }

    #[tokio::test]
    async fn test_bind_server_config_conflict() {
        let network = Network::builder().build();
        let a = make_identity("alpha");
        let b = make_identity("beta");

        let cfg_a = make_server_config();
        let cfg_b = {
            let own = crate::endpoint::server::ServerSpecificConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            };
            ServerQuicConfig {
                common: Arc::default(),
                own: Arc::new(own),
            }
        };

        let _held = network
            .bind_server(a, cfg_a, Arc::new(Vec::new()))
            .await
            .expect("first bind succeeds");
        let err = network
            .bind_server(b, cfg_b, Arc::new(Vec::new()))
            .await
            .expect_err("incompatible server config must fail");
        assert!(
            matches!(err, BindServerError::ServerConfigConflict),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_bind_server_slot_auto_reset() {
        let network = Network::builder().build();

        let cfg_a = make_server_config();
        let cfg_b = {
            let own = crate::endpoint::server::ServerSpecificConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            };
            ServerQuicConfig {
                common: Arc::default(),
                own: Arc::new(own),
            }
        };

        {
            let _first = network
                .bind_server(make_identity("alpha"), cfg_a, Arc::new(Vec::new()))
                .await
                .expect("first bind succeeds");
        }
        // After the binding drops the slot should clear, allowing a new
        // incompatible config to install.
        let _second = network
            .bind_server(make_identity("beta"), cfg_b, Arc::new(Vec::new()))
            .await
            .expect("slot should auto-reset after last binding dropped");
    }

    // ── Helpers for two_sni_share_network_and_port ──

    use futures::{FutureExt, StreamExt, stream};
    use http::uri::Authority;
    use tokio_util::task::AbortOnDropHandle;

    use crate::{
        client::Client,
        connection::ConnectionBuilder,
        dquic::{
            prelude::{BoundAddr, IO},
            qbase::net::addr::{EndpointAddr, SocketEndpointAddr},
            qresolve::{Resolve, ResolveFuture, Source},
        },
        endpoint::{
            ClientQuicConfig, ClientSpecificConfig, H3Endpoint, QuicEndpoint,
            ServerCertVerifierChoice,
        },
        pool::Pool,
        server::{self, Router},
    };

    /// Test-only resolver that maps every name lookup to a fixed loopback
    /// endpoint. Lets tests dial arbitrary SNIs (e.g. `alpha`, `beta`) without
    /// requiring `/etc/hosts` entries.
    #[derive(Debug)]
    struct FixedResolver(std::net::SocketAddr);

    impl std::fmt::Display for FixedResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "FixedResolver({})", self.0)
        }
    }

    impl Resolve for FixedResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
            let ep = EndpointAddr::Socket(SocketEndpointAddr::direct(self.0));
            let source = Source::System;
            async move { Ok(stream::iter(std::iter::once((source, ep))).boxed()) }.boxed()
        }
    }

    async fn alpha_service(_: &mut server::Request, response: &mut server::Response) {
        response
            .set_status(http::StatusCode::OK)
            .set_body(&b"alpha"[..]);
    }

    async fn beta_service(_: &mut server::Request, response: &mut server::Response) {
        response
            .set_status(http::StatusCode::OK)
            .set_body(&b"beta"[..]);
    }

    /// Two named servers (`alpha`, `beta`) share one [`Network`] and one listen
    /// port. Both register distinct SNIs via the Network's SNI registry. A
    /// client dialing `alpha:PORT` must receive the `alpha` handler's response,
    /// and `beta:PORT` must receive `beta`'s. This exercises:
    ///
    /// * shared [`Network`] infrastructure (one bind port, one QuicRouter, one
    ///   connectionless dispatcher);
    /// * the Network's per-SNI mpmc fan-out (`sni_registry` + `bind_server`);
    /// * rustls [`SniCertResolver`] picking the correct [`CertifiedKey`];
    /// * [`QuicEndpoint::accept`] returning only connections destined for its
    ///   own SNI.
    #[tokio::test]
    async fn test_two_sni_share_network_and_port() {
        let network = Network::builder().build();
        let _bind = network
            .bind(BindPattern::from_str("inet://127.0.0.1:0").unwrap())
            .await;
        let bind_iface = network.interfaces().into_iter().next().unwrap();
        let port = match bind_iface.borrow().bound_addr().unwrap() {
            BoundAddr::Internet(s) => s.port(),
            _ => unreachable!(),
        };
        let resolver: Arc<dyn Resolve + Send + Sync> =
            Arc::new(FixedResolver(format!("127.0.0.1:{port}").parse().unwrap()));

        let mut serve_handles = Vec::new();
        let mut bindings = Vec::new();
        // Share one config Arc across both servers; otherwise
        // `ServerQuicConfig::default()` yields fresh trait objects each
        // call and `server_config_compatible` rejects the second bind.
        let shared_server_config = ServerQuicConfig::default();
        let alpha_router = Router::new().get("/hello", alpha_service);
        let beta_router = Router::new().get("/hello", beta_service);
        for (name, router) in [("alpha", alpha_router), ("beta", beta_router)] {
            let named = make_identity(name);
            // Eagerly register so rustls' SniCertResolver sees both SNIs
            // before the first ClientHello arrives (avoids a startup race
            // where a client connects before the server task has polled
            // its first `accept()`).
            let binding = network
                .bind_server(
                    named.clone(),
                    shared_server_config.clone(),
                    Arc::new(Vec::new()),
                )
                .await
                .expect("eager bind_server");
            bindings.push(binding);
            let quic = QuicEndpoint::new(
                network.clone(),
                Some(named),
                resolver.clone(),
                ClientQuicConfig::default(),
                shared_server_config.clone(),
                Arc::new(Vec::new()),
            )
            .await;
            let h3 = H3Endpoint::new(
                quic,
                Pool::empty(),
                Arc::new(ConnectionBuilder::new(Arc::default())),
            );
            serve_handles.push(AbortOnDropHandle::new(tokio::spawn(
                async move { h3.serve(router).await }.in_current_span(),
            )));
        }

        // Client with dangerous verifier (cert was issued for `localhost` so
        // webpki would reject `alpha`/`beta` even though they share material).
        let client_own = ClientSpecificConfig {
            verifier: ServerCertVerifierChoice::Dangerous,
            ..Default::default()
        };
        let client_quic_config = ClientQuicConfig {
            common: Arc::default(),
            own: Arc::new(client_own),
        };
        let client_quic = QuicEndpoint::new(
            network.clone(),
            None,
            resolver.clone(),
            client_quic_config,
            ServerQuicConfig::default(),
            Arc::new(Vec::new()),
        )
        .await;
        let client = Client::from_quic_client().client(client_quic).build();

        for (sni, expected) in [("alpha", "alpha"), ("beta", "beta")] {
            let authority: Authority = format!("{sni}:{port}").parse().unwrap();
            let uri: http::Uri = format!("https://{authority}/hello").parse().unwrap();
            let (_req, mut resp) = client
                .new_request()
                .with_authority(authority)
                .get(uri)
                .await
                .unwrap_or_else(|e| panic!("request for {sni} failed: {e:?}"));
            assert_eq!(resp.status(), http::StatusCode::OK);
            let body = resp.read_to_string().await.expect("read body");
            assert_eq!(body, expected, "sni {sni} got wrong response");
        }

        drop(serve_handles);
        drop(bindings);
    }
}
