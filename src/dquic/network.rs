//! Process-shared QUIC network infrastructure.
//!
//! [`Network`] owns the long-lived bind registry and device reconciliation
//! task. Its built-in [`QuicBindDriver`] owns the QUIC runtime components
//! needed to send and receive QUIC packets on a set of network interfaces,
//! including the SNI fan-out registry used to route newly-accepted
//! connections to per-identity
//! [`QuicEndpoint`](crate::dquic::endpoint::QuicEndpoint) listeners.
//!
//! A [`Network`] is always used via [`Arc<Network>`]: clone the [`Arc`] to
//! share the infrastructure between many endpoints. The builder returns an
//! [`Arc`] directly via [`Network::builder().build()`](Network::builder).
//!
//! ## SNI dispatch
//!
//! The built-in QUIC driver installs a *connectionless packet dispatcher* on
//! its [`QuicRouter`]. When an Initial / 0-RTT packet arrives without matching
//! an existing connection, the dispatcher constructs a fresh server
//! [`Connection`] using the shared
//! [`ServerQuicConfig`] stored in the
//! QUIC driver's `server_slot`, waits for the handshake to reveal the
//! ClientHello SNI, and fans the connection into the matching
//! [`ServerBinding`]'s mpmc queue.
//!
//! Because the underlying rustls `ServerConfig` must be chosen *before* SNI
//! is known, the QUIC driver stores **one** `ServerQuicConfig` at a time.
//! The first call to [`QuicBindDriver::bind_server`] initialises that slot;
//! subsequent calls with an identical (or `Arc::ptr_eq`) configuration
//! succeed, while a conflicting configuration is rejected with
//! [`BindServerError::ServerConfigConflict`]. When the last [`ServerBinding`]
//! referring to the slot drops, the slot clears and a different configuration
//! may be used on the next bind.
//!
//! ## Binds registry
//!
//! [`QuicBindDriver::bind`] and [`Network::bind_with`] register a
//! [`BindPattern`] with reference counting. Repeated calls with the same
//! driver and pattern increment the count; when every
//! returned [`BindHandle`] is dropped or [`BindHandle::unbind`] is called,
//! the count reaches zero and the bound interfaces are released.
//! A single background reconcile task (started at build time)
//! watches for device changes and keeps every pattern's bound interfaces in
//! sync.

use std::{
    collections::HashMap,
    io, mem,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak},
    task::{Context, Poll},
};

use dashmap::DashMap;
use dhttp_identity::name::Name;
use futures::{FutureExt, future::BoxFuture};
use snafu::Snafu;
use tokio::sync::{Mutex as TokioMutex, OwnedMutexGuard};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

// Re-export ServerBinding so `crate::dquic::network::ServerBinding` resolves.
// `sni` module is the canonical source; this re-export is kept for compatibility
// with existing consumers (e.g. `crate::dquic::endpoint`).
pub use crate::dquic::sni::ServerBinding;
use crate::dquic::{
    binds::BindPattern,
    connection::Connection,
    identity::Identity,
    net::{
        BindInterface, BindUri, Devices, Family, InterfaceManager, Locations, ProductIO,
        QuicRouter, handy::DEFAULT_IO_FACTORY,
    },
    resolver::{Resolve, handy::SystemResolver},
    server::ServerQuicConfig,
    sni::{self, RegistryGuard, ServerConfig, ServerEntry, SniCertResolver},
    tls::{
        AuthClient, ClientAuthorityVerifyResult, ClientNameVerifyResult, LocalAuthority,
        RemoteAuthority,
    },
};
// Internal implementation types — not part of curated domain modules
use crate::dquic::{
    qbase::packet::Packet,
    qconnection::builder::ConnectionFoundation,
    qinterface::{
        component::{
            location::LocationsComponent,
            route::{QuicRouterComponent, Way},
        },
        device::InterfaceEvent,
    },
    qtraversal::{
        nat::{client::StunClientsComponent, router::StunRouterComponent},
        route::{ForwardersComponent, ReceiveAndDeliverPacketComponent},
    },
};

pub(crate) type SniRegistry = Arc<DashMap<Name<'static>, Weak<ServerEntry>>>;
type BoundInterfaces = HashMap<String, (BindUri, BindInterface)>;

fn interface_contains(interface: &::dquic::qinterface::device::Interface, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => interface.ipv4.iter().any(|net| net.contains(&ip)),
        IpAddr::V6(ip) => interface.ipv6.iter().any(|net| net.contains(&ip)),
    }
}

fn iface_bind_uri_device(uri: &BindUri) -> Option<&str> {
    uri.as_iface_bind_uri()
        .map(|(_family, device, _port)| device)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BindRegistryKey {
    driver: BindDriverId,
    pattern: BindPattern,
}

/// Opaque identity of an [`Arc`]-backed [`BindDriver`].
///
/// The bind registry stores a strong `Arc<dyn BindDriver>` next to every key,
/// so the allocation behind this pointer identity cannot be freed or reused
/// while the key is live. A `Weak` key would still need the same pointer-based
/// hashing/equality, while also mixing liveness into an identity-only key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BindDriverId(usize);

fn bind_driver_id<D: BindDriver + ?Sized>(driver: &Arc<D>) -> BindDriverId {
    BindDriverId(Arc::as_ptr(driver) as *const () as usize)
}

/// Driver that binds one concrete [`BindUri`] into a runtime binding resource.
pub trait BindDriver: Send + Sync {
    fn bind<'a>(&'a self, network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface>;

    fn rebind<'a>(&'a self, _network: &'a Network, _iface: &'a BindInterface) -> BoxFuture<'a, ()> {
        async {}.boxed()
    }
}

/// Built-in QUIC binding runtime owned by [`Network`].
///
/// Obtain it with [`Network::quic`]. Methods that register or query binds use
/// the originating [`Network`]'s bind registry; keep the `Network` alive while
/// using a cloned `Arc<QuicBindDriver>`.
pub struct QuicBindDriver {
    network: Weak<Network>,
    iface_manager: Arc<InterfaceManager>,
    io_factory: Arc<dyn ProductIO + 'static>,
    stun_resolver: Arc<dyn Resolve + Send + Sync>,
    stun_server: Option<Arc<str>>,
    quic_router: Arc<QuicRouter>,
    locations: Arc<Locations>,
    sni_registry: SniRegistry,
    server_slot: RwLock<Weak<sni::ServerConfig>>,
}

#[bon::bon]
impl QuicBindDriver {
    #[builder]
    fn new(
        network: Weak<Network>,
        #[builder(default = Arc::new(InterfaceManager::new()))] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = Arc::new(DEFAULT_IO_FACTORY))] io_factory: Arc<dyn ProductIO + 'static>,
        #[builder(default = Arc::new(SystemResolver))] stun_resolver: Arc<
            dyn Resolve + Send + Sync,
        >,
        stun_server: Option<Arc<str>>,
        #[builder(default = Arc::new(QuicRouter::new()))] quic_router: Arc<QuicRouter>,
        #[builder(default = Arc::new(Locations::new()))] locations: Arc<Locations>,
    ) -> Arc<Self> {
        let driver = Arc::new(Self {
            network,
            iface_manager,
            io_factory,
            stun_resolver,
            stun_server,
            quic_router,
            locations,
            sni_registry: Arc::new(DashMap::new()),
            server_slot: RwLock::new(Weak::new()),
        });

        let weak_driver = Arc::downgrade(&driver);
        let installed = driver
            .quic_router
            .on_connectless_packets(move |packet, way| {
                let Some(driver) = weak_driver.upgrade() else {
                    return;
                };
                Self::dispatch_initial_packet(driver, packet, way);
            });
        tracing::debug!(installed, "sni dispatcher installation");

        driver
    }
}

impl BindDriver for QuicBindDriver {
    fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
        async move {
            let iface = self.iface_manager.bind(uri, self.io_factory.clone()).await;
            self.init_quic_iface_components(&iface);
            iface
        }
        .boxed()
    }

    fn rebind<'a>(&'a self, _network: &'a Network, iface: &'a BindInterface) -> BoxFuture<'a, ()> {
        async move {
            iface.rebind().await;
        }
        .boxed()
    }
}

impl QuicBindDriver {
    fn registry_id(&self) -> BindDriverId {
        BindDriverId(self as *const Self as *const () as usize)
    }

    fn network(&self) -> Arc<Network> {
        self.network
            .upgrade()
            .expect("quic driver is detached from network")
    }

    #[must_use]
    pub fn iface_manager(&self) -> Arc<InterfaceManager> {
        self.iface_manager.clone()
    }

    #[must_use]
    pub fn io_factory(&self) -> Arc<dyn ProductIO + 'static> {
        self.io_factory.clone()
    }

    #[must_use]
    pub fn quic_router(&self) -> Arc<QuicRouter> {
        self.quic_router.clone()
    }

    #[must_use]
    pub fn locations(&self) -> Arc<Locations> {
        self.locations.clone()
    }

    #[must_use]
    pub fn stun_server(&self) -> Option<Arc<str>> {
        self.stun_server.clone()
    }

    #[must_use]
    pub fn stun_resolver(&self) -> Arc<dyn Resolve + Send + Sync> {
        self.stun_resolver.clone()
    }

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

    fn init_quic_iface_components(&self, bind_iface: &BindInterface) {
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

    fn server_binding_for_existing(
        existing: &Arc<ServerEntry>,
        bind_patterns: Arc<Vec<BindPattern>>,
    ) -> ServerBinding {
        ServerBinding {
            entry: Arc::new(ServerEntry {
                identity: existing.identity.clone(),
                certified_key: existing.certified_key.clone(),
                incomings_tx: existing.incomings_tx.clone(),
                incomings_rx: existing.incomings_rx.clone(),
                config: existing.config.clone(),
                guard: existing.guard.clone(),
                bind: bind_patterns,
            }),
        }
    }

    fn compatible_server_slot(
        &self,
        server_config: &ServerQuicConfig,
    ) -> Result<Arc<ServerConfig>, BindServerError> {
        use bind_server_error::*;

        let slot_guard = self.server_slot.read().unwrap();
        if let Some(slot) = slot_guard.upgrade() {
            if !slot.config.is_compatible_with(server_config) {
                return ServerConfigConflictSnafu.fail();
            }
            return Ok(slot);
        }

        drop(slot_guard);
        let mut slot_guard = self.server_slot.write().unwrap();
        if let Some(slot) = slot_guard.upgrade() {
            if !slot.config.is_compatible_with(server_config) {
                return ServerConfigConflictSnafu.fail();
            }
            return Ok(slot);
        }

        let resolver = SniCertResolver {
            registry: Arc::downgrade(&self.sni_registry),
        };
        let rustls_config = Arc::new(server_config.build_rustls_server_config(resolver)?);
        let slot = Arc::new(ServerConfig {
            config: server_config.clone(),
            rustls_config,
        });
        *slot_guard = Arc::downgrade(&slot);
        Ok(slot)
    }

    pub async fn bind_server(
        self: Arc<Self>,
        identity: Arc<Identity>,
        server_config: ServerQuicConfig,
        bind_patterns: Arc<Vec<BindPattern>>,
    ) -> Result<ServerBinding, BindServerError> {
        let name = identity.name.clone();
        let slot = self.compatible_server_slot(&server_config)?;

        if let Some(kv) = self.sni_registry.get(&name)
            && let Some(existing) = kv.value().upgrade()
            && Arc::ptr_eq(&existing.identity, &identity)
        {
            // NOTE: creates a new Arc<ServerEntry> sharing the existing
            // guard. When the original entry drops before this clone,
            // a zombie Weak<ServerEntry> lingers in sni_registry until
            // the next bind_server call. This is benign:
            // - SniCertResolver::resolve returns None for dead Weak
            // - InterfaceAuthClient::verify_client_name returns SilentRefuse
            // - Next bind_server removes the zombie via occupied.remove()
            return Ok(Self::server_binding_for_existing(&existing, bind_patterns));
        }

        let certified_key = crate::dquic::identity::build_certified_key(&identity)?;

        use dashmap::mapref::entry::Entry;
        match self.sni_registry.entry(name.clone()) {
            Entry::Occupied(occupied) => match occupied.get().upgrade() {
                Some(existing) if Arc::ptr_eq(&existing.identity, &identity) => {
                    // NOTE: same shared-guard pattern as the
                    // pre-check path above; see that comment for
                    // the benign zombie Weak explanation.
                    return Ok(Self::server_binding_for_existing(&existing, bind_patterns));
                }
                _ => {
                    occupied.remove();
                }
            },
            Entry::Vacant(_) => {}
        }

        let (incomings_tx, incomings_rx) = async_channel::bounded(server_config.backlog);

        let entry = Arc::new_cyclic(|weak_entry| ServerEntry {
            identity,
            certified_key,
            incomings_tx,
            incomings_rx,
            config: slot,
            guard: Arc::new(RegistryGuard {
                name: name.clone(),
                registry: Arc::downgrade(&self.sni_registry),
                self_entry: weak_entry.clone(),
            }),
            bind: bind_patterns.clone(),
        });

        self.sni_registry
            .insert(name.clone(), Arc::downgrade(&entry));

        Ok(ServerBinding { entry })
    }

    #[cfg(test)]
    fn registered_sni_names(&self) -> Vec<Name<'static>> {
        self.sni_registry
            .iter()
            .filter(|kv| kv.value().upgrade().is_some())
            .map(|kv| kv.key().clone())
            .collect()
    }

    /// Register a [`BindPattern`] through this built-in QUIC driver.
    ///
    /// Returns a [`BindHandle`] that keeps the pattern alive. When all
    /// handles for a pattern are dropped (or [`BindHandle::unbind`] is
    /// called), the bound interfaces are released.
    pub async fn bind(self: Arc<Self>, pattern: BindPattern) -> BindHandle {
        let network = self.network();
        network.bind_with(self.clone(), pattern).await
    }

    fn collect_bound<T>(&self, map: impl Fn(&BindUri, &BindInterface) -> T) -> Vec<T> {
        let network = self.network();
        let registry = network
            .bind_registry
            .lock()
            .expect("bind_registry poisoned");
        let quic_driver = self.registry_id();
        let mut items = Vec::new();
        for (_, entry) in registry.iter().filter(|(key, _)| key.driver == quic_driver) {
            let state = entry.lock_state();
            items.extend(state.bound.values().map(|(uri, iface)| map(uri, iface)));
        }
        items
    }

    /// Return all currently bound interfaces owned by this QUIC driver.
    #[must_use]
    pub fn interfaces(&self) -> Vec<BindInterface> {
        self.collect_bound(|_, iface| iface.clone())
    }

    /// Return all currently bound URIs owned by this QUIC driver.
    #[must_use]
    pub fn current_bind_uris(&self) -> Vec<BindUri> {
        self.collect_bound(|uri, _| uri.clone())
    }

    /// Return the currently bound interface for an exact [`BindUri`].
    #[must_use]
    pub fn get_iface(&self, uri: &BindUri) -> Option<BindInterface> {
        let key = uri.identity_key();
        let network = self.network();
        let registry = network
            .bind_registry
            .lock()
            .expect("bind_registry poisoned");
        let quic_driver = self.registry_id();
        registry
            .iter()
            .filter(|(key, _)| key.driver == quic_driver)
            .map(|(_, entry)| entry)
            .find_map(|entry| {
                let state = entry.lock_state();
                state.bound.get(&key).map(|(_uri, iface)| iface.clone())
            })
    }

    /// Return all currently bound interfaces for a specific [`BindPattern`].
    ///
    /// Returns `None` if the pattern has not been registered through this
    /// driver.
    #[must_use]
    pub fn get_interfaces(&self, pattern: &BindPattern) -> Option<Vec<BindInterface>> {
        let network = self.network();
        let key = BindRegistryKey {
            driver: self.registry_id(),
            pattern: pattern.clone(),
        };
        let registry = network
            .bind_registry
            .lock()
            .expect("bind_registry poisoned");
        registry.get(&key).map(|entry| {
            entry
                .lock_state()
                .bound
                .values()
                .map(|(_, iface)| iface.clone())
                .collect()
        })
    }

    /// Connectionless packet dispatcher installed on the [`QuicRouter`].
    ///
    /// Called for every Initial / 0-RTT packet that doesn't match an
    /// existing connection. Spawns a new server [`Connection`] using the
    /// shared server slot, waits for the TLS handshake to reveal the SNI,
    /// and fans the connection into the matching [`ServerBinding`]'s queue.
    fn dispatch_initial_packet(driver: Arc<Self>, packet: Packet, way: Way) {
        use crate::dquic::qbase::packet::{
            DataHeader,
            header::{self, GetDcid},
        };

        // Filter to Initial and 0-RTT packets.
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

        // Read the slot synchronously: this router callback cannot await.
        let Some(slot) = driver.server_slot.try_read().ok().and_then(|g| g.upgrade()) else {
            return;
        };

        // Build the connection synchronously so the CID is registered in
        // QuicRouter before the first packet is delivered.
        let sni_registry = driver.sni_registry.clone();

        let foundation = Connection::new_server(slot.config.token_provider.clone())
            .with_parameters(slot.config.parameters.clone())
            .with_client_auther(Box::new((
                InterfaceAuthClient {
                    bind_uri: bind_uri.clone(),
                    sni_registry: sni_registry.clone(),
                },
                slot.config.client_auther.clone(),
            )))
            .with_tls_config((*slot.rustls_config).clone());

        let conn = driver
            .configure_connection(foundation)
            .with_streams_concurrency_strategy(slot.config.stream_strategy_factory.as_ref())
            .with_defer_idle_timeout(slot.config.defer_idle_timeout)
            .with_zero_rtt(slot.config.enable_0rtt)
            .with_cids(origin_dcid)
            .with_qlog(slot.config.qlogger.clone())
            .run();

        let quic_router = driver.quic_router.clone();

        // Spawn only async delivery and SNI dispatch work.
        // Inherent termination: this task owns the newly-created server
        // connection and exits once SNI dispatch succeeds, the SNI queue is
        // closed, or connection name resolution fails.
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
                    let incomings_tx = entry.incomings_tx.clone();
                    drop(entry);
                    if incomings_tx.send(conn).await.is_err() {
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
}

/// Error returned by [`QuicBindDriver::bind_server`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BindServerError {
    /// Another [`Identity`] is already registered for the same SNI.
    #[snafu(display("sni {name} is already bound to a different identity"))]
    SniInUse {
        /// SNI that is already registered.
        name: Name<'static>,
    },
    /// The QUIC driver already has a server configuration that is
    /// incompatible with the one provided. Drop every existing
    /// [`ServerBinding`] before binding with a different configuration.
    #[snafu(display("quic driver already holds an incompatible server configuration"))]
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

/// Shared network bind orchestration with a built-in QUIC runtime.
///
/// Used exclusively via [`Arc<Network>`]. [`Network::builder().build()`](Network::builder)
/// returns an [`Arc`] directly after constructing the built-in QUIC driver.
pub struct Network {
    devices: &'static Devices,
    quic_driver: Arc<QuicBindDriver>,
    bind_registry: Mutex<HashMap<BindRegistryKey, Arc<BindsEntry>>>,
    _reconcile: OnceLock<AbortOnDropHandle<()>>,
}

struct BindsEntry {
    key: BindRegistryKey,
    driver: Arc<dyn BindDriver>,
    pattern: BindPattern,
    serial: Arc<TokioMutex<()>>,
    state: Mutex<BindsState>,
}

struct BindsState {
    refcount: usize,
    closing: bool,
    /// Live bindings keyed by [`BindUri::identity_key`]. Holds strong
    /// [`BindInterface`] references so that the interfaces (and their
    /// installed components) stay alive.
    bound: BoundInterfaces,
}

#[derive(Clone)]
struct BindEntryRef {
    key: BindRegistryKey,
    entry: Arc<BindsEntry>,
}

impl BindsEntry {
    fn new(key: BindRegistryKey, driver: Arc<dyn BindDriver>) -> Self {
        Self {
            pattern: key.pattern.clone(),
            key,
            driver,
            serial: Arc::new(TokioMutex::new(())),
            state: Mutex::new(BindsState {
                refcount: 0,
                closing: false,
                bound: HashMap::new(),
            }),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, BindsState> {
        self.state.lock().expect("bind entry state mutex poisoned")
    }

    fn is_closing(&self) -> bool {
        self.lock_state().closing
    }

    fn pattern_matches_device(&self, device: &str) -> bool {
        self.pattern.interface_bind_uris(device).next().is_some()
    }
}

impl BindsState {
    fn missing_current_device_uris(
        &self,
        pattern: &BindPattern,
        devices: &'static Devices,
    ) -> Vec<BindUri> {
        pattern
            .to_bind_uris(devices.interfaces().keys().map(String::as_str))
            .filter(|uri| !self.bound.contains_key(&uri.identity_key()))
            .collect()
    }

    fn missing_added_device_uris(&self, pattern: &BindPattern, device: &str) -> Vec<BindUri> {
        pattern
            .interface_bind_uris(device)
            .filter(|uri| !self.bound.contains_key(&uri.identity_key()))
            .collect()
    }

    fn drain_device_bindings(&mut self, device: &str) -> CloseBatch {
        let mut retained = HashMap::with_capacity(self.bound.len());
        let mut close = CloseBatch::new();

        for (key, (uri, iface)) in mem::take(&mut self.bound) {
            if iface_bind_uri_device(&uri) == Some(device) {
                close.push(iface);
            } else {
                retained.insert(key, (uri, iface));
            }
        }

        self.bound = retained;
        close
    }

    fn changed_device_targets(&self, device: &str) -> Vec<BindInterface> {
        self.bound
            .values()
            .filter(|(uri, _iface)| iface_bind_uri_device(uri) == Some(device))
            .map(|(_uri, iface)| iface.clone())
            .collect()
    }
}

#[derive(Default)]
struct CloseBatch {
    current: Option<BoxFuture<'static, ()>>,
    ifaces: Vec<BindInterface>,
}

impl CloseBatch {
    fn new() -> Self {
        Self::default()
    }

    fn is_empty(&self) -> bool {
        self.current.is_none() && self.ifaces.is_empty()
    }

    fn push(&mut self, iface: BindInterface) {
        self.ifaces.push(iface);
    }

    fn extend(&mut self, ifaces: impl IntoIterator<Item = BindInterface>) {
        self.ifaces.extend(ifaces);
    }

    fn close_iface(iface: BindInterface) -> BoxFuture<'static, ()> {
        async move {
            iface.close().await.ok();
        }
        .boxed()
    }

    async fn close_all(&mut self) {
        loop {
            if self.current.is_none() {
                self.current = self.ifaces.pop().map(Self::close_iface);
            }

            let Some(current) = self.current.as_mut() else {
                return;
            };

            current.as_mut().await;
            self.current = None;
        }
    }
}

impl Drop for CloseBatch {
    fn drop(&mut self) {
        if self.is_empty() {
            return;
        }

        let mut close = Self {
            current: self.current.take(),
            ifaces: mem::take(&mut self.ifaces),
        };
        // Inherent termination: the spawned task owns a finite list of
        // already-drained interfaces and exits after closing each one.
        tokio::spawn(
            async move {
                close.close_all().await;
            }
            .in_current_span(),
        );
    }
}

struct BindEntryPermit {
    key: BindRegistryKey,
    entry: Arc<BindsEntry>,
    _serial: OwnedMutexGuard<()>,
}

struct EntryRelease {
    network: Arc<Network>,
    key: BindRegistryKey,
    entry: Arc<BindsEntry>,
    permit: Option<BindEntryPermit>,
    remove_entry: bool,
    close: CloseBatch,
    completed: bool,
}

struct PendingBindRegistration {
    network: Arc<Network>,
    permit: Option<BindEntryPermit>,
    new_bindings: Vec<(String, BindUri, BindInterface)>,
}

impl BindEntryPermit {
    fn begin_bind_registration(self, network: Arc<Network>) -> PendingBindRegistration {
        PendingBindRegistration {
            network,
            permit: Some(self),
            new_bindings: Vec::new(),
        }
    }

    fn plan_added_device_bind(&self, device: &str) -> Vec<BindUri> {
        let state = self.entry.lock_state();
        if state.closing {
            return Vec::new();
        }
        state.missing_added_device_uris(&self.entry.pattern, device)
    }

    fn commit_added_device(
        &self,
        device_exists: bool,
        new_bindings: Vec<(String, BindUri, BindInterface)>,
    ) -> CloseBatch {
        let mut state = self.entry.lock_state();
        let mut close = CloseBatch::new();

        if state.closing || !device_exists {
            close.extend(new_bindings.into_iter().map(|(_, _, iface)| iface));
            return close;
        }

        for (key, uri, iface) in new_bindings {
            if let std::collections::hash_map::Entry::Vacant(slot) = state.bound.entry(key) {
                slot.insert((uri, iface));
            } else {
                close.push(iface);
            }
        }

        close
    }

    fn drain_removed_device(&self, device: &str) -> CloseBatch {
        let mut state = self.entry.lock_state();
        if state.closing {
            return CloseBatch::new();
        }
        state.drain_device_bindings(device)
    }

    fn targets_for_changed_device(&self, device: &str) -> Vec<BindInterface> {
        let state = self.entry.lock_state();
        if state.closing {
            return Vec::new();
        }
        state.changed_device_targets(device)
    }

    fn release_one_handle(self, network: Arc<Network>) -> EntryRelease {
        let mut state = self.entry.lock_state();
        let mut close = CloseBatch::new();
        let mut remove_entry = false;

        if !state.closing && state.refcount > 0 {
            state.refcount -= 1;
            if state.refcount == 0 {
                state.closing = true;
                close.extend(state.bound.drain().map(|(_, (_, iface))| iface));
                remove_entry = true;
            }
        }

        drop(state);

        EntryRelease {
            network,
            key: self.key.clone(),
            entry: self.entry.clone(),
            permit: Some(self),
            remove_entry,
            close,
            completed: false,
        }
    }
}

impl EntryRelease {
    async fn finish(mut self) {
        self.close.close_all().await;

        if self.remove_entry {
            self.network.remove_entry_if_current(&self.key, &self.entry);
            self.remove_entry = false;
        }

        self.completed = true;
    }
}

impl Drop for EntryRelease {
    fn drop(&mut self) {
        if self.completed {
            return;
        }

        if self.close.is_empty() {
            if self.remove_entry {
                self.network.remove_entry_if_current(&self.key, &self.entry);
                self.remove_entry = false;
            }
            return;
        }

        let Some(permit) = self.permit.take() else {
            return;
        };
        let network = self.network.clone();
        let key = self.key.clone();
        let entry = self.entry.clone();
        let remove_entry = self.remove_entry;
        self.remove_entry = false;
        let mut close = mem::take(&mut self.close);

        // Inherent termination: the spawned task owns the exact entry permit
        // plus a finite close batch, then removes the same registry entry if
        // this was the final release.
        tokio::spawn(
            async move {
                let _permit = permit;
                close.close_all().await;
                if remove_entry {
                    network.remove_entry_if_current(&key, &entry);
                }
            }
            .in_current_span(),
        );
    }
}

impl PendingBindRegistration {
    fn close_new_bindings(&mut self) -> CloseBatch {
        let mut close = CloseBatch::new();
        close.extend(
            mem::take(&mut self.new_bindings)
                .into_iter()
                .map(|(_, _, iface)| iface),
        );
        close
    }

    fn abandon_uncommitted_entry(
        network: Arc<Network>,
        permit: BindEntryPermit,
        mut close: CloseBatch,
    ) {
        let remove_entry = {
            let mut state = permit.entry.lock_state();
            let remove_entry = state.refcount == 0 && state.bound.is_empty();
            if remove_entry {
                state.closing = true;
            }
            remove_entry
        };

        if close.is_empty() {
            if remove_entry {
                network.remove_entry_if_current(&permit.key, &permit.entry);
            }
            return;
        }

        let key = permit.key.clone();
        let entry = permit.entry.clone();

        // Inherent termination: the spawned task owns the uncommitted
        // interfaces and exact entry permit, closes the finite batch, then
        // removes the still-unowned registry entry when appropriate.
        tokio::spawn(
            async move {
                let _permit = permit;
                close.close_all().await;
                if remove_entry {
                    network.remove_entry_if_current(&key, &entry);
                }
            }
            .in_current_span(),
        );
    }

    fn plan_current_devices_bind(&self, devices: &'static Devices) -> Vec<BindUri> {
        let permit = self.permit.as_ref().expect("pending bind has permit");
        let state = permit.entry.lock_state();
        if state.closing {
            return Vec::new();
        }
        state.missing_current_device_uris(&permit.entry.pattern, devices)
    }

    fn push_new_binding(&mut self, uri: BindUri, iface: BindInterface) {
        self.new_bindings.push((uri.identity_key(), uri, iface));
    }

    fn commit_into_handle(mut self, network: Arc<Network>) -> BindHandle {
        let permit = self.permit.take().expect("pending bind has permit");
        let new_bindings = mem::take(&mut self.new_bindings);

        {
            let mut state = permit.entry.lock_state();
            debug_assert!(!state.closing, "permit should not commit a closing entry");
            state.refcount += 1;
            let mut close = CloseBatch::new();
            for (key, uri, iface) in new_bindings {
                if let std::collections::hash_map::Entry::Vacant(slot) = state.bound.entry(key) {
                    slot.insert((uri, iface));
                } else {
                    close.push(iface);
                }
            }
            drop(close);
        }

        BindHandle {
            network,
            key: permit.key.clone(),
            entry: permit.entry.clone(),
            released: false,
        }
    }
}

impl Drop for PendingBindRegistration {
    fn drop(&mut self) {
        let close = self.close_new_bindings();
        let Some(permit) = self.permit.take() else {
            drop(close);
            return;
        };

        Self::abandon_uncommitted_entry(self.network.clone(), permit, close);
    }
}

/// RAII handle returned by [`QuicBindDriver::bind`] or [`Network::bind_with`].
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
    key: BindRegistryKey,
    entry: Arc<BindsEntry>,
    released: bool,
}

/// IO implementation used by non-packet bind drivers during the current
/// `InterfaceManager` transition.
///
/// It only carries a [`BindUri`] and does not provide any packet I/O.
#[derive(Debug)]
pub struct NullIo {
    bind_uri: BindUri,
}

impl NullIo {
    #[must_use]
    pub fn new(bind_uri: BindUri) -> Self {
        Self { bind_uri }
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "null io does not support packet operations",
        )
    }
}

#[derive(Debug, Default)]
pub struct NullIoFactory;

impl ProductIO for NullIoFactory {
    fn bind(&self, bind_uri: BindUri) -> Box<dyn crate::dquic::net::IO> {
        Box::new(NullIo::new(bind_uri))
    }
}

impl crate::dquic::net::IO for NullIo {
    fn bind_uri(&self) -> BindUri {
        self.bind_uri.clone()
    }

    fn bound_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(Self::unsupported())
    }

    fn max_segment_size(&self) -> io::Result<usize> {
        Err(Self::unsupported())
    }

    fn max_segments(&self) -> io::Result<usize> {
        Err(Self::unsupported())
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        _pkts: &[io::IoSlice],
        _route: crate::dquic::qbase::net::route::Route,
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(Self::unsupported()))
    }

    fn poll_recv(
        &self,
        _cx: &mut Context,
        _pkts: &mut [bytes::BytesMut],
        _route: &mut [crate::dquic::qbase::net::route::Route],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(Self::unsupported()))
    }

    fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Builder (bon)
// ---------------------------------------------------------------------------

#[bon::bon]
impl Network {
    #[builder(start_fn(name = builder, vis = "pub"), builder_type(vis = "pub"))]
    fn new(
        stun_server: Option<Arc<str>>,
        #[builder(default = Arc::new(InterfaceManager::new()))] iface_manager: Arc<
            InterfaceManager,
        >,
        #[builder(default = Arc::new(DEFAULT_IO_FACTORY))] io_factory: Arc<dyn ProductIO + 'static>,
        #[builder(default = Arc::new(SystemResolver))] stun_resolver: Arc<
            dyn Resolve + Send + Sync,
        >,
        #[builder(default = Arc::new(QuicRouter::new()))] quic_router: Arc<QuicRouter>,
        #[builder(default = Arc::new(Locations::new()))] locations: Arc<Locations>,
        #[builder(default = Devices::global())] devices: &'static Devices,
    ) -> Arc<Self> {
        Self::build_with_quic_driver(devices, |network| {
            QuicBindDriver::builder()
                .network(network.clone())
                .iface_manager(iface_manager)
                .io_factory(io_factory)
                .stun_resolver(stun_resolver)
                .maybe_stun_server(stun_server)
                .quic_router(quic_router)
                .locations(locations)
                .build()
        })
    }
}

// ---------------------------------------------------------------------------
// Network methods
// ---------------------------------------------------------------------------

impl Network {
    fn build_with_quic_driver(
        devices: &'static Devices,
        build_quic_driver: impl FnOnce(Weak<Network>) -> Arc<QuicBindDriver>,
    ) -> Arc<Self> {
        let network = Arc::new_cyclic(|network| {
            let quic_driver = build_quic_driver(network.clone());
            Network {
                devices,
                quic_driver,
                bind_registry: Mutex::new(HashMap::new()),
                _reconcile: OnceLock::new(),
            }
        });

        // Start the background reconcile task that keeps bound interfaces
        // in sync with device changes.
        let reconcile_net = Arc::downgrade(&network);
        let devices = network.devices;
        let handle = tokio::spawn(
            async move {
                Network::run_reconcile(reconcile_net, devices).await;
            }
            .in_current_span(),
        );
        let _ = network._reconcile.set(AbortOnDropHandle::new(handle));

        network
    }

    /// Return the built-in QUIC runtime view for QUIC-specific operations.
    #[must_use]
    pub fn quic(&self) -> Arc<QuicBindDriver> {
        self.quic_driver.clone()
    }

    async fn acquire_or_insert_entry(
        self: &Arc<Self>,
        key: BindRegistryKey,
        driver: Arc<dyn BindDriver>,
    ) -> BindEntryPermit {
        loop {
            let entry = {
                let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
                registry
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(BindsEntry::new(key.clone(), driver.clone())))
                    .clone()
            };

            let serial = entry.serial.clone().lock_owned().await;

            let current = {
                let registry = self.bind_registry.lock().expect("bind_registry poisoned");
                registry
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry))
            };

            if current && !entry.is_closing() {
                return BindEntryPermit {
                    key: key.clone(),
                    entry,
                    _serial: serial,
                };
            }
        }
    }

    async fn acquire_existing_entry(
        &self,
        key: BindRegistryKey,
        entry: Arc<BindsEntry>,
    ) -> Option<BindEntryPermit> {
        let serial = entry.serial.clone().lock_owned().await;

        let current = {
            let registry = self.bind_registry.lock().expect("bind_registry poisoned");
            registry
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &entry))
        };

        current.then_some(BindEntryPermit {
            key,
            entry,
            _serial: serial,
        })
    }

    fn entries_matching_device(&self, device: &str) -> Vec<BindEntryRef> {
        let registry = self.bind_registry.lock().expect("bind_registry poisoned");
        registry
            .values()
            .filter(|entry| entry.pattern_matches_device(device))
            .map(|entry| BindEntryRef {
                key: entry.key.clone(),
                entry: entry.clone(),
            })
            .collect()
    }

    fn remove_entry_if_current(&self, key: &BindRegistryKey, entry: &Arc<BindsEntry>) {
        let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
        if registry
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
        {
            registry.remove(key);
        }
    }

    /// Register a [`BindPattern`] through an explicit binding driver.
    pub async fn bind_with<D>(self: &Arc<Self>, driver: Arc<D>, pattern: BindPattern) -> BindHandle
    where
        D: BindDriver + 'static,
    {
        let key = BindRegistryKey {
            driver: bind_driver_id(&driver),
            pattern,
        };
        let driver_erased: Arc<dyn BindDriver> = driver;

        let permit = self
            .acquire_or_insert_entry(key, driver_erased.clone())
            .await;
        let mut pending = permit.begin_bind_registration(self.clone());

        for uri in pending.plan_current_devices_bind(self.devices) {
            let iface = driver_erased.bind(self, uri.clone()).await;
            pending.push_new_binding(uri, iface);
        }

        pending.commit_into_handle(self.clone())
    }

    /// Release a previously registered [`BindPattern`] and its bound
    /// interfaces.
    async fn release_exact_entry(self: &Arc<Self>, key: BindRegistryKey, entry: Arc<BindsEntry>) {
        let Some(permit) = self
            .acquire_existing_entry(key.clone(), entry.clone())
            .await
        else {
            return;
        };

        permit.release_one_handle(self.clone()).finish().await;
    }

    /// Resolve the current address for a device and IP family.
    ///
    /// Bind drivers use this to derive per-device resources from the same
    /// device snapshot that drives [`Network`] reconciliation.
    #[must_use]
    pub fn resolve_device_addr(&self, device: &str, family: Family) -> Option<IpAddr> {
        self.devices.resolve(device, family)
    }

    /// Return whether `bound_addr` belongs to the currently-default interface
    /// represented by `bind_uri`.
    ///
    /// Stale bind handles can briefly outlive netlink reconciliation after a
    /// device is removed. In that case the device is absent from the current
    /// snapshot and this method returns `false`.
    #[must_use]
    pub fn bound_addr_is_on_default_route(
        &self,
        bind_uri: &BindUri,
        bound_addr: SocketAddr,
    ) -> bool {
        let Some((family, device, _port)) = bind_uri.as_iface_bind_uri() else {
            return false;
        };
        let bound_family = if bound_addr.is_ipv4() {
            Family::V4
        } else {
            Family::V6
        };
        if family != bound_family {
            return false;
        }

        self.devices.get(device).is_some_and(|interface| {
            interface.default && interface_contains(&interface, bound_addr.ip())
        })
    }

    /// Return all currently bound interfaces for a specific driver and pattern.
    #[must_use]
    pub fn get_interfaces_with<D>(
        &self,
        driver: &Arc<D>,
        pattern: &BindPattern,
    ) -> Option<Vec<BindInterface>>
    where
        D: BindDriver + ?Sized,
    {
        let key = BindRegistryKey {
            driver: bind_driver_id(driver),
            pattern: pattern.clone(),
        };
        let registry = self.bind_registry.lock().expect("bind_registry poisoned");
        registry.get(&key).map(|entry| {
            entry
                .lock_state()
                .bound
                .values()
                .map(|(_, iface)| iface.clone())
                .collect()
        })
    }

    /// Background task that reconciles bound interfaces with device changes.
    async fn run_reconcile(network: Weak<Network>, devices: &'static Devices) {
        let mut monitor = devices.monitor();
        while let Some((_interfaces, event)) = monitor.update().await {
            let Some(network) = network.upgrade() else {
                break;
            };
            tracing::debug!(
                ?event,
                "network interface change, reconciling affected binds"
            );
            network.reconcile_event(event.as_ref()).await;
        }
    }

    async fn bind_added_device(&self, device: &str) {
        if self.devices.get(device).is_none() {
            return;
        }

        for entry_ref in self.entries_matching_device(device) {
            let Some(permit) = self
                .acquire_existing_entry(entry_ref.key, entry_ref.entry)
                .await
            else {
                continue;
            };

            let missing = permit.plan_added_device_bind(device);
            let mut new_bindings = Vec::with_capacity(missing.len());
            for uri in missing {
                if self.devices.get(device).is_none() {
                    break;
                }
                let iface = permit.entry.driver.bind(self, uri.clone()).await;
                new_bindings.push((uri.identity_key(), uri, iface));
            }

            let mut close =
                permit.commit_added_device(self.devices.get(device).is_some(), new_bindings);
            close.close_all().await;

            if self.devices.get(device).is_none() {
                return;
            }
        }
    }

    async fn remove_device_bindings(&self, device: &str) {
        for entry_ref in self.entries_matching_device(device) {
            let Some(permit) = self
                .acquire_existing_entry(entry_ref.key, entry_ref.entry)
                .await
            else {
                continue;
            };

            let mut close = permit.drain_removed_device(device);
            close.close_all().await;
        }
    }

    async fn rebind_changed_device(&self, device: &str) {
        if self.devices.get(device).is_none() {
            return;
        }

        for entry_ref in self.entries_matching_device(device) {
            if self.devices.get(device).is_none() {
                return;
            }

            let Some(permit) = self
                .acquire_existing_entry(entry_ref.key, entry_ref.entry)
                .await
            else {
                continue;
            };

            for iface in permit.targets_for_changed_device(device) {
                permit.entry.driver.rebind(self, &iface).await;
            }
        }
    }

    /// Extracted reconcile logic, run per interface change.
    async fn reconcile_event(&self, event: &InterfaceEvent) {
        let device = event.device();

        match event {
            InterfaceEvent::Added { .. } => {
                self.bind_added_device(device).await;
            }
            InterfaceEvent::Removed { .. } => {
                self.remove_device_bindings(device).await;
            }
            InterfaceEvent::Changed { .. } => {
                self.rebind_changed_device(device).await;
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
        server_authority: &LocalAuthority,
        _client_name: Option<&str>,
    ) -> ClientNameVerifyResult {
        let sni = server_authority.name();
        let sni_lower = sni.to_ascii_lowercase();
        let entry = self
            .sni_registry
            .get::<str>(&sni_lower)
            .and_then(|item| item.value().upgrade());

        match entry {
            None => ClientNameVerifyResult::SilentRefuse("no server registered for SNI".to_owned()),
            Some(entry) if entry.bind.is_empty() => ClientNameVerifyResult::Accept,
            Some(entry) if entry.bind.iter().any(|p| p.matches(&self.bind_uri)) => {
                ClientNameVerifyResult::Accept
            }
            Some(_) => ClientNameVerifyResult::SilentRefuse("bind pattern mismatch".to_owned()),
        }
    }

    fn verify_client_authority(
        &self,
        _server_authority: &LocalAuthority,
        _client_authority: &RemoteAuthority,
    ) -> ClientAuthorityVerifyResult {
        ClientAuthorityVerifyResult::Accept
    }
}

// ---------------------------------------------------------------------------
// BindHandle
// ---------------------------------------------------------------------------

impl BindHandle {
    /// Release the bind pattern synchronously.
    pub async fn unbind(&mut self) {
        if !self.released {
            self.network
                .release_exact_entry(self.key.clone(), self.entry.clone())
                .await;
            self.released = true;
        }
    }
}

impl Drop for BindHandle {
    fn drop(&mut self) {
        if !self.released {
            let network = self.network.clone();
            let key = self.key.clone();
            let entry = self.entry.clone();
            // Inherent termination: the spawned task exits after the unbind
            // completes. If the runtime is shutting down, the unbind is
            // best-effort.
            tokio::spawn(
                async move {
                    network.release_exact_entry(key, entry).await;
                }
                .in_current_span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        str::FromStr,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::Waker,
        time::Duration,
    };

    use dquic::{
        prelude::{IO, handy::NoopTokenRegistry},
        qinterface::device::{Interface, InterfaceEvent},
    };
    use futures::{FutureExt, StreamExt, future::BoxFuture};
    use rustls::ClientConfig as TlsClientConfig;

    use super::*;
    use crate::dquic::{binds::BindPattern, identity::Identity};

    fn make_identity(name: &str) -> Arc<Identity> {
        use dquic::prelude::handy::{ToCertificate, ToPrivateKey};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        let certs: Vec<CertificateDer<'static>> = SERVER_CERT.to_certificate();
        let key: PrivateKeyDer<'static> = SERVER_KEY.to_private_key();

        Arc::new(Identity {
            name: name.parse().unwrap(),
            certs: Arc::new(certs),
            key: Arc::new(key),
            ocsp: Arc::new(None),
        })
    }

    fn make_server_config() -> ServerQuicConfig {
        ServerQuicConfig::default()
    }

    fn make_local_authority(name: &str) -> LocalAuthority {
        let identity = make_identity(name);
        let certified_key =
            crate::dquic::identity::build_certified_key(&identity).expect("valid certified key");
        LocalAuthority::new(Arc::from(name), certified_key)
    }

    fn make_remote_authority(name: &str) -> RemoteAuthority {
        let identity = make_identity(name);
        RemoteAuthority::new(Arc::from(name), Arc::from(identity.certs.as_slice()))
    }

    struct TestNullDriver {
        manager: Arc<crate::dquic::net::InterfaceManager>,
    }

    impl TestNullDriver {
        fn new() -> Self {
            Self {
                manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
            }
        }
    }

    impl BindDriver for TestNullDriver {
        fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
            async move { self.manager.bind(uri, Arc::new(NullIo::new)).await }.boxed()
        }
    }

    fn dummy_interface_named(name: &str) -> Interface {
        let mut interface = Interface::dummy();
        interface.name = name.to_owned();
        interface
    }

    fn added_event(device: &str) -> InterfaceEvent {
        InterfaceEvent::Added {
            device: device.to_owned(),
            new_interface: dummy_interface_named(device),
        }
    }

    fn removed_event(device: &str) -> InterfaceEvent {
        InterfaceEvent::Removed {
            device: device.to_owned(),
            old_interface: dummy_interface_named(device),
        }
    }

    fn changed_event(device: &str) -> InterfaceEvent {
        InterfaceEvent::Changed {
            device: device.to_owned(),
            old_interface: dummy_interface_named(device),
            new_interface: dummy_interface_named(device),
        }
    }

    struct CountingDriver {
        manager: Arc<crate::dquic::net::InterfaceManager>,
        binds: AtomicUsize,
        rebinds: AtomicUsize,
    }

    impl CountingDriver {
        fn new() -> Self {
            Self {
                manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
                binds: AtomicUsize::new(0),
                rebinds: AtomicUsize::new(0),
            }
        }

        fn bind_count(&self) -> usize {
            self.binds.load(Ordering::Relaxed)
        }

        fn rebind_count(&self) -> usize {
            self.rebinds.load(Ordering::Relaxed)
        }
    }

    impl BindDriver for CountingDriver {
        fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
            async move {
                self.binds.fetch_add(1, Ordering::Relaxed);
                self.manager.bind(uri, Arc::new(NullIoFactory)).await
            }
            .boxed()
        }

        fn rebind<'a>(
            &'a self,
            _network: &'a Network,
            _iface: &'a BindInterface,
        ) -> BoxFuture<'a, ()> {
            async move {
                self.rebinds.fetch_add(1, Ordering::Relaxed);
            }
            .boxed()
        }
    }

    #[derive(Debug)]
    struct CloseCountingFactory {
        closes: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct CloseCountingIo {
        bind_uri: BindUri,
        closes: Arc<AtomicUsize>,
    }

    impl ProductIO for CloseCountingFactory {
        fn bind(&self, bind_uri: BindUri) -> Box<dyn crate::dquic::net::IO> {
            Box::new(CloseCountingIo {
                bind_uri,
                closes: self.closes.clone(),
            })
        }
    }

    impl crate::dquic::net::IO for CloseCountingIo {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not needed"))
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1200)
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(1)
        }

        fn poll_send(
            &self,
            _cx: &mut Context,
            _pkts: &[io::IoSlice],
            _route: crate::dquic::qbase::net::route::Route,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _pkts: &mut [bytes::BytesMut],
            _route: &mut [crate::dquic::qbase::net::route::Route],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    struct CloseCountingDriver {
        manager: Arc<crate::dquic::net::InterfaceManager>,
        closes: Arc<AtomicUsize>,
    }

    impl CloseCountingDriver {
        fn new() -> Self {
            Self {
                manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
                closes: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn close_count(&self) -> usize {
            self.closes.load(Ordering::SeqCst)
        }
    }

    impl BindDriver for CloseCountingDriver {
        fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
            async move {
                self.manager
                    .bind(
                        uri,
                        Arc::new(CloseCountingFactory {
                            closes: self.closes.clone(),
                        }),
                    )
                    .await
            }
            .boxed()
        }
    }

    struct BlockingCloseControl {
        close_started: AtomicBool,
        release_close: AtomicBool,
        close_waker: StdMutex<Option<Waker>>,
        close_completed: AtomicUsize,
        close_started_notify: tokio::sync::Notify,
    }

    impl BlockingCloseControl {
        fn new() -> Self {
            Self {
                close_started: AtomicBool::new(false),
                release_close: AtomicBool::new(false),
                close_waker: StdMutex::new(None),
                close_completed: AtomicUsize::new(0),
                close_started_notify: tokio::sync::Notify::new(),
            }
        }

        async fn wait_close_started(&self) {
            if self.close_started.load(Ordering::SeqCst) {
                return;
            }
            self.close_started_notify.notified().await;
        }

        fn release_close(&self) {
            self.release_close.store(true, Ordering::SeqCst);
            if let Some(waker) = self
                .close_waker
                .lock()
                .expect("close waker mutex poisoned")
                .take()
            {
                waker.wake();
            }
        }

        fn complete_count(&self) -> usize {
            self.close_completed.load(Ordering::SeqCst)
        }
    }

    struct BlockingCloseFactory {
        control: Arc<BlockingCloseControl>,
    }

    struct BlockingCloseIo {
        bind_uri: BindUri,
        control: Arc<BlockingCloseControl>,
        closed: bool,
    }

    impl ProductIO for BlockingCloseFactory {
        fn bind(&self, bind_uri: BindUri) -> Box<dyn crate::dquic::net::IO> {
            Box::new(BlockingCloseIo {
                bind_uri,
                control: self.control.clone(),
                closed: false,
            })
        }
    }

    impl crate::dquic::net::IO for BlockingCloseIo {
        fn bind_uri(&self) -> BindUri {
            self.bind_uri.clone()
        }

        fn bound_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "not needed"))
        }

        fn max_segment_size(&self) -> io::Result<usize> {
            Ok(1200)
        }

        fn max_segments(&self) -> io::Result<usize> {
            Ok(1)
        }

        fn poll_send(
            &self,
            _cx: &mut Context,
            _pkts: &[io::IoSlice],
            _route: crate::dquic::qbase::net::route::Route,
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }

        fn poll_recv(
            &self,
            _cx: &mut Context,
            _pkts: &mut [bytes::BytesMut],
            _route: &mut [crate::dquic::qbase::net::route::Route],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_close(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
            if self.closed {
                return Poll::Ready(Ok(()));
            }

            self.control.close_started.store(true, Ordering::SeqCst);
            self.control.close_started_notify.notify_one();

            if self.control.release_close.load(Ordering::SeqCst) {
                self.closed = true;
                self.control.close_completed.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            } else {
                *self
                    .control
                    .close_waker
                    .lock()
                    .expect("close waker mutex poisoned") = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }

    struct BlockingCloseDriver {
        manager: Arc<crate::dquic::net::InterfaceManager>,
        control: Arc<BlockingCloseControl>,
    }

    impl BlockingCloseDriver {
        fn new() -> Self {
            Self {
                manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
                control: Arc::new(BlockingCloseControl::new()),
            }
        }

        async fn wait_close_started(&self) {
            self.control.wait_close_started().await;
        }

        fn release_close(&self) {
            self.control.release_close();
        }

        fn complete_count(&self) -> usize {
            self.control.complete_count()
        }
    }

    impl BindDriver for BlockingCloseDriver {
        fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
            async move {
                self.manager
                    .bind(
                        uri,
                        Arc::new(BlockingCloseFactory {
                            control: self.control.clone(),
                        }),
                    )
                    .await
            }
            .boxed()
        }
    }

    struct SlowCountingDriver {
        manager: Arc<crate::dquic::net::InterfaceManager>,
        active: AtomicUsize,
        max_active: AtomicUsize,
        binds: AtomicUsize,
    }

    impl SlowCountingDriver {
        fn new() -> Self {
            Self {
                manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
                binds: AtomicUsize::new(0),
            }
        }

        fn max_active(&self) -> usize {
            self.max_active.load(Ordering::SeqCst)
        }

        fn bind_count(&self) -> usize {
            self.binds.load(Ordering::SeqCst)
        }
    }

    impl BindDriver for SlowCountingDriver {
        fn bind<'a>(&'a self, _network: &'a Network, uri: BindUri) -> BoxFuture<'a, BindInterface> {
            async move {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_active.fetch_max(active, Ordering::SeqCst);
                self.binds.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                let iface = self.manager.bind(uri, Arc::new(NullIoFactory)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                iface
            }
            .boxed()
        }
    }

    async fn clear_bound_for_test(
        network: &Network,
        driver: &Arc<CountingDriver>,
        pattern: &BindPattern,
    ) {
        let key = BindRegistryKey {
            driver: bind_driver_id(driver),
            pattern: pattern.clone(),
        };
        let mut close = {
            let registry = network
                .bind_registry
                .lock()
                .expect("bind_registry poisoned");
            let entry = registry.get(&key).expect("registered pattern");
            let mut state = entry.lock_state();
            let mut close = CloseBatch::new();
            close.extend(state.bound.drain().map(|(_, (_, iface))| iface));
            close
        };
        close.close_all().await;
    }

    #[derive(Debug)]
    struct MarkerResolver;

    impl std::fmt::Display for MarkerResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("marker resolver")
        }
    }

    impl Resolve for MarkerResolver {
        fn lookup<'a>(&'a self, _name: &'a str) -> crate::dquic::resolver::ResolveFuture<'a> {
            async move { Ok(futures::stream::empty().boxed()) }.boxed()
        }
    }

    #[tokio::test]
    async fn network_builder_accepts_custom_stun_resolver() {
        let resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(MarkerResolver);
        let network = Network::builder().stun_resolver(resolver.clone()).build();

        assert!(Arc::ptr_eq(&network.quic().stun_resolver, &resolver));
    }

    #[tokio::test]
    async fn network_builder_forwards_quic_bind_driver_options() {
        let iface_manager = Arc::new(InterfaceManager::new());
        let io_factory: Arc<dyn ProductIO + 'static> = Arc::new(NullIoFactory);
        let stun_resolver: Arc<dyn Resolve + Send + Sync> = Arc::new(MarkerResolver);
        let quic_router = Arc::new(QuicRouter::new());
        let locations = Arc::new(Locations::new());

        let network = Network::builder()
            .iface_manager(iface_manager.clone())
            .io_factory(io_factory.clone())
            .stun_resolver(stun_resolver.clone())
            .stun_server(Arc::from("builder.stun.example:3478"))
            .quic_router(quic_router.clone())
            .locations(locations.clone())
            .build();
        let quic = network.quic();

        assert!(Arc::ptr_eq(&quic.iface_manager, &iface_manager));
        assert!(Arc::ptr_eq(&quic.io_factory, &io_factory));
        assert!(Arc::ptr_eq(&quic.stun_resolver, &stun_resolver));
        assert_eq!(
            quic.stun_server.as_deref(),
            Some("builder.stun.example:3478")
        );
        assert!(Arc::ptr_eq(&quic.quic_router, &quic_router));
        assert!(Arc::ptr_eq(&quic.locations, &locations));
    }

    #[test]
    fn interface_contains_matches_ipv4_and_ipv6_networks() {
        let mut interface = ::dquic::qinterface::device::Interface::dummy();
        interface.ipv4.push("192.0.2.10/24".parse().unwrap());
        interface.ipv6.push("2001:db8::10/64".parse().unwrap());

        assert!(interface_contains(
            &interface,
            "192.0.2.99".parse().unwrap()
        ));
        assert!(!interface_contains(
            &interface,
            "198.51.100.1".parse().unwrap()
        ));
        assert!(interface_contains(
            &interface,
            "2001:db8::99".parse().unwrap()
        ));
        assert!(!interface_contains(
            &interface,
            "2001:db9::1".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn default_bind_driver_rebind_is_noop() {
        let network = Network::builder().build();
        let driver = Arc::new(TestNullDriver::new());
        let uri: BindUri = "iface://v4.lo:0".parse().expect("valid bind uri");
        let iface = driver.bind(&network, uri).await;

        driver.rebind(&network, &iface).await;
    }

    #[tokio::test]
    async fn test_bind_server_overwrite() {
        let network = Network::builder().build();
        let identity_a = make_identity("test.example.com");
        let identity_b = make_identity("test.example.com");
        let config = make_server_config();

        let binding_a = network
            .quic()
            .bind_server(identity_a.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .quic()
            .bind_server(identity_b.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with different identity should succeed (overwrite)");

        assert_eq!(binding_a.name(), binding_b.name());
        let quic = network.quic();
        assert_eq!(quic.sni_registry.len(), 1);

        let entry = quic
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
            .quic()
            .bind_server(identity.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .quic()
            .bind_server(identity.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with same identity should succeed (reuse)");

        assert_eq!(binding_a.name(), binding_b.name());
        let quic = network.quic();
        assert_eq!(quic.sni_registry.len(), 1);

        let entry_a = quic
            .sni_registry
            .get(binding_a.name())
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the entry");
        let entry_b = quic
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
        let locations = network.quic().locations();
        let _cloned = locations.clone();
    }

    #[tokio::test]
    async fn quic_driver_exposes_quic_specific_queries() {
        let network = Network::builder().build();
        let quic: Arc<QuicBindDriver> = network.quic();
        assert!(Arc::ptr_eq(&quic, &network.quic()));
        assert!(Arc::ptr_eq(&quic.locations(), &network.quic().locations()));

        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");
        let mut handle = quic.clone().bind(pattern.clone()).await;

        let quic_interfaces = quic.interfaces();

        let quic_uris = quic.current_bind_uris();

        if let Some(uri) = quic_uris.first() {
            assert!(quic.get_iface(uri).is_some());
        }

        assert_eq!(
            quic.get_interfaces(&pattern)
                .expect("quic interfaces should be registered")
                .len(),
            quic_interfaces.len()
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn network_drop_is_not_prevented_by_background_callbacks() {
        let network = Network::builder().build();
        let weak = Arc::downgrade(&network);

        drop(network);
        tokio::task::yield_now().await;

        assert!(
            weak.upgrade().is_none(),
            "network should not be retained by reconcile or router callbacks"
        );
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_empty() {
        let network = Network::builder().build();
        assert!(
            network.quic().registered_sni_names().is_empty(),
            "fresh network should have no registered sni names"
        );
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_after_bind() {
        let network = Network::builder().build();
        let identity = make_identity("alpha");
        let config = make_server_config();

        let _binding = network
            .quic()
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        let names = network.quic().registered_sni_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].as_str(), "alpha");
    }

    #[tokio::test]
    async fn test_network_registered_sni_names_after_drop() {
        let network = Network::builder().build();
        let identity = make_identity("alpha");
        let config = make_server_config();

        let binding = network
            .quic()
            .bind_server(identity, config, Arc::new(Vec::new()))
            .await
            .expect("bind should succeed");

        assert_eq!(network.quic().registered_sni_names().len(), 1);
        drop(binding);
        assert!(
            network.quic().registered_sni_names().is_empty(),
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
            .quic()
            .bind_server(identity_a.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .quic()
            .bind_server(identity_b.clone(), config.clone(), Arc::new(Vec::new()))
            .await
            .expect("second bind with same config should succeed");

        assert_eq!(binding_a.name().as_str(), "a");
        assert_eq!(binding_b.name().as_str(), "b");

        let names = network.quic().registered_sni_names();
        assert_eq!(names.len(), 2, "both names should be registered");
        assert!(names.iter().any(|n| n.as_str() == "a"));
        assert!(names.iter().any(|n| n.as_str() == "b"));
    }

    #[test]
    fn test_bind_server_error_sni_in_use_display() {
        let err = BindServerError::SniInUse {
            name: "example.com".parse().unwrap(),
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
            display.starts_with("quic driver"),
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
            .quic()
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
            .quic()
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
        let new_builder = || {
            let provider = TlsClientConfig::builder().crypto_provider().clone();
            let tls = TlsClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 should be supported")
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth();

            Connection::new_client("test.example.com".to_string(), Arc::new(NoopTokenRegistry))
                .with_tls_config(tls)
        };

        let _foundation = network.quic().configure_connection(new_builder());
        let _foundation = network.quic().configure_connection(new_builder());
    }

    #[test]
    fn test_bind_pattern_parsing() {
        let pattern = BindPattern::from_str("127.0.0.1:8080").expect("valid pattern");
        assert_eq!(pattern.port, Some(8080));
    }

    #[tokio::test]
    async fn bind_server_same_identity_rejects_incompatible_server_config() {
        let network = Network::builder().build();
        let identity = make_identity("same.example.com");
        let cfg_a = make_server_config();
        let cfg_b = ServerQuicConfig {
            alpns: vec![b"altproto".to_vec()],
            ..Default::default()
        };

        let _held = network
            .quic()
            .bind_server(identity.clone(), cfg_a, Arc::new(Vec::new()))
            .await
            .expect("first bind succeeds");

        let error = network
            .quic()
            .bind_server(identity, cfg_b, Arc::new(Vec::new()))
            .await
            .expect_err("same identity with incompatible config must fail");

        assert!(matches!(error, BindServerError::ServerConfigConflict));
    }

    #[tokio::test]
    async fn test_bind_server_config_conflict() {
        let network = Network::builder().build();
        let a = make_identity("alpha");
        let b = make_identity("beta");

        let cfg_a = make_server_config();
        let cfg_b = {
            ServerQuicConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            }
        };

        let _held = network
            .quic()
            .bind_server(a, cfg_a, Arc::new(Vec::new()))
            .await
            .expect("first bind succeeds");
        let err = network
            .quic()
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
            ServerQuicConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            }
        };

        {
            let _first = network
                .quic()
                .bind_server(make_identity("alpha"), cfg_a, Arc::new(Vec::new()))
                .await
                .expect("first bind succeeds");
        }
        // After the binding drops the slot should clear, allowing a new
        // incompatible config to install.
        let _second = network
            .quic()
            .bind_server(make_identity("beta"), cfg_b, Arc::new(Vec::new()))
            .await
            .expect("slot should auto-reset after last binding dropped");
    }

    #[test]
    fn null_io_only_exposes_bind_uri_and_close() {
        use std::task::{Context, Poll};

        use bytes::BytesMut;
        use dquic::{qbase::net::route::Route, qinterface::io::IO};
        use futures::task::noop_waker;

        let bind_uri: BindUri = "iface://v4.lo:0".parse().expect("valid bind uri");
        let mut io = NullIo::new(bind_uri.clone());
        assert_eq!(io.bind_uri(), bind_uri);
        assert!(io.bound_addr().is_err());
        assert!(io.max_segment_size().is_err());
        assert!(io.max_segments().is_err());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let send = io.poll_send(&mut cx, &[], Route::empty());
        assert!(matches!(send, Poll::Ready(Err(_))));

        let mut packets = Vec::<BytesMut>::new();
        let mut routes = Vec::<Route>::new();
        let recv = io.poll_recv(&mut cx, &mut packets, &mut routes);
        assert!(matches!(recv, Poll::Ready(Err(_))));

        assert!(matches!(io.poll_close(&mut cx), Poll::Ready(Ok(()))));
    }

    #[tokio::test]
    async fn bind_with_keeps_driver_bindings_separate_for_same_pattern() {
        let network = Network::builder().build();
        let driver_a = Arc::new(TestNullDriver::new());
        let driver_b = Arc::new(TestNullDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle_a = network.bind_with(driver_a.clone(), pattern.clone()).await;
        let mut handle_b = network.bind_with(driver_b.clone(), pattern.clone()).await;

        let a_ifaces = network
            .get_interfaces_with(&driver_a, &pattern)
            .expect("driver a bindings");
        let b_ifaces = network
            .get_interfaces_with(&driver_b, &pattern)
            .expect("driver b bindings");

        assert_eq!(a_ifaces.len(), b_ifaces.len());
        assert!(!a_ifaces.is_empty());
        assert!(!a_ifaces[0].borrow().same_io(&b_ifaces[0].borrow()));
        assert!(
            network.quic().interfaces().is_empty(),
            "non-quic driver binds must not appear in quic interface queries"
        );
        assert!(
            network.quic().current_bind_uris().is_empty(),
            "non-quic driver binds must not appear in quic bind uri queries"
        );
        assert!(
            network.quic().get_interfaces(&pattern).is_none(),
            "non-quic driver binds must not appear in quic pattern queries"
        );

        handle_a.unbind().await;
        handle_b.unbind().await;
    }

    #[tokio::test]
    async fn bind_entry_operations_are_serialized_per_key() {
        let network = Network::builder().build();
        let driver = Arc::new(SlowCountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let first = tokio::spawn({
            let network = network.clone();
            let driver = driver.clone();
            let pattern = pattern.clone();
            async move { network.bind_with(driver, pattern).await }.in_current_span()
        });
        let second = tokio::spawn({
            let network = network.clone();
            let driver = driver.clone();
            let pattern = pattern.clone();
            async move { network.bind_with(driver, pattern).await }.in_current_span()
        });

        let mut first = first.await.expect("first bind task should not panic");
        let mut second = second.await.expect("second bind task should not panic");

        assert_eq!(
            driver.max_active(),
            1,
            "same entry must not run driver.bind concurrently"
        );
        assert_eq!(
            driver.bind_count(),
            1,
            "second bind should reuse the first entry membership"
        );

        first.unbind().await;
        second.unbind().await;
    }

    #[tokio::test]
    async fn canceled_pending_bind_registration_removes_unowned_entry_after_closing() {
        let network = Network::builder().build();
        let driver = Arc::new(CloseCountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");
        let key = BindRegistryKey {
            driver: bind_driver_id(&driver),
            pattern,
        };
        let driver_erased: Arc<dyn BindDriver> = driver.clone();

        let permit = network
            .acquire_or_insert_entry(key.clone(), driver_erased.clone())
            .await;
        let mut pending = permit.begin_bind_registration(network.clone());
        let uri: BindUri = "iface://v4.lo:0".parse().expect("valid bind uri");
        let iface = driver_erased.bind(&network, uri.clone()).await;
        pending.push_new_binding(uri, iface);

        drop(pending);

        tokio::time::timeout(Duration::from_secs(1), async {
            while network.get_interfaces_with(&driver, &key.pattern).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("canceled pending registration should remove the unowned registry entry");

        assert!(
            driver.close_count() > 0,
            "canceled pending registration should close uncommitted interfaces"
        );
    }

    #[tokio::test]
    async fn canceled_unbind_completes_cleanup_before_rebind() {
        let network = Network::builder().build();
        let driver = Arc::new(BlockingCloseDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern.clone()).await;
        let unbind = tokio::spawn({
            async move {
                handle.unbind().await;
            }
            .in_current_span()
        });

        driver.wait_close_started().await;
        unbind.abort();
        let aborted = unbind.await.expect_err("unbind task should be aborted");
        assert!(aborted.is_cancelled());

        driver.release_close();

        let mut rebound = tokio::time::timeout(
            Duration::from_secs(1),
            network.bind_with(driver.clone(), pattern),
        )
        .await
        .expect("canceled unbind cleanup should not strand the bind key");

        assert!(
            driver.complete_count() > 0,
            "canceled unbind cleanup should complete the pending close"
        );

        rebound.unbind().await;
    }

    #[tokio::test]
    async fn release_exact_entry_does_not_remove_replaced_entry() {
        let network = Network::builder().build();
        let driver = Arc::new(TestNullDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut first = network.bind_with(driver.clone(), pattern.clone()).await;
        let stale_entry = first.entry.clone();
        let key = first.key.clone();
        first.unbind().await;

        let mut replacement = network.bind_with(driver.clone(), pattern.clone()).await;
        network.release_exact_entry(key, stale_entry).await;

        assert!(
            network.get_interfaces_with(&driver, &pattern).is_some(),
            "stale exact-entry release must not remove replacement entry"
        );

        replacement.unbind().await;
    }

    #[tokio::test]
    async fn bind_handle_unbind_is_refcounted_and_idempotent() {
        let network = Network::builder().build();
        let driver = Arc::new(TestNullDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut first = network.bind_with(driver.clone(), pattern.clone()).await;
        let mut second = network.bind_with(driver.clone(), pattern.clone()).await;

        first.unbind().await;
        assert!(
            network.get_interfaces_with(&driver, &pattern).is_some(),
            "first unbind should only decrement the shared bind refcount"
        );

        first.unbind().await;
        assert!(
            network.get_interfaces_with(&driver, &pattern).is_some(),
            "repeating unbind on the same handle must not release again"
        );

        second.unbind().await;
        assert!(
            network.get_interfaces_with(&driver, &pattern).is_none(),
            "last handle should remove the registry entry"
        );
    }

    #[tokio::test]
    async fn dropped_bind_handle_releases_binding_in_background() {
        let network = Network::builder().build();
        let driver = Arc::new(TestNullDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        {
            let _handle = network.bind_with(driver.clone(), pattern.clone()).await;
            assert!(network.get_interfaces_with(&driver, &pattern).is_some());
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while network.get_interfaces_with(&driver, &pattern).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the last handle should schedule an unbind task");
    }

    #[tokio::test]
    async fn interface_auth_client_checks_sni_registry_and_bind_patterns() {
        let network = Network::builder().build();
        let quic = network.quic();
        let server_authority = make_local_authority("alpha");
        let client_authority = make_remote_authority("client");

        let auth = InterfaceAuthClient {
            bind_uri: "iface://v4.eth0:443".parse().expect("valid bind uri"),
            sni_registry: quic.sni_registry.clone(),
        };

        let empty_bind = quic
            .clone()
            .bind_server(
                make_identity("alpha"),
                make_server_config(),
                Arc::new(Vec::new()),
            )
            .await
            .expect("bind should succeed");
        assert_eq!(
            auth.verify_client_name(&server_authority, None),
            ClientNameVerifyResult::Accept
        );
        assert_eq!(
            auth.verify_client_authority(&server_authority, &client_authority),
            ClientAuthorityVerifyResult::Accept
        );

        drop(empty_bind);
        assert!(matches!(
            auth.verify_client_name(&server_authority, None),
            ClientNameVerifyResult::SilentRefuse(reason)
                if reason == "no server registered for SNI"
        ));

        let patterns = Arc::new(vec![
            BindPattern::from_str("iface://v4.lo:443").expect("valid pattern"),
        ]);
        let _scoped_bind = quic
            .clone()
            .bind_server(make_identity("alpha"), make_server_config(), patterns)
            .await
            .expect("bind should succeed");

        assert!(matches!(
            auth.verify_client_name(&server_authority, None),
            ClientNameVerifyResult::SilentRefuse(reason) if reason == "bind pattern mismatch"
        ));

        let matching_auth = InterfaceAuthClient {
            bind_uri: "iface://v4.lo:443".parse().expect("valid bind uri"),
            sni_registry: quic.sni_registry.clone(),
        };
        assert_eq!(
            matching_auth.verify_client_name(&server_authority, None),
            ClientNameVerifyResult::Accept
        );
    }

    #[tokio::test]
    async fn network_device_addr_helpers_reject_non_matching_inputs() {
        let network = Network::builder().build();
        assert!(
            network
                .resolve_device_addr("__missing__", Family::V4)
                .is_none()
        );

        let inet_uri: BindUri = "inet://127.0.0.1:443".parse().expect("valid bind uri");
        assert!(!network.bound_addr_is_on_default_route(
            &inet_uri,
            SocketAddr::from(([127, 0, 0, 1], 443)),
        ));

        let iface_uri: BindUri = "iface://v4.__missing__:443"
            .parse()
            .expect("valid bind uri");
        assert!(
            !network
                .bound_addr_is_on_default_route(&iface_uri, SocketAddr::from(([0, 0, 0, 0], 443)),)
        );
        assert!(!network.bound_addr_is_on_default_route(
            &iface_uri,
            "[::1]:443".parse().expect("valid socket addr"),
        ));
    }

    #[tokio::test]
    async fn quic_bind_driver_initializes_stun_component_branches() {
        let manager = Arc::new(InterfaceManager::new());
        let network = Network::build_with_quic_driver(Devices::global(), |network| {
            QuicBindDriver::builder()
                .network(network)
                .iface_manager(manager)
                .io_factory(Arc::new(NullIoFactory))
                .stun_server(Arc::from("default.stun.example:3478"))
                .build()
        });
        let quic = network.quic();

        let disabled: BindUri = "iface://v4.lo:0/?stun=false"
            .parse()
            .expect("valid bind uri");
        let _disabled_iface = BindDriver::bind(quic.as_ref(), &network, disabled).await;

        let explicit: BindUri = "iface://v4.lo:1/?stun_server=explicit.stun.example:3478"
            .parse()
            .expect("valid bind uri");
        let _explicit_iface = BindDriver::bind(quic.as_ref(), &network, explicit).await;
    }

    #[tokio::test]
    async fn reconcile_event_rebinds_matching_changed_interface_bindings() {
        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern).await;
        assert!(driver.bind_count() > 0, "initial bind should create iface");

        network.reconcile_event(&changed_event("lo")).await;

        assert!(
            driver.rebind_count() > 0,
            "matching changed event should rebind existing lo iface"
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn reconcile_event_skips_unrelated_changed_interface_bindings() {
        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern).await;
        assert!(driver.bind_count() > 0, "initial bind should create iface");

        network
            .reconcile_event(&changed_event("__unrelated__"))
            .await;

        assert_eq!(
            driver.rebind_count(),
            0,
            "unrelated changed event must not rebind lo iface"
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn reconcile_event_skips_inet_bindings() {
        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern).await;
        assert_eq!(
            driver.bind_count(),
            1,
            "initial inet bind should create one iface"
        );

        network.reconcile_event(&changed_event("lo")).await;

        assert_eq!(
            driver.rebind_count(),
            0,
            "interface changed event must not rebind inet iface"
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn reconcile_event_added_binds_missing_matching_membership_without_rebind() {
        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern.clone()).await;
        let initial_binds = driver.bind_count();
        assert!(initial_binds > 0, "initial bind should create iface");

        clear_bound_for_test(&network, &driver, &pattern).await;

        network.reconcile_event(&added_event("lo")).await;

        assert!(
            driver.bind_count() > initial_binds,
            "matching added event should create missing bound membership"
        );
        assert_eq!(
            driver.rebind_count(),
            0,
            "added event must not rebind existing bindings"
        );
        assert!(
            network
                .get_interfaces_with(&driver, &pattern)
                .is_some_and(|interfaces| !interfaces.is_empty()),
            "added reconcile should repopulate registry membership"
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn reconcile_event_removed_removes_matching_membership_without_rebind() {
        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern.clone()).await;
        assert!(
            network
                .get_interfaces_with(&driver, &pattern)
                .is_some_and(|interfaces| !interfaces.is_empty()),
            "initial bind should create membership"
        );

        network.reconcile_event(&removed_event("lo")).await;

        assert!(
            network
                .get_interfaces_with(&driver, &pattern)
                .is_some_and(|interfaces| interfaces.is_empty()),
            "removed event should remove stale bound iface for the removed device"
        );
        assert_eq!(
            driver.rebind_count(),
            0,
            "removed event must not rebind remaining bindings"
        );

        handle.unbind().await;
    }

    #[tokio::test]
    async fn removed_device_then_release_closes_each_binding_once() {
        let network = Network::builder().build();
        let driver = Arc::new(CloseCountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern.clone()).await;
        let initial = network
            .get_interfaces_with(&driver, &pattern)
            .expect("registered pattern")
            .len();
        assert!(initial > 0, "test expects loopback bindings");

        network.reconcile_event(&removed_event("lo")).await;
        assert_eq!(
            driver.close_count(),
            initial,
            "removed event should close drained loopback bindings"
        );

        handle.unbind().await;
        assert_eq!(
            driver.close_count(),
            initial,
            "final release must not double-close already drained bindings"
        );
    }

    #[tokio::test]
    async fn quic_bind_driver_rebinds_existing_interface_io() {
        use std::{
            net::SocketAddr,
            sync::atomic::{AtomicUsize, Ordering},
            task::Poll,
        };

        use bytes::BytesMut;
        use dquic::qbase::net::route::Route;

        #[derive(Debug)]
        struct RebindingIoFactory {
            bind_count: AtomicUsize,
        }

        #[derive(Debug)]
        struct RebindingIo {
            bind_uri: BindUri,
            addr: SocketAddr,
        }

        impl ProductIO for RebindingIoFactory {
            fn bind(&self, bind_uri: BindUri) -> Box<dyn crate::dquic::net::IO> {
                let port = 10_000 + self.bind_count.fetch_add(1, Ordering::SeqCst) as u16;
                Box::new(RebindingIo {
                    bind_uri,
                    addr: SocketAddr::from(([127, 0, 0, 1], port)),
                })
            }
        }

        impl crate::dquic::net::IO for RebindingIo {
            fn bind_uri(&self) -> BindUri {
                self.bind_uri.clone()
            }

            fn bound_addr(&self) -> io::Result<SocketAddr> {
                Ok(self.addr)
            }

            fn max_segment_size(&self) -> io::Result<usize> {
                Ok(1200)
            }

            fn max_segments(&self) -> io::Result<usize> {
                Ok(1)
            }

            fn poll_send(
                &self,
                _cx: &mut Context,
                _pkts: &[io::IoSlice],
                _route: Route,
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(0))
            }

            fn poll_recv(
                &self,
                _cx: &mut Context,
                _pkts: &mut [BytesMut],
                _route: &mut [Route],
            ) -> Poll<io::Result<usize>> {
                Poll::Pending
            }

            fn poll_close(&mut self, _cx: &mut Context) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        let factory = Arc::new(RebindingIoFactory {
            bind_count: AtomicUsize::new(0),
        });
        let manager = Arc::new(InterfaceManager::new());
        let network = Network::build_with_quic_driver(Devices::global(), |network| {
            QuicBindDriver::builder()
                .network(network)
                .iface_manager(manager)
                .io_factory(factory.clone())
                .build()
        });
        let uri: BindUri = "inet://127.0.0.1:0".parse().expect("valid bind uri");

        let quic = network.quic();
        let iface = BindDriver::bind(quic.as_ref(), &network, uri).await;
        let before = iface.borrow().bound_addr().expect("initial bound addr");

        quic.rebind(&network, &iface).await;

        let after = iface.borrow().bound_addr().expect("rebound addr");
        assert_ne!(before, after, "quic bind driver must replace stale IO");
        assert_eq!(factory.bind_count.load(Ordering::SeqCst), 2);
    }
}
