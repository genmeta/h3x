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
    collections::{HashMap, hash_map},
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
    task::{Context, Poll},
};

use dashmap::DashMap;
use dhttp_identity::name::Name;
use futures::{FutureExt, future::BoxFuture};
use snafu::Snafu;
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
    tls::{AuthClient, ClientAgentVerifyResult, ClientNameVerifyResult, LocalAgent, RemoteAgent},
};
// Internal implementation types — not part of curated domain modules
use crate::dquic::{
    qbase::packet::Packet,
    qconnection::builder::ConnectionFoundation,
    qinterface::component::{
        location::LocationsComponent,
        route::{QuicRouterComponent, Way},
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
    pub fn locations(&self) -> Arc<Locations> {
        self.locations.clone()
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

        let slot = self.compatible_server_slot(&server_config)?;

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
        registry
            .iter()
            .filter(|(key, _)| key.driver == quic_driver)
            .map(|(_, entry)| entry)
            .flat_map(|entry| {
                let bound = entry.bound.lock().expect("bound mutex poisoned");
                bound
                    .values()
                    .map(|(uri, iface)| map(uri, iface))
                    .collect::<Vec<_>>()
            })
            .collect()
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
                let bound = entry.bound.lock().expect("bound mutex poisoned");
                bound.get(&key).map(|(_uri, iface)| iface.clone())
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
                .bound
                .lock()
                .expect("bound mutex poisoned")
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
    bind_registry: Mutex<HashMap<BindRegistryKey, BindsEntry>>,
    _reconcile: OnceLock<AbortOnDropHandle<()>>,
}

struct BindsEntry {
    refcount: usize,
    driver: Arc<dyn BindDriver>,
    /// Live bindings keyed by [`BindUri::identity_key`]. Holds strong
    /// [`BindInterface`] references so that the interfaces (and their
    /// installed components) stay alive. The inner lock is separate from
    /// the outer `bind_registry` mutex so the reconcile task can perform
    /// async bind/unbind without holding the registry lock.
    bound: Mutex<BoundInterfaces>,
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
        #[builder(default = Devices::global())] devices: &'static Devices,
    ) -> Arc<Self> {
        Self::build_with_quic_driver(devices, |network| {
            QuicBindDriver::builder()
                .network(network.clone())
                .maybe_stun_server(stun_server)
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

        // Collect URIs that need binding while holding both locks, so the
        // refcount is incremented before we drop the locks and perform async
        // bind operations.
        let needs_bind: Vec<BindUri> = {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            let entry = registry.entry(key.clone()).or_insert_with(|| BindsEntry {
                refcount: 0,
                driver: driver_erased.clone(),
                bound: Mutex::new(HashMap::new()),
            });
            entry.refcount += 1;

            let bound = entry.bound.lock().expect("bound mutex poisoned");
            key.pattern
                .to_bind_uris(self.devices.interfaces().keys().map(String::as_str))
                .filter(|uri| !bound.contains_key(&uri.identity_key()))
                .collect()
        }; // locks dropped before await

        // Perform async binds without holding any locks
        let mut new_ifaces: Vec<(String, BindUri, BindInterface)> =
            Vec::with_capacity(needs_bind.len());
        for uri in &needs_bind {
            let iface = driver_erased.bind(self, uri.clone()).await;
            new_ifaces.push((uri.identity_key(), uri.clone(), iface));
        }

        // Re-acquire locks to store the new bindings
        if !new_ifaces.is_empty() {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            if let Some(entry) = registry.get_mut(&key) {
                let mut bound = entry.bound.lock().expect("bound mutex poisoned");
                for (key, uri, iface) in new_ifaces {
                    bound.insert(key, (uri, iface));
                }
            }
        }

        BindHandle {
            network: self.clone(),
            key,
            released: false,
        }
    }

    /// Release a previously registered [`BindPattern`] and its bound
    /// interfaces.
    async fn unbind(&self, key: &BindRegistryKey) {
        let bound = {
            let mut registry = self.bind_registry.lock().expect("bind_registry poisoned");
            if let hash_map::Entry::Occupied(mut entry) = registry.entry(key.clone()) {
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
                .bound
                .lock()
                .expect("bound mutex poisoned")
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
            tracing::debug!(?event, "network interface change, reconciling binds");
            network.reconcile_once().await;
        }
    }

    /// Extracted reconcile logic, run per interface change.
    async fn reconcile_once(&self) {
        let entries: Vec<(BindRegistryKey, BoundInterfaces, Arc<dyn BindDriver>)> = {
            let registry = self.bind_registry.lock().expect("bind_registry poisoned");
            registry
                .iter()
                .map(|(key, entry)| {
                    let bound = entry.bound.lock().expect("bound mutex poisoned");
                    (key.clone(), bound.clone(), entry.driver.clone())
                })
                .collect()
        };

        for (key, mut bound, driver) in entries {
            let desired_uris: Vec<BindUri> = key
                .pattern
                .to_bind_uris(self.devices.interfaces().keys().map(String::as_str))
                .collect();
            let desired_keys: std::collections::HashSet<String> =
                desired_uris.iter().map(BindUri::identity_key).collect();
            bound.retain(|bind_key, _| desired_keys.contains(bind_key));

            for (_, iface) in bound.values() {
                driver.rebind(self, iface).await;
            }

            for uri in desired_uris {
                let bind_key = uri.identity_key();
                if let std::collections::hash_map::Entry::Vacant(e) = bound.entry(bind_key) {
                    let iface = driver.bind(self, uri.clone()).await;
                    e.insert((uri.clone(), iface));
                }
            }

            if let Some(entry) = self
                .bind_registry
                .lock()
                .expect("bind_registry poisoned")
                .get(&key)
            {
                let mut target = entry.bound.lock().expect("bound mutex poisoned");
                // Retain only interfaces that still match current
                // devices, then merge reconcile's additions without
                // clobbering concurrent insertions from bind().
                target.retain(|k, _| desired_keys.contains(k));
                for (k, v) in bound {
                    target.entry(k).or_insert(v);
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
            Some(entry) if entry.bind.is_empty() => ClientNameVerifyResult::Accept,
            Some(entry) if entry.bind.iter().any(|p| p.matches(&self.bind_uri)) => {
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
            self.network.unbind(&self.key).await;
            self.released = true;
        }
    }
}

impl Drop for BindHandle {
    fn drop(&mut self) {
        if !self.released {
            let network = self.network.clone();
            let key = self.key.clone();
            // Inherent termination: the spawned task exits after the unbind
            // completes. If the runtime is shutting down, the unbind is
            // best-effort.
            tokio::spawn(
                async move {
                    network.unbind(&key).await;
                }
                .in_current_span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use dquic::prelude::{IO, handy::NoopTokenRegistry};
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
        use futures::{FutureExt, future::BoxFuture};

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
            fn bind<'a>(
                &'a self,
                _network: &'a Network,
                uri: BindUri,
            ) -> BoxFuture<'a, BindInterface> {
                async move { self.manager.bind(uri, Arc::new(NullIo::new)).await }.boxed()
            }
        }

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
    async fn reconcile_rebinds_existing_driver_bindings() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use futures::{FutureExt, future::BoxFuture};

        struct CountingDriver {
            manager: Arc<crate::dquic::net::InterfaceManager>,
            rebinds: AtomicUsize,
        }

        impl CountingDriver {
            fn new() -> Self {
                Self {
                    manager: Arc::new(crate::dquic::net::InterfaceManager::new()),
                    rebinds: AtomicUsize::new(0),
                }
            }
        }

        impl BindDriver for CountingDriver {
            fn bind<'a>(
                &'a self,
                _network: &'a Network,
                uri: BindUri,
            ) -> BoxFuture<'a, BindInterface> {
                async move { self.manager.bind(uri, Arc::new(NullIoFactory)).await }.boxed()
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

        let network = Network::builder().build();
        let driver = Arc::new(CountingDriver::new());
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let mut handle = network.bind_with(driver.clone(), pattern).await;

        network.reconcile_once().await;

        assert!(driver.rebinds.load(Ordering::Relaxed) > 0);

        handle.unbind().await;
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
