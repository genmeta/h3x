//! Process-shared QUIC network infrastructure.
//!
//! [`Network`] owns the long-lived components needed to send and receive QUIC
//! packets on a set of network interfaces, **and** the SNI fan-out registry
//! used to route newly-accepted connections to per-identity
//! [`QuicEndpoint`](super::QuicEndpoint) listeners.
//!
//! A [`Network`] is always used via [`Arc<Network>`]: clone the [`Arc`] to
//! share the infrastructure between many endpoints. The builder returns an
//! [`Arc`] directly via [`NetworkBuilder::build`].
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
//! Repeated calls with the same pattern increment the count; [`Network::unbind`]
//! decrements it and tears down the bound interfaces only when the count
//! reaches zero. A single background reconcile task (started at build time)
//! watches for device changes and keeps every pattern's bound interfaces in
//! sync.

use std::{
    collections::{HashMap, hash_map},
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, Weak},
};

use bon::Builder;
use dashmap::DashMap;
use futures::Stream;
use rustls::{ServerConfig as RustlsServerConfig, sign::CertifiedKey};
use snafu::{ResultExt, Snafu};
use tokio::sync::RwLock;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

pub use super::sni::ServerBinding;
use super::{
    binds::{BindHost, BindPattern},
    identity::{Identity, ServerName},
    server::ServerQuicConfig,
    sni::{self, SniCertResolver, SniEntry, SniGuard},
};
use crate::dquic::{
    prelude::{
        Connection, Resolve,
        handy::{DEFAULT_IO_FACTORY, SystemResolver},
        qconnection::builder::ConnectionFoundation,
    },
    qbase::packet::{DataHeader, GetDcid, Packet, long::DataHeader as LongHeader},
    qinterface::{
        BindInterface, Interface,
        bind_uri::BindUri,
        component::{
            Components,
            alive::RebindOnNetworkChangedComponent,
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

pub(crate) type SniRegistry = Arc<DashMap<ServerName, Weak<SniEntry>>>;

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
/// Used exclusively via [`Arc<Network>`]. [`NetworkBuilder::build`] returns
/// an [`Arc`] directly after installing the SNI dispatcher on the router.
#[derive(Builder)]
#[builder(finish_fn = build_raw)]
pub struct Network {
    #[builder(default = Arc::new(SystemResolver))]
    stun_resolver: Arc<dyn Resolve + Send + Sync>,
    stun_server: Option<Arc<str>>,
    #[builder(default = Devices::global())]
    devices: &'static Devices,
    #[builder(default = Arc::new(DEFAULT_IO_FACTORY))]
    io_factory: Arc<dyn ProductIO + 'static>,
    #[builder(default = InterfaceManager::global().clone())]
    iface_manager: Arc<InterfaceManager>,
    #[builder(default = QuicRouter::global().clone())]
    quic_router: Arc<QuicRouter>,
    #[builder(default = Arc::new(Locations::new()))]
    locations: Arc<Locations>,
    #[builder(skip = Mutex::new(HashMap::new()))]
    bind_registry: Mutex<HashMap<BindPattern, BindsEntry>>,
    #[builder(skip = Arc::new(DashMap::new()))]
    sni_registry: SniRegistry,
    #[builder(skip = RwLock::new(Weak::new()))]
    server_slot: RwLock<Weak<sni::ServerSlotInner>>,
    #[builder(skip)]
    dispatcher_installed: OnceLock<()>,
    #[builder(skip)]
    _reconcile: OnceLock<AbortOnDropHandle<()>>,
}

impl<S: network_builder::IsComplete> NetworkBuilder<S> {
    /// Finalize the builder, wrap in [`Arc`], and install the SNI dispatcher.
    pub fn build(self) -> Arc<Network> {
        let network = Arc::new(self.build_raw());
        network.install_dispatcher();
        network.start_reconcile();
        network
    }
}

type BoundMap = Arc<Mutex<HashMap<String, (BindUri, BindInterface)>>>;

struct BindsEntry {
    refcount: usize,
    /// Live bindings keyed by [`BindUri::identity_key`]. Holds strong
    /// [`BindInterface`] references so that the interfaces (and their
    /// installed components) stay alive. The inner lock is separate from
    /// the outer `bind_registry` mutex so the reconcile task can perform
    /// async bind/unbind without holding the registry lock.
    bound: BoundMap,
}

/// Expand a single [`BindPattern`] into concrete [`BindUri`]s given the
/// current set of interface names.
fn expand_pattern<'a>(
    pattern: &BindPattern,
    interfaces: impl IntoIterator<Item = &'a str>,
) -> Vec<BindUri> {
    let template = pattern.bind_uri_template();

    // IP hosts produce a fixed URI independent of interface names.
    if let BindHost::Ip { addr, .. } = &pattern.host {
        let port = pattern.effective_port();
        if let Ok(authority) = format!("{addr}:{port}").parse()
            && let Some(uri) = template(authority)
        {
            return vec![uri];
        }
        return Vec::new();
    }

    // Glob / exact hosts are expanded per interface.
    interfaces
        .into_iter()
        .flat_map(|iface_name| {
            pattern
                .bind_hosts_for_interface(iface_name)
                .filter_map(&template)
        })
        .collect()
}

impl Network {
    /// Apply this network's infrastructure (IO factory, interface manager,
    /// router and locations) to a connection builder.
    pub(crate) fn configure_connection<F, T>(
        &self,
        builder: ConnectionFoundation<F, T>,
    ) -> ConnectionFoundation<F, T> {
        builder
            .with_iface_factory(self.io_factory.clone())
            .with_iface_manager(self.iface_manager.clone())
            .with_quic_router(self.quic_router.clone())
            .with_locations(self.locations.clone())
    }

    /// Bind the given URI on this network.
    ///
    /// In addition to acquiring the underlying [`BindInterface`] from the
    /// [`InterfaceManager`], this also installs the QUIC packet routing,
    /// location tracking, STUN client and packet receive/deliver components
    /// on the interface so that QUIC packets actually flow.
    pub async fn bind_iface(&self, bind_uri: BindUri) -> BindInterface {
        let bind_iface = self
            .iface_manager
            .bind(bind_uri, self.io_factory.clone())
            .await;
        self.init_iface_components(&bind_iface);
        bind_iface
    }

    fn init_iface_components(&self, bind_iface: &BindInterface) {
        let stun_agent = if let Some(server) = bind_iface.bind_uri().stun_server() {
            Some(Arc::from(server))
        } else if let Some("false") = bind_iface.bind_uri().prop(BindUri::STUN_PROP).as_deref() {
            None
        } else {
            self.stun_server.clone()
        };
        let resolver = self.stun_resolver.clone();
        let devices = self.devices;
        let quic_router = self.quic_router.clone();
        let locations = self.locations.clone();
        bind_iface.with_components_mut(move |components: &mut Components, iface: &Interface| {
            components.init_with(|| RebindOnNetworkChangedComponent::new(iface, devices));
            let quic_router = components
                .init_with(|| QuicRouterComponent::new(quic_router))
                .router();
            let locations = components
                .init_with(|| LocationsComponent::new(iface.downgrade(), locations))
                .clone();

            match stun_agent {
                Some(stun_server) => {
                    let stun_router = components
                        .init_with(|| StunRouterComponent::new(iface.downgrade()))
                        .router();
                    let clients = components
                        .init_with(|| {
                            StunClientsComponent::new(
                                iface.downgrade(),
                                stun_router.clone(),
                                resolver,
                                stun_server,
                                [],
                                Some(locations.clone()),
                            )
                        })
                        .clone();
                    let relay = bind_iface
                        .bind_uri()
                        .relay()
                        .and_then(|r| r.parse::<SocketAddr>().ok());
                    let forwarder = if let Some(relay) = relay {
                        components
                            .init_with(|| ForwardersComponent::new_server(relay))
                            .forwarder()
                    } else {
                        components
                            .init_with(|| ForwardersComponent::new_client(clients))
                            .forwarder()
                    };
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .stun_router(stun_router)
                            .forwarder(forwarder)
                            .init()
                    });
                }
                None => {
                    components.init_with(|| {
                        ReceiveAndDeliverPacketComponent::builder(iface.downgrade())
                            .quic_router(quic_router)
                            .init()
                    });
                }
            };
        });
    }

    /// Bind many URIs in parallel.
    pub async fn bind_many(
        self: &Arc<Self>,
        bind_uris: impl IntoIterator<Item = impl Into<BindUri>>,
    ) -> impl Stream<Item = BindInterface> {
        use futures::stream::FuturesUnordered;

        bind_uris
            .into_iter()
            .map(|bind_uri| {
                let network = self.clone();
                async move { network.bind_iface(bind_uri.into()).await }
            })
            .collect::<FuturesUnordered<_>>()
    }

    /// Register a [`BindPattern`] with this network (refcounted).
    ///
    /// If the same pattern is already registered, its reference count is
    /// incremented and no new interfaces are bound. Otherwise the pattern
    /// is expanded against the current device set and each resulting
    /// [`BindUri`] is bound via [`bind_iface`](Self::bind_iface).
    ///
    /// A background reconcile task (started at build time) watches for
    /// device changes and keeps the bound interfaces in sync.
    pub async fn bind(self: &Arc<Self>, pattern: BindPattern) {
        // Fast path: bump refcount if already registered.
        {
            let mut registry = self.bind_registry.lock().unwrap();
            if let Some(entry) = registry.get_mut(&pattern) {
                entry.refcount += 1;
                return;
            }
        }

        // Expand pattern and bind interfaces (without holding the lock).
        let monitor = self.devices.monitor();
        let uris = expand_pattern(&pattern, monitor.interfaces().keys().map(String::as_str));
        let mut initial_bound = HashMap::with_capacity(uris.len());
        for uri in uris {
            let iface = self.bind_iface(uri.clone()).await;
            initial_bound.insert(uri.identity_key(), (uri, iface));
        }
        let bound = Arc::new(Mutex::new(initial_bound));

        // Re-lock and insert (double-check for concurrent bind of the
        // same pattern).
        let mut registry = self.bind_registry.lock().unwrap();
        match registry.entry(pattern) {
            hash_map::Entry::Occupied(mut e) => {
                e.get_mut().refcount += 1;
                // Another caller bound the same pattern concurrently.
                // InterfaceManager deduplicates, so our BindInterfaces
                // are safe to drop.
            }
            hash_map::Entry::Vacant(e) => {
                e.insert(BindsEntry { refcount: 1, bound });
            }
        }
    }

    /// Decrement the reference count for a [`BindPattern`].
    ///
    /// When the last reference is removed, the pattern's bound interfaces
    /// are released asynchronously.
    pub async fn unbind(self: &Arc<Self>, pattern: &BindPattern) {
        let bound = {
            let mut registry = self.bind_registry.lock().unwrap();
            match registry.get_mut(pattern) {
                Some(entry) => {
                    entry.refcount -= 1;
                    if entry.refcount > 0 {
                        return;
                    }
                    registry.remove(pattern).unwrap().bound
                }
                None => return,
            }
        };

        // Release interfaces outside the lock.
        let uris: Vec<BindUri> = bound
            .lock()
            .unwrap()
            .drain()
            .map(|(_, (uri, _))| uri)
            .collect();
        for uri in uris {
            self.iface_manager.unbind(uri).await;
        }
    }

    /// Snapshot of all [`BindInterface`]s currently bound via
    /// [`bind`](Self::bind).
    #[must_use]
    pub fn interfaces(&self) -> Vec<BindInterface> {
        let registry = self.bind_registry.lock().unwrap();
        registry
            .values()
            .flat_map(|entry| {
                entry
                    .bound
                    .lock()
                    .unwrap()
                    .values()
                    .map(|(_, iface)| iface.clone())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Snapshot of SNI names currently registered on this network.
    ///
    /// A name appears in the result iff at least one [`ServerBinding`]
    /// (or a cache entry of a [`QuicEndpoint`](super::QuicEndpoint)) for
    /// that name is still live. Names whose `Weak<SniEntry>` cannot be
    /// upgraded — i.e. whose last binding was dropped but whose registry
    /// slot has not yet been cleared by
    /// [`SniGuard`](super::sni::SniGuard)'s `Drop` — are filtered out.
    #[must_use]
    pub fn registered_sni_names(&self) -> Vec<ServerName> {
        self.sni_registry
            .iter()
            .filter_map(|kv| kv.value().upgrade().map(|_| kv.key().clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Reconcile task
// ---------------------------------------------------------------------------

impl Network {
    /// Start the single background reconcile task that watches for device
    /// changes and keeps every registered [`BindPattern`]'s bound
    /// interfaces in sync. Idempotent — subsequent calls are no-ops.
    fn start_reconcile(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let devices = self.devices;
        let handle = AbortOnDropHandle::new(tokio::spawn(
            async move {
                Self::reconcile_loop(weak, devices).await;
            }
            .instrument(tracing::Span::current()),
        ));
        let _ = self._reconcile.set(handle);
    }

    async fn reconcile_loop(weak: Weak<Self>, devices: &'static Devices) {
        let mut monitor = devices.monitor();

        while let Some((interfaces, _event)) = monitor.update().await {
            let Some(network) = weak.upgrade() else {
                return;
            };

            // Snapshot the desired vs current state under the registry lock.
            let mut to_bind: Vec<(BindPattern, Vec<BindUri>)> = Vec::new();
            let mut to_unbind: Vec<(BoundMap, Vec<BindUri>)> = Vec::new();
            {
                let registry = network.bind_registry.lock().unwrap();
                for (pattern, entry) in registry.iter() {
                    let desired: HashMap<String, BindUri> =
                        expand_pattern(pattern, interfaces.keys().map(String::as_str))
                            .into_iter()
                            .map(|uri| (uri.identity_key(), uri))
                            .collect();

                    let bound = entry.bound.lock().unwrap();

                    let unbind_uris: Vec<BindUri> = bound
                        .iter()
                        .filter(|(key, _)| !desired.contains_key(*key))
                        .map(|(_, (uri, _))| uri.clone())
                        .collect();

                    let bind_uris: Vec<BindUri> = desired
                        .into_iter()
                        .filter(|(key, _)| !bound.contains_key(key))
                        .map(|(_, uri)| uri)
                        .collect();

                    if !unbind_uris.is_empty() {
                        to_unbind.push((entry.bound.clone(), unbind_uris));
                    }
                    if !bind_uris.is_empty() {
                        to_bind.push((pattern.clone(), bind_uris));
                    }
                }
            } // release registry lock

            // Unbind removed interfaces.
            for (bound, uris) in to_unbind {
                for uri in uris {
                    bound.lock().unwrap().remove(&uri.identity_key());
                    network.iface_manager.unbind(uri).await;
                }
            }

            // Bind new interfaces (double-check the pattern is still
            // registered before inserting).
            for (pattern, uris) in to_bind {
                for uri in uris {
                    let iface = network.bind_iface(uri.clone()).await;
                    let registry = network.bind_registry.lock().unwrap();
                    if let Some(entry) = registry.get(&pattern) {
                        entry
                            .bound
                            .lock()
                            .unwrap()
                            .insert(uri.identity_key(), (uri, iface));
                    }
                    // If the pattern was removed while we were binding,
                    // drop the interface silently.
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SNI dispatcher + bind_server
// ---------------------------------------------------------------------------

impl Network {
    /// Install the connectionless-packet dispatcher on the network's QUIC
    /// router. Idempotent — subsequent calls are no-ops.
    fn install_dispatcher(self: &Arc<Self>) {
        if self.dispatcher_installed.set(()).is_err() {
            return;
        }
        let weak = Arc::downgrade(self);
        let installed = self
            .quic_router
            .on_connectless_packets(move |packet: Packet, way: Way| {
                let Some(network) = weak.upgrade() else {
                    return;
                };
                network.dispatch_initial_packet(packet, way);
            });
        if !installed {
            tracing::warn!(
                target: "h3x::endpoint",
                "quic router already has a connectionless dispatcher installed; \
                 this Network's server endpoints will be unreachable"
            );
        }
    }

    /// Called from the router's connectionless-packet hook.
    fn dispatch_initial_packet(self: &Arc<Self>, packet: Packet, way: Way) {
        // Fast path: if no SNI is registered, drop before touching the slot.
        if self.sni_registry.is_empty() {
            return;
        }
        let origin_dcid = match &packet {
            Packet::Data(data_packet) => match &data_packet.header {
                DataHeader::Long(LongHeader::Initial(hdr)) => *hdr.dcid(),
                DataHeader::Long(LongHeader::ZeroRtt(hdr)) => *hdr.dcid(),
                _ => return,
            },
            _ => return,
        };
        if origin_dcid.is_empty() {
            return;
        }

        // Upgrade the slot synchronously. If the Weak is dead, no server is
        // registered right now — drop.
        let slot_opt = self.server_slot.try_read().ok().and_then(|g| g.upgrade());
        let Some(slot) = slot_opt else {
            return;
        };

        // IMPORTANT: construct the server `Connection` synchronously so that
        // the CID route on the shared `QuicRouter` is installed before this
        // function returns. Otherwise a second Initial packet with the same
        // ODCID arriving during the async gap would still be dispatched as
        // "connectionless", spawning another server `Connection` for the
        // same ODCID — both would attempt to respond with Handshake packets
        // derived from independent keying state, and the peer would decrypt
        // later packets with the wrong keys (observed as
        // "Invalid reserved bits" transport errors).
        //
        // Only the genuinely async work (packet delivery + waiting for the
        // ClientHello / SNI resolution) is spawned below.
        let cfg = &slot.config;
        let connection = Connection::new_server(cfg.own.token_provider.clone())
            .with_parameters(cfg.own.parameters.clone())
            .with_client_auther(Box::new(cfg.own.client_auther.clone()))
            .with_tls_config((*slot.rustls_config).clone())
            .with_streams_concurrency_strategy(cfg.common.stream_strategy_factory.as_ref())
            .with_zero_rtt(cfg.common.enable_0rtt)
            .with_iface_factory(self.io_factory.clone())
            .with_iface_manager(self.iface_manager.clone())
            .with_quic_router(self.quic_router.clone())
            .with_locations(self.locations.clone())
            .with_defer_idle_timeout(cfg.common.defer_idle_timeout)
            .with_cids(origin_dcid)
            .with_qlog(cfg.common.qlogger.clone())
            .run();

        let network = self.clone();
        let sni_registry = self.sni_registry.clone();
        let task = async move {
            network.quic_router.deliver(packet, way).await;
            match connection.server_name().await {
                Ok(name) => {
                    let _ = connection.subscribe_local_address();
                    let entry = sni_registry.iter().find_map(|kv| {
                        if kv.key().eq_ignore_ascii_case(&name) {
                            kv.value().upgrade()
                        } else {
                            None
                        }
                    });
                    match entry {
                        Some(entry) => {
                            if entry.incomings_tx.try_send(connection).is_err() {
                                tracing::debug!(
                                    target: "h3x::endpoint",
                                    name = %name,
                                    "accept backlog full or no receiver, dropping connection"
                                );
                            }
                        }
                        None => {
                            tracing::debug!(
                                target: "h3x::endpoint",
                                name = %name,
                                "no endpoint registered for SNI, dropping connection"
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        target: "h3x::endpoint",
                        "failed to obtain server name, dropping connection: {error}"
                    );
                }
            }
        };
        // Detached: the Network lives for the process lifetime and these
        // tasks are short-lived and self-contained. Previously these were
        // pushed into a `JoinSet` that nothing ever drained, which leaked
        // one task-output slot per incoming handshake.
        tokio::spawn(task);
    }

    /// Register a server-side identity on this network.
    ///
    /// On success returns a [`ServerBinding`] whose [`ServerBinding::recv`]
    /// yields accepted connections whose ClientHello SNI matches
    /// `named.name`. Cloning the returned binding is cheap and clones share
    /// the inbound mpmc queue so concurrent receivers cooperate.
    pub async fn bind_server(
        self: &Arc<Self>,
        identity: Arc<Identity>,
        server_config: ServerQuicConfig,
    ) -> Result<ServerBinding, BindServerError> {
        let name = identity.name.clone();

        if let Some(weak) = self.sni_registry.get(&name).map(|kv| kv.value().clone())
            && let Some(entry) = weak.upgrade()
        {
            if Arc::ptr_eq(&entry.identity, &identity) {
                return Ok(ServerBinding {
                    name,
                    _guard: entry.guard.clone(),
                    entry,
                });
            }
        }

        let slot = {
            let mut slot_guard = self.server_slot.write().await;
            match slot_guard.upgrade() {
                Some(existing) => {
                    if !server_config_compatible(&existing.config, &server_config) {
                        return Err(BindServerError::ServerConfigConflict);
                    }
                    existing
                }
                None => {
                    let rustls_config = build_rustls_server_config(
                        &server_config,
                        SniCertResolver {
                            registry: Arc::downgrade(&self.sni_registry),
                        },
                    )?;
                    let inner = Arc::new(sni::ServerSlotInner {
                        config: server_config.clone(),
                        rustls_config: Arc::new(rustls_config),
                    });
                    *slot_guard = Arc::downgrade(&inner);
                    inner
                }
            }
        };

        let certified_key = build_certified_key(&identity)?;
        let backlog = server_config.own.backlog.max(1);
        let (tx, rx) = async_channel::bounded(backlog);

        let entry = Arc::new_cyclic(|entry_weak| {
            let guard = Arc::new(SniGuard {
                name: name.clone(),
                registry: Arc::downgrade(&self.sni_registry),
                self_entry: entry_weak.clone(),
            });
            SniEntry {
                identity,
                certified_key,
                incomings_tx: tx,
                incomings_rx: rx,
                _slot: slot,
                guard,
            }
        });

        self.sni_registry
            .insert(name.clone(), Arc::downgrade(&entry));

        Ok(ServerBinding {
            name,
            _guard: entry.guard.clone(),
            entry,
        })
    }
}

/// Build the rustls server config shared across all SNIs registered on a
/// network. The resolver selects a [`CertifiedKey`] based on ClientHello SNI.
fn build_rustls_server_config(
    server_config: &ServerQuicConfig,
    resolver: SniCertResolver,
) -> Result<RustlsServerConfig, BindServerError> {
    use bind_server_error::VersionSnafu;

    const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    let provider = RustlsServerConfig::builder().crypto_provider().clone();
    let builder = RustlsServerConfig::builder_with_provider(provider)
        .with_protocol_versions(TLS13)
        .context(VersionSnafu)?;

    let mut tls = builder
        .with_client_cert_verifier(server_config.own.client_cert_verifier.clone())
        .with_cert_resolver(Arc::new(resolver));
    tls.alpn_protocols.clone_from(&server_config.own.alpns);
    if server_config.common.enable_0rtt {
        tls.max_early_data_size = 0xffff_ffff;
    }
    Ok(tls)
}

fn build_certified_key(named: &Identity) -> Result<Arc<CertifiedKey>, BindServerError> {
    use bind_server_error::LoadKeySnafu;

    let provider = RustlsServerConfig::builder().crypto_provider().clone();
    let key = provider
        .key_provider
        .load_private_key(named.key.clone_key())
        .context(LoadKeySnafu)?;
    Ok(Arc::new(CertifiedKey {
        cert: named.certs.iter().cloned().collect(),
        key,
        ocsp: None,
    }))
}

/// Returns `true` when `a` and `b` describe the same server configuration.
///
/// Fast path: whole-[`Arc`] pointer equality for `common` and `own`.
/// Slow path: field-by-field comparison, using [`PartialEq`] where available
/// and [`Arc::ptr_eq`] for the trait-object members.
fn server_config_compatible(a: &ServerQuicConfig, b: &ServerQuicConfig) -> bool {
    if Arc::ptr_eq(&a.common, &b.common) && Arc::ptr_eq(&a.own, &b.own) {
        return true;
    }
    let common_eq = a.common.defer_idle_timeout == b.common.defer_idle_timeout
        && a.common.enable_0rtt == b.common.enable_0rtt
        && a.common.enable_sslkeylog == b.common.enable_sslkeylog
        && Arc::ptr_eq(
            &a.common.stream_strategy_factory,
            &b.common.stream_strategy_factory,
        )
        && Arc::ptr_eq(&a.common.qlogger, &b.common.qlogger);
    let own_eq = a.own.alpns == b.own.alpns
        && a.own.backlog == b.own.backlog
        && a.own.anti_port_scan == b.own.anti_port_scan
        && a.own.parameters == b.own.parameters
        && Arc::ptr_eq(&a.own.token_provider, &b.own.token_provider)
        && Arc::ptr_eq(&a.own.client_auther, &b.own.client_auther)
        && Arc::ptr_eq(&a.own.client_cert_verifier, &b.own.client_cert_verifier);
    common_eq && own_eq
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::identity::Identity;

    fn make_identity(name: &str) -> Arc<Identity> {
        Arc::new(Identity {
            name: Arc::from(name),
            certs: Arc::new(vec![]),
            key: Arc::new(rustls::pki_types::PrivateKeyDer::Pkcs8(
                b"dummy".to_vec().into(),
            )),
            ocsp: Arc::new(None),
        })
    }

    fn make_server_config() -> ServerQuicConfig {
        use std::sync::Arc;

        use crate::endpoint::server::{CommonQuicConfig, ServerOnlyConfig};

        ServerQuicConfig {
            common: Arc::new(CommonQuicConfig {
                defer_idle_timeout: false,
                enable_0rtt: false,
                enable_sslkeylog: false,
                stream_strategy_factory: Arc::new(dquic::prelude::DefaultStreamStrategyFactory),
                qlogger: Arc::new(None),
            }),
            own: Arc::new(ServerOnlyConfig {
                alpns: vec![b"h3".to_vec()],
                backlog: 32,
                anti_port_scan: false,
                parameters: Default::default(),
                token_provider: Arc::new(dquic::prelude::DefaultTokenProvider),
                client_auther: Arc::new(None),
                client_cert_verifier: Arc::new(None),
            }),
        }
    }

    #[tokio::test]
    async fn test_bind_server_overwrite() {
        let network = Arc::new(Network::new());
        let identity_a = make_identity("test.example.com");
        let identity_b = make_identity("test.example.com");
        let config = make_server_config();

        let binding_a = network
            .bind_server(identity_a.clone(), config.clone())
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .bind_server(identity_b.clone(), config.clone())
            .await
            .expect("second bind with different identity should succeed (overwrite)");

        assert_eq!(binding_a.name, binding_b.name);
        assert_eq!(network.sni_registry.len(), 1);

        let entry = network
            .sni_registry
            .get(&binding_b.name)
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the new entry");
        assert!(Arc::ptr_eq(&entry.identity, &identity_b));
    }

    #[tokio::test]
    async fn test_bind_server_same_identity_reuse() {
        let network = Arc::new(Network::new());
        let identity = make_identity("test.example.com");
        let config = make_server_config();

        let binding_a = network
            .bind_server(identity.clone(), config.clone())
            .await
            .expect("first bind should succeed");

        let binding_b = network
            .bind_server(identity.clone(), config.clone())
            .await
            .expect("second bind with same identity should succeed (reuse)");

        assert_eq!(binding_a.name, binding_b.name);
        assert_eq!(network.sni_registry.len(), 1);

        let entry_a = network
            .sni_registry
            .get(&binding_a.name)
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the entry");
        let entry_b = network
            .sni_registry
            .get(&binding_b.name)
            .and_then(|kv| kv.value().upgrade())
            .expect("registry should have the entry");

        assert!(Arc::ptr_eq(&entry_a, &entry_b));
    }
}
