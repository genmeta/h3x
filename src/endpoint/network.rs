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
//! [`Network::add_binds`] expands a [`Binds`] pattern against the current
//! device set, binds each resulting URI through the shared
//! [`InterfaceManager`], and installs a background reconcile task that
//! re-evaluates the pattern on device changes. The call returns a
//! [`BindsGuard`] whose [`Drop`] impl cancels the reconcile task and unbinds
//! any URIs that were opened by the entry.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use bon::Builder;
use dashmap::DashMap;
use futures::Stream;
use rustls::{ServerConfig as RustlsServerConfig, sign::CertifiedKey};
use snafu::{ResultExt, Snafu};
use tokio::{sync::RwLock, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

pub use super::sni::ServerBinding;
use super::{
    binds::{BindConflictError, Binds, watch_bind_interfaces},
    config::ServerQuicConfig,
    identity::{NamedIdentity, ServerName},
    sni::{self, SniCertResolver, SniEntry, SniGuard},
};
use crate::dquic::{
    prelude::{
        Connection, Resolve,
        handy::{DEFAULT_IO_FACTORY, SystemResolver},
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

type BindRegistry = Arc<Mutex<HashMap<u64, BindsEntry>>>;
pub(crate) type SniRegistry = Arc<DashMap<ServerName, Weak<SniEntry>>>;

/// Error returned by [`Network::bind_server`].
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BindServerError {
    /// Another [`NamedIdentity`] is already registered for the same SNI.
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
    pub(crate) stun_resolver: Arc<dyn Resolve + Send + Sync>,
    pub(crate) stun_server: Option<Arc<str>>,
    #[builder(default = Devices::global())]
    pub(crate) devices: &'static Devices,
    #[builder(default = Arc::new(DEFAULT_IO_FACTORY))]
    pub(crate) io_factory: Arc<dyn ProductIO + 'static>,
    #[builder(default = InterfaceManager::global().clone())]
    pub(crate) iface_manager: Arc<InterfaceManager>,
    #[builder(default = QuicRouter::global().clone())]
    pub(crate) quic_router: Arc<QuicRouter>,
    #[builder(default = Arc::new(Locations::new()))]
    pub(crate) locations: Arc<Locations>,
    #[builder(skip = Arc::new(Mutex::new(HashMap::new())))]
    bind_registry: BindRegistry,
    #[builder(skip = Arc::new(AtomicU64::new(0)))]
    next_bind_id: Arc<AtomicU64>,
    #[builder(skip = Arc::new(DashMap::new()))]
    sni_registry: SniRegistry,
    #[builder(skip = RwLock::new(Weak::new()))]
    server_slot: RwLock<Weak<sni::ServerSlotInner>>,
    #[builder(skip = Mutex::new(JoinSet::new()))]
    dispatcher_tasks: Mutex<JoinSet<()>>,
    #[builder(skip)]
    dispatcher_installed: OnceLock<()>,
}

impl<S: network_builder::IsComplete> NetworkBuilder<S> {
    /// Finalize the builder, wrap in [`Arc`], and install the SNI dispatcher.
    pub fn build(self) -> Arc<Network> {
        let network = Arc::new(self.build_raw());
        network.install_dispatcher();
        network
    }
}

struct BindsEntry {
    _reconcile: AbortOnDropHandle<()>,
    bound_uris: Arc<Mutex<HashMap<String, BindUri>>>,
}

impl Network {
    /// Accessor for the interface manager.
    #[must_use]
    pub fn iface_manager(&self) -> &Arc<InterfaceManager> {
        &self.iface_manager
    }

    /// Accessor for the QUIC router.
    #[must_use]
    pub fn quic_router(&self) -> &Arc<QuicRouter> {
        &self.quic_router
    }

    /// Accessor for the shared [`Locations`] table.
    #[must_use]
    pub fn locations(&self) -> &Arc<Locations> {
        &self.locations
    }

    /// Accessor for the device tracker.
    #[must_use]
    pub fn devices(&self) -> &'static Devices {
        self.devices
    }

    /// Accessor for the I/O factory.
    #[must_use]
    pub fn io_factory(&self) -> &Arc<dyn ProductIO + 'static> {
        &self.io_factory
    }

    /// Accessor for the STUN server, if configured.
    #[must_use]
    pub fn stun_server(&self) -> Option<&Arc<str>> {
        self.stun_server.as_ref()
    }

    /// Accessor for the resolver used when looking up STUN server addresses.
    #[must_use]
    pub fn stun_resolver(&self) -> &Arc<dyn Resolve + Send + Sync> {
        &self.stun_resolver
    }

    /// Bind the given URI on this network.
    ///
    /// In addition to acquiring the underlying [`BindInterface`] from the
    /// [`InterfaceManager`], this also installs the QUIC packet routing,
    /// location tracking, STUN client and packet receive/deliver components
    /// on the interface so that QUIC packets actually flow.
    pub async fn bind(&self, bind_uri: BindUri) -> BindInterface {
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
                async move { network.bind(bind_uri.into()).await }
            })
            .collect::<FuturesUnordered<_>>()
    }

    /// Register a [`Binds`] pattern with this network.
    pub async fn add_binds(
        self: &Arc<Self>,
        binds: &Binds,
    ) -> Result<BindsGuard, Box<BindConflictError>> {
        let monitor = self.devices.monitor();
        let initial_uris = binds.to_bind_uris(monitor.interfaces().keys().map(String::as_str))?;

        let bound_uris = Arc::new(Mutex::new(
            initial_uris
                .iter()
                .map(|uri| (uri.identity_key(), uri.clone()))
                .collect::<HashMap<_, _>>(),
        ));

        for uri in &initial_uris {
            self.bind(uri.clone()).await;
        }

        let reconcile = {
            let network = self.clone();
            let bound_uris_bind = bound_uris.clone();
            let bind_fn = move |uri: BindUri| {
                let network = network.clone();
                let bound_uris_bind = bound_uris_bind.clone();
                Box::pin(async move {
                    network.bind(uri.clone()).await;
                    bound_uris_bind
                        .lock()
                        .unwrap()
                        .insert(uri.identity_key(), uri);
                })
                    as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            };

            let iface_manager_unbind = self.iface_manager.clone();
            let bound_uris_unbind = bound_uris.clone();
            let unbind_fn = move |uri: BindUri| {
                bound_uris_unbind
                    .lock()
                    .unwrap()
                    .remove(&uri.identity_key());
                let iface_manager_unbind = iface_manager_unbind.clone();
                tokio::spawn(async move {
                    iface_manager_unbind.unbind(uri).await;
                });
            };

            watch_bind_interfaces(binds, monitor, initial_uris, bind_fn, unbind_fn)
        };

        let id = self.next_bind_id.fetch_add(1, Ordering::Relaxed);
        self.bind_registry.lock().unwrap().insert(
            id,
            BindsEntry {
                _reconcile: reconcile,
                bound_uris: bound_uris.clone(),
            },
        );

        Ok(BindsGuard {
            id,
            registry: self.bind_registry.clone(),
            iface_manager: self.iface_manager.clone(),
            bound_uris,
        })
    }

    /// Snapshot of the URIs currently bound via [`Network::add_binds`].
    #[must_use]
    pub fn current_bind_uris(&self) -> Vec<BindUri> {
        let registry = self.bind_registry.lock().unwrap();
        registry
            .values()
            .flat_map(|entry| {
                entry
                    .bound_uris
                    .lock()
                    .unwrap()
                    .values()
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect()
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

        let network = self.clone();
        let sni_registry = self.sni_registry.clone();
        let task = async move {
            let cfg = &slot.config;
            let connection = Connection::new_server(cfg.own.token_provider.clone())
                .with_parameters(cfg.own.parameters.clone())
                .with_client_auther(Box::new(cfg.own.client_auther.clone()))
                .with_tls_config((*slot.rustls_config).clone())
                .with_streams_concurrency_strategy(cfg.common.stream_strategy_factory.as_ref())
                .with_zero_rtt(cfg.common.enable_0rtt)
                .with_iface_factory(network.io_factory.clone())
                .with_iface_manager(network.iface_manager.clone())
                .with_quic_router(network.quic_router.clone())
                .with_locations(network.locations.clone())
                .with_defer_idle_timeout(cfg.common.defer_idle_timeout)
                .with_cids(origin_dcid)
                .with_qlog(cfg.common.qlogger.clone())
                .run();
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
        self.dispatcher_tasks.lock().unwrap().spawn(task);
    }

    /// Register a server-side identity on this network.
    ///
    /// On success returns a [`ServerBinding`] whose [`ServerBinding::recv`]
    /// yields accepted connections whose ClientHello SNI matches
    /// `named.name`. Cloning the returned binding is cheap and clones share
    /// the inbound mpmc queue so concurrent receivers cooperate.
    pub async fn bind_server(
        self: &Arc<Self>,
        named: Arc<NamedIdentity>,
        server_config: ServerQuicConfig,
    ) -> Result<ServerBinding, BindServerError> {
        let name = named.name.clone();

        // Reuse path: existing SNI registration with the same identity.
        if let Some(weak) = self.sni_registry.get(&name).map(|kv| kv.value().clone())
            && let Some(entry) = weak.upgrade()
        {
            if !Arc::ptr_eq(&entry.named_identity, &named) {
                return Err(BindServerError::SniInUse { name });
            }
            return Ok(ServerBinding {
                name,
                _guard: entry.guard.clone(),
                entry,
            });
        }

        // Slot: reuse existing compatible slot, or initialise a new one.
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

        let certified_key = build_certified_key(&named)?;
        let backlog = server_config.own.backlog.max(1);
        let (tx, rx) = async_channel::bounded(backlog);

        let guard = Arc::new(SniGuard {
            name: name.clone(),
            registry: Arc::downgrade(&self.sni_registry),
        });
        let entry = Arc::new(SniEntry {
            named_identity: named,
            certified_key,
            incomings_tx: tx,
            incomings_rx: rx,
            _slot: slot,
            guard: guard.clone(),
        });
        self.sni_registry
            .insert(name.clone(), Arc::downgrade(&entry));

        Ok(ServerBinding {
            name,
            entry,
            _guard: guard,
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

fn build_certified_key(named: &NamedIdentity) -> Result<Arc<CertifiedKey>, BindServerError> {
    use bind_server_error::LoadKeySnafu;

    let provider = RustlsServerConfig::builder().crypto_provider().clone();
    let key = provider
        .key_provider
        .load_private_key(named.key.clone_key())
        .context(LoadKeySnafu)?;
    Ok(Arc::new(CertifiedKey {
        cert: named.certs.clone(),
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

// ---------------------------------------------------------------------------
// BindsGuard
// ---------------------------------------------------------------------------

/// RAII guard returned by [`Network::add_binds`].
pub struct BindsGuard {
    id: u64,
    registry: BindRegistry,
    iface_manager: Arc<InterfaceManager>,
    bound_uris: Arc<Mutex<HashMap<String, BindUri>>>,
}

impl Drop for BindsGuard {
    fn drop(&mut self) {
        self.registry.lock().unwrap().remove(&self.id);
        let uris: Vec<BindUri> = self
            .bound_uris
            .lock()
            .unwrap()
            .drain()
            .map(|(_, uri)| uri)
            .collect();
        for uri in uris {
            let iface_manager = self.iface_manager.clone();
            tokio::spawn(async move {
                iface_manager.unbind(uri).await;
            });
        }
    }
}
