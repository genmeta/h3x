//! Process-shared QUIC network infrastructure.
//!
//! [`Network`] owns the long-lived components needed to send and receive QUIC
//! packets on a set of network interfaces.
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
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use bon::Builder;
use futures::Stream;
use tokio_util::task::AbortOnDropHandle;

use super::binds::{BindConflictError, Binds, watch_bind_interfaces};
use crate::dquic::{
    prelude::{
        Resolve,
        handy::{DEFAULT_IO_FACTORY, SystemResolver},
    },
    qinterface::{
        BindInterface, Interface,
        bind_uri::BindUri,
        component::{
            Components,
            alive::RebindOnNetworkChangedComponent,
            location::{Locations, LocationsComponent},
            route::{QuicRouter, QuicRouterComponent},
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

/// Shared QUIC network infrastructure.
#[derive(Clone, Builder)]
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
        let stun_server = if let Some(server) = bind_uri.stun_server() {
            Some(Arc::from(server))
        } else if let Some("false") = bind_uri.prop(BindUri::STUN_PROP).as_deref() {
            None
        } else {
            self.stun_server.clone()
        };
        // Defer STUN agent DNS resolution to `StunClientsComponent`'s
        // background task: it will call `resolver.lookup` (with its own
        // timeout) whenever the live agent count drops below `MIN_AGENTS`.
        // Resolving synchronously here has been observed to hang the entire
        // bind path when the resolver stalls, so the agent list is
        // intentionally left empty.
        let stun_agent = stun_server.map(|server| (server, Vec::<SocketAddr>::new()));

        let bind_iface = self
            .iface_manager
            .bind(bind_uri, self.io_factory.clone())
            .await;
        self.init_iface_components(&bind_iface, stun_agent);
        bind_iface
    }

    fn init_iface_components(
        &self,
        bind_iface: &BindInterface,
        stun_agent: Option<(Arc<str>, Vec<SocketAddr>)>,
    ) {
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
                Some((stun_server, stun_agents)) => {
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
                                stun_agents,
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
        &self,
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
    pub async fn add_binds(&self, binds: &Binds) -> Result<BindsGuard, Box<BindConflictError>> {
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

/// Placeholder handle for a per-SNI server binding.
#[non_exhaustive]
pub struct ServerBinding {}
