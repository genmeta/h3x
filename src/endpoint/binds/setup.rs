//! Shared bind setup logic for QUIC interface binding.
//!
//! Consolidates the duplicated bind-interfaces initialization flow.

use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{BindConflictError, Binds};
use crate::dquic::{
    prelude::handy::DEFAULT_IO_FACTORY,
    qinterface::{
        BindInterface,
        bind_uri::BindUri,
        device::{Devices, InterfacesMonitor},
        manager::InterfaceManager,
    },
};

/// Result of [`setup_bind_interfaces`], carrying all state needed by downstream
/// code (DNS resolver construction, H3Client building, etc.).
pub struct BindSetup {
    /// Concrete bind URIs expanded from the user-supplied [`Binds`] patterns.
    pub bind_uris: Vec<BindUri>,
    /// Interface manager that owns the bindings.
    pub iface_manager: Arc<InterfaceManager>,
    /// Bound interfaces — one per bind URI.
    pub bind_interfaces: Vec<BindInterface>,
    /// Interfaces monitor for detecting runtime changes to network interfaces.
    pub monitor: InterfacesMonitor,
}

/// Like [`setup_bind_interfaces`], but calls `f` on the expanded bind URIs
/// before binding, allowing callers to mutate them (e.g. inject properties).
pub async fn setup_bind_interfaces_with(
    binds: &Binds,
    f: impl FnOnce(&mut Vec<BindUri>),
) -> Result<BindSetup, Box<BindConflictError>> {
    let monitor = Devices::global().monitor();

    let mut bind_uris = binds.to_bind_uris(monitor.interfaces().keys().map(String::as_str))?;
    f(&mut bind_uris);

    let iface_manager = Arc::new(InterfaceManager::new());
    let io_factory = Arc::new(DEFAULT_IO_FACTORY);

    let bind_interfaces = bind_uris
        .iter()
        .map(|bind_uri| iface_manager.bind(bind_uri.clone(), io_factory.clone()))
        .collect::<FuturesUnordered<_>>()
        .collect::<Vec<_>>()
        .await;

    Ok(BindSetup {
        bind_uris,
        iface_manager,
        bind_interfaces,
        monitor,
    })
}

/// Expand [`Binds`] patterns into concrete network bindings.
pub async fn setup_bind_interfaces(binds: &Binds) -> Result<BindSetup, Box<BindConflictError>> {
    setup_bind_interfaces_with(binds, |_| {}).await
}

/// Watch for network interface changes and dynamically bind/unbind URIs.
pub fn watch_bind_interfaces<B, U>(
    binds: &Binds,
    mut monitor: InterfacesMonitor,
    initial_bind_uris: Vec<BindUri>,
    bind_fn: B,
    unbind_fn: U,
) -> AbortOnDropHandle<()>
where
    B: Fn(BindUri) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    U: Fn(BindUri) + Send + 'static,
{
    let binds = binds.clone();
    let span = tracing::Span::current();

    AbortOnDropHandle::new(tokio::spawn(
        async move {
            fn to_keyed_map(uris: Vec<BindUri>) -> HashMap<String, BindUri> {
                uris.into_iter()
                    .map(|uri| (uri.identity_key(), uri))
                    .collect()
            }

            // Initial reconcile
            let mut current_map: HashMap<String, BindUri> =
                match binds.to_bind_uris(monitor.interfaces().keys().map(String::as_str)) {
                    Ok(new_uris) => {
                        let new_map = to_keyed_map(new_uris);
                        let initial_map = to_keyed_map(initial_bind_uris);

                        for (key, uri) in &new_map {
                            if !initial_map.contains_key(key) {
                                tracing::debug!("binding new URI `{uri}` during initial reconcile");
                                bind_fn(uri.clone()).await;
                            }
                        }
                        for (key, uri) in &initial_map {
                            if !new_map.contains_key(key) {
                                tracing::info!("unbinding URI `{uri}` during initial reconcile");
                                unbind_fn(uri.clone());
                            }
                        }

                        new_map
                    }
                    Err(err) => {
                        tracing::warn!(
                            "failed to compute bind URIs during initial reconcile: {}",
                            snafu::Report::from_error(&err)
                        );
                        to_keyed_map(initial_bind_uris)
                    }
                };

            while let Some((interfaces, _event)) = monitor.update().await {
                let new_uris = match binds.to_bind_uris(interfaces.keys().map(String::as_str)) {
                    Ok(uris) => uris,
                    Err(err) => {
                        tracing::warn!(
                            "failed to compute bind URIs after interface change: {}",
                            snafu::Report::from_error(&err)
                        );
                        continue;
                    }
                };

                let new_map = to_keyed_map(new_uris);

                for (key, uri) in &current_map {
                    if !new_map.contains_key(key) {
                        tracing::info!("unbinding URI `{uri}`");
                        unbind_fn(uri.clone());
                    }
                }
                for (key, uri) in &new_map {
                    if !current_map.contains_key(key) {
                        tracing::debug!("binding new URI `{uri}`");
                        bind_fn(uri.clone()).await;
                    }
                }

                current_map = new_map;
            }
        }
        .instrument(span),
    ))
}
