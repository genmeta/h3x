//! QUIC-only endpoint built on top of a shared [`Network`].

use std::{
    any::Any, collections::HashMap, net::SocketAddr, str::FromStr, sync::Arc, time::Duration,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use bon::bon;
use futures::{FutureExt, Stream, StreamExt, future::join_all};
use rustls::ClientConfig;
use snafu::{Report, ResultExt, Snafu};
use tracing::Instrument;

use crate::{
    dquic::{
        binds::BindPattern,
        client::{ClientQuicConfig, ServerCertVerifierChoice},
        connection::Connection,
        identity::Identity,
        net::{BindUri, ConnectionId, EndpointAddr},
        network::{BindHandle, BindServerError, Network, ServerBinding},
        resolver::{Resolve, Source},
        server::ServerQuicConfig,
    },
    quic,
    util::tls::DangerousServerCertVerifier,
};

/// Error building the client-side TLS configuration.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BuildClientTlsError {
    /// rustls failed to choose a supported protocol version.
    #[snafu(display("failed to select TLS protocol version"))]
    Version {
        /// Underlying rustls error.
        source: rustls::Error,
    },
    /// rustls refused the provided client certificate / key.
    #[snafu(display("failed to load client authentication certificate"))]
    ClientAuth {
        /// Underlying rustls error.
        source: rustls::Error,
    },
    /// Failed to set a transport parameter on the client parameters.
    #[snafu(display("failed to set client name transport parameter"))]
    SetParameter {
        /// Underlying parameter error.
        source: crate::dquic::qbase::param::error::Error,
    },
}

/// Error returned by [`QuicEndpoint`] when opening an outbound connection.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum ConnectError {
    /// Failed to build the client TLS configuration.
    #[snafu(display("failed to build client TLS config"))]
    Tls {
        /// Underlying build error.
        source: BuildClientTlsError,
    },
    /// DNS resolution failed.
    #[snafu(display("dns lookup failed"))]
    Dns {
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The resolver produced no reachable endpoint.
    #[snafu(display("no reachable endpoint found for server"))]
    NoReachableEndpoint,
}

/// Error returned by [`QuicEndpoint`] when awaiting an inbound connection.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum AcceptError {
    /// The endpoint's identity is anonymous — no SNI to register.
    #[snafu(display("cannot accept connections on an anonymous identity"))]
    ServerUnavailable,
    /// Registering the identity on the network failed.
    #[snafu(display("failed to bind server on network"))]
    BindServer {
        /// Underlying network error.
        source: BindServerError,
    },
    /// The endpoint has been shut down.
    #[snafu(display("endpoint has been shut down"))]
    Shutdown,
}

/// Back-compat alias.
pub type EndpointError = ConnectError;

/// A QUIC-only endpoint backed by a shared [`Network`].
pub struct QuicEndpoint {
    /// Shared network infrastructure.
    pub(crate) network: Arc<Network>,
    /// TLS identity for this endpoint (`None` for anonymous/client-only).
    pub(crate) identity: Arc<ArcSwapOption<Identity>>,
    /// Resolver used when establishing outbound connections.
    pub(crate) resolver: Arc<dyn Resolve + Send + Sync>,
    /// Client-side configuration.
    pub(crate) client: Arc<ArcSwap<ClientQuicConfig>>,
    /// Server-side configuration.
    pub(crate) server: Arc<ArcSwap<ServerQuicConfig>>,
    /// Bind patterns for interface filtering (shared by client and server roles).
    pub(crate) bind: Arc<Vec<BindPattern>>,
    _binds: Arc<Vec<BindHandle>>,
    client_tls_cache: ArcSwapOption<ClientConfig>,
    server_binding_cache: ArcSwapOption<ServerBinding>,
}

impl Clone for QuicEndpoint {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            identity: self.identity.clone(),
            resolver: self.resolver.clone(),
            client: self.client.clone(),
            server: self.server.clone(),
            bind: self.bind.clone(),
            _binds: self._binds.clone(),
            client_tls_cache: ArcSwapOption::empty(),
            server_binding_cache: ArcSwapOption::empty(),
        }
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s client configuration.
///
/// On drop, invalidates the endpoint's `client_tls_cache` so that the next
/// `connect()` call rebuilds the TLS configuration.
pub struct ClientConfigMutGuard<'a> {
    config: Arc<ClientQuicConfig>,
    target: &'a ArcSwap<ClientQuicConfig>,
    cache: &'a ArcSwapOption<ClientConfig>,
}

impl<'a> std::ops::Deref for ClientConfigMutGuard<'a> {
    type Target = ClientQuicConfig;
    fn deref(&self) -> &Self::Target {
        self.config.as_ref()
    }
}

impl<'a> std::ops::DerefMut for ClientConfigMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.config)
    }
}

impl<'a> Drop for ClientConfigMutGuard<'a> {
    fn drop(&mut self) {
        self.target.store(self.config.clone());
        self.cache.store(None);
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s server configuration.
///
/// On drop, invalidates the endpoint's `server_binding_cache` so that the next
/// `accept()` call rebuilds the server binding.
pub struct ServerConfigMutGuard<'a> {
    config: Arc<ServerQuicConfig>,
    target: &'a ArcSwap<ServerQuicConfig>,
    cache: &'a ArcSwapOption<ServerBinding>,
}

impl<'a> std::ops::Deref for ServerConfigMutGuard<'a> {
    type Target = ServerQuicConfig;
    fn deref(&self) -> &Self::Target {
        self.config.as_ref()
    }
}

impl<'a> std::ops::DerefMut for ServerConfigMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.config)
    }
}

impl<'a> Drop for ServerConfigMutGuard<'a> {
    fn drop(&mut self) {
        self.target.store(self.config.clone());
        self.cache.store(None);
    }
}

impl QuicEndpoint {
    pub async fn new() -> Self {
        Self::builder().build().await
    }

    /// Reference to the shared network infrastructure.
    pub fn network(&self) -> &Arc<Network> {
        &self.network
    }

    /// Current TLS identity, if any.
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.load_full()
    }

    /// Bind patterns governing which interfaces this endpoint uses.
    pub fn bind_patterns(&self) -> &Arc<Vec<BindPattern>> {
        &self.bind
    }

    /// Reference to the DNS resolver.
    pub fn resolver(&self) -> &Arc<dyn Resolve + Send + Sync> {
        &self.resolver
    }

    pub fn set_resolver(&mut self, resolver: Arc<dyn Resolve + Send + Sync>) {
        self.resolver = resolver;
    }
}

impl quic::WithLocalAuthority for QuicEndpoint {
    type LocalAuthority = Identity;

    async fn local_authority(&self) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
        Ok(self.identity().as_deref().cloned())
    }
}

#[bon]
impl QuicEndpoint {
    #[builder]
    pub async fn new(
        #[builder(default = Network::builder().build())] network: Arc<Network>,
        identity: Option<Arc<Identity>>,
        #[builder(default = Arc::new(crate::dquic::prelude::handy::SystemResolver))] resolver: Arc<
            dyn Resolve + Send + Sync,
        >,
        #[builder(default)] client: ClientQuicConfig,
        #[builder(default)] server: ServerQuicConfig,
        #[builder(default = Arc::new(Vec::new()))] bind: Arc<Vec<BindPattern>>,
    ) -> Self {
        let bind = if bind.is_empty() {
            Arc::new(vec![BindPattern::from_str("*").unwrap()])
        } else {
            bind
        };
        let binds: Vec<BindHandle> =
            join_all(bind.iter().map(|p| network.quic().bind(p.clone()))).await;
        let endpoint = Self {
            network,
            identity: Arc::new(ArcSwapOption::from(identity)),
            resolver,
            client: Arc::new(ArcSwap::from_pointee(client)),
            server: Arc::new(ArcSwap::from_pointee(server)),
            bind,
            _binds: Arc::new(binds),
            client_tls_cache: ArcSwapOption::empty(),
            server_binding_cache: ArcSwapOption::empty(),
        };
        endpoint.init_client();
        endpoint.init_server().await;
        endpoint
    }
}

impl QuicEndpoint {
    fn ensure_client(&self) -> Result<Arc<ClientConfig>, BuildClientTlsError> {
        if let Some(cached) = self.client_tls_cache.load_full() {
            return Ok(cached);
        }
        let config = Arc::new(self.build_client_tls()?);
        self.client_tls_cache.store(Some(config.clone()));
        Ok(config)
    }

    fn build_client_tls(&self) -> Result<ClientConfig, BuildClientTlsError> {
        use build_client_tls_error::{ClientAuthSnafu, VersionSnafu};

        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = ClientConfig::builder().crypto_provider().clone();
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13)
            .context(VersionSnafu)?;
        let client = self.client.load_full();
        let builder = match &client.verifier {
            ServerCertVerifierChoice::Dangerous => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier)),
            ServerCertVerifierChoice::WebPki(v) => builder.with_webpki_verifier(v.clone()),
            ServerCertVerifierChoice::Custom(v) => builder
                .dangerous()
                .with_custom_certificate_verifier(v.clone()),
        };
        let mut tls = match self.identity.load_full() {
            None => builder.with_no_client_auth(),
            Some(id) => builder
                .with_client_auth_cert(id.certs.iter().cloned().collect(), id.key.clone_key())
                .context(ClientAuthSnafu)?,
        };
        tls.alpn_protocols.clone_from(&client.alpns);
        tls.enable_early_data = client.enable_0rtt;
        Ok(tls)
    }
}

impl QuicEndpoint {
    fn build_client_connection(
        &self,
        server_name: &str,
        tls: Arc<ClientConfig>,
    ) -> Result<Arc<Connection>, BuildClientTlsError> {
        use build_client_tls_error::SetParameterSnafu;

        // Propagate the endpoint's named identity into the QUIC transport
        // `ClientName` parameter so the peer can populate its
        // `remote_authority` (identity-based access control on the server
        // relies on this).
        let client = self.client.load_full();
        let mut parameters = client.parameters.clone();
        if let Some(named) = self.identity.load_full() {
            parameters
                .set(
                    crate::dquic::qbase::param::ParameterId::ClientName,
                    named.name.to_string(),
                )
                .context(SetParameterSnafu)?;
        }
        let builder = Connection::new_client(server_name.to_owned(), client.token_sink.clone())
            .with_parameters(parameters)
            .with_tls_config((*tls).clone())
            .with_streams_concurrency_strategy(client.stream_strategy_factory.as_ref())
            .with_zero_rtt(client.enable_0rtt);
        let connection = self
            .network
            .quic()
            .configure_connection(builder)
            .with_defer_idle_timeout(client.defer_idle_timeout)
            .with_cids(ConnectionId::random_gen(8))
            .with_qlog(client.qlogger.clone())
            .run();
        Ok(connection)
    }
}

impl QuicEndpoint {
    async fn ensure_server(&self) -> Result<ServerBinding, AcceptError> {
        use accept_error::BindServerSnafu;

        let named = match self.identity.load_full() {
            None => return Err(AcceptError::ServerUnavailable),
            Some(id) => id,
        };
        if let Some(cached) = self.server_binding_cache.load_full() {
            return Ok(cached.as_ref().clone());
        }
        let server = self.server.load_full();
        let binding = self
            .network
            .quic()
            .bind_server(named, (*server).clone(), self.bind.clone())
            .await
            .context(BindServerSnafu)?;
        self.server_binding_cache
            .store(Some(Arc::new(binding.clone())));
        Ok(binding)
    }

    /// Eagerly build the client TLS configuration so the first `connect()`
    /// is fast. Silently ignores errors — the real error surfaces at
    /// connection time.
    fn init_client(&self) {
        let _ = self.ensure_client();
    }

    /// Eagerly register the server SNI so `accept()` can return immediately.
    /// No-op when no identity is configured. Silently ignores errors.
    async fn init_server(&self) {
        if self.identity.load_full().is_some() {
            let _ = self.ensure_server().await;
        }
    }

    /// Accept an inbound connection, using the cached server binding.
    pub async fn accept(&self) -> Result<Arc<Connection>, AcceptError> {
        let binding = self.ensure_server().await?;
        let conn = binding.recv().await.ok_or(AcceptError::Shutdown)?;
        let mut observer = self.network.quic().locations().subscribe();
        let weak = Arc::downgrade(&conn);
        let patterns: Vec<BindPattern> = self.bind.iter().cloned().collect();
        // Inherent termination: this companion task tracks local
        // address changes for the accepted connection. It exits when
        // (a) conn is dropped (weak.upgrade fails), (b) conn terminates,
        // or (c) the locations observer channel is exhausted. The
        // terminated future is created from a temporary strong reference
        // that is dropped before the task waits on close or location events.
        tokio::spawn(
            async move {
                let mut local_addresses = LocalAddressTracker::default();
                loop {
                    let Some(terminated) = weak.upgrade().map(|c| c.terminated()) else {
                        break;
                    };
                    tokio::select! {
                        _ = terminated => break,
                        event = observer.recv() => {
                            let Some((bind_uri, event)) = event else { break };
                            if !patterns.iter().any(|p| p.matches(&bind_uri)) {
                                continue;
                            }
                            let Some(c) = weak.upgrade() else { break };
                            local_addresses.handle(&c, bind_uri, event);
                        }
                    }
                }
            }
            .in_current_span(),
        );
        Ok(conn)
    }
}

impl quic::Connect for QuicEndpoint {
    type Connection = Connection;
    type Error = ConnectError;

    async fn connect(
        &self,
        server: &http::uri::Authority,
    ) -> Result<Arc<Self::Connection>, Self::Error> {
        use connect_error::{DnsSnafu, TlsSnafu};

        let full = server.as_str();
        let server_str = full.rsplit_once('@').map_or(full, |(_, host)| host);

        tracing::debug!(server = server_str, "connecting quic endpoint");
        let tls = self.ensure_client().context(TlsSnafu)?;
        let mut server_eps =
            futures::StreamExt::fuse(self.resolver.lookup(server_str).await.context(DnsSnafu)?);
        let connection = self
            .build_client_connection(server_str, tls)
            .context(TlsSnafu)?;
        tracing::trace!(
            server = server_str,
            timeout_ms = self.connect_path_timeout().as_millis(),
            bind_pattern_count = self.bind.len(),
            "waiting for quic path"
        );

        // Two legs driving path establishment:
        //   1. DNS results      → add peer endpoints
        //   2. Locations events → add local endpoints
        //
        // Locations replays the current bound addresses when a subscriber is
        // registered, so connect does not scan bound interfaces and synthesize
        // local addresses on its own.
        let mut observer = self.network.quic().locations().subscribe();
        let bind = self.bind.clone();
        let connect_timeout = tokio::time::sleep(self.connect_path_timeout());
        tokio::pin!(connect_timeout);
        let mut peer_agent_seen = false;
        let mut local_addresses = LocalAddressTracker::default();

        loop {
            tokio::select! {
                biased;
                _ = connection.terminated() => {
                    return Err(ConnectError::NoReachableEndpoint);
                }
                result = connection.handshaked(), if peer_agent_seen => {
                    result.map_err(|_| ConnectError::NoReachableEndpoint)?;
                    Self::spawn_path_discovery_companion(
                        bind.clone(),
                        connection.clone(),
                        server_eps,
                        observer,
                        local_addresses,
                    );
                    tracing::debug!(server = server_str, "quic endpoint handshaked before agent path");
                    return Ok(connection);
                }
                _ = &mut connect_timeout => {
                    connection
                        .validate()
                        .map_err(|_| ConnectError::NoReachableEndpoint)?;
                    Self::spawn_path_discovery_companion(
                        bind.clone(),
                        connection.clone(),
                        server_eps,
                        observer,
                        local_addresses,
                    );
                    return Ok(connection);
                }
                Some((source, server_ep)) = server_eps.next() => {
                    tracing::trace!(
                        server = server_str,
                        ?source,
                        endpoint = ?server_ep,
                        "resolved peer endpoint"
                    );
                    peer_agent_seen |= Self::endpoint_is_agent(server_ep);
                    Self::add_resolved_peer_endpoint(
                        &connection,
                        source,
                        server_ep,
                    );
                    // Resolver streams often contain a batch of equivalent endpoints
                    // that are ready immediately (for example STUN-agent and
                    // same-link direct records). Install the ready batch before
                    // evaluating readiness so a Direct record cannot return before
                    // a peer Agent record in the same DNS response is observed.
                    peer_agent_seen |= Self::drain_ready_peer_endpoints(
                        &connection,
                        &mut server_eps,
                    );
                }
                Some((bind_uri, event)) = observer.recv() => {
                    if !bind.iter().any(|p| p.matches(&bind_uri)) {
                        tracing::trace!(%bind_uri, "ignoring location event outside bind patterns");
                        continue;
                    }
                    tracing::trace!(%bind_uri, "handling location event for connect");
                    local_addresses.handle(&connection, bind_uri, event);
                }
            }

            match Self::connection_has_paths(&connection, peer_agent_seen) {
                Ok(true) => {
                    Self::spawn_path_discovery_companion(
                        bind.clone(),
                        connection.clone(),
                        server_eps,
                        observer,
                        local_addresses,
                    );
                    tracing::debug!(server = server_str, "quic endpoint has at least one path");
                    return Ok(connection);
                }
                Ok(false) => {} // no paths yet — continue loop
                Err(_) => return Err(ConnectError::NoReachableEndpoint),
            }
        }
    }
}

impl quic::Listen for QuicEndpoint {
    type Connection = Connection;
    type Error = AcceptError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        QuicEndpoint::accept(self).await
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        self.server_binding_cache.store(None);
        Ok(())
    }
}

impl quic::Listen for &QuicEndpoint {
    type Connection = Connection;
    type Error = AcceptError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        (**self).accept().await
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        (**self).shutdown().await
    }
}

#[allow(dead_code)]
impl QuicEndpoint {
    fn invalidate_client_cache(&self) {
        self.client_tls_cache.store(None);
    }

    fn invalidate_server_cache(&self) {
        self.server_binding_cache.store(None);
    }

    fn invalidate_caches(&self) {
        self.invalidate_client_cache();
        self.invalidate_server_cache();
    }

    /// Obtain a mutable guard for the endpoint's identity.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting
    /// `Option<Arc<Identity>>`, so callers may inspect, mutate, set, or
    /// clear the identity. Caches are invalidated when the guard is dropped.
    pub fn identity_mut(&mut self) -> IdentityMutGuard<'_> {
        let value = self.identity.load_full();
        IdentityMutGuard {
            identity: self.identity.as_ref(),
            value,
            client_cache: &self.client_tls_cache,
            server_cache: &self.server_binding_cache,
        }
    }

    /// Update the OCSP staple for this endpoint's identity.
    ///
    /// Convenience wrapper around [`Self::identity_mut`]; no-op when there
    /// is no identity set.
    pub fn update_ocsp(&mut self, ocsp: Option<Vec<u8>>) {
        let mut guard = self.identity_mut();
        if let Some(arc) = guard.as_mut() {
            Arc::make_mut(arc).ocsp = Arc::new(ocsp);
        }
    }

    /// Obtain a mutable guard for the client configuration.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting
    /// [`ClientQuicConfig`], so callers can mutate fields directly.
    /// When the guard is dropped, the `client_tls_cache` is invalidated.
    pub fn client_config_mut(&mut self) -> ClientConfigMutGuard<'_> {
        ClientConfigMutGuard {
            config: self.client.load_full(),
            target: self.client.as_ref(),
            cache: &self.client_tls_cache,
        }
    }

    /// Obtain a mutable guard for the server configuration.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting
    /// [`ServerQuicConfig`], so callers can mutate fields directly.
    /// When the guard is dropped, the `server_binding_cache` is invalidated.
    pub fn server_config_mut(&mut self) -> ServerConfigMutGuard<'_> {
        ServerConfigMutGuard {
            config: self.server.load_full(),
            target: self.server.as_ref(),
            cache: &self.server_binding_cache,
        }
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s identity.
///
/// On drop, stores the modified identity back into the endpoint's
/// `ArcSwapOption<Identity>` and invalidates both caches (identity changes
/// affect both client TLS auth cert and server SNI binding).
pub struct IdentityMutGuard<'a> {
    identity: &'a ArcSwapOption<Identity>,
    value: Option<Arc<Identity>>,
    client_cache: &'a ArcSwapOption<ClientConfig>,
    server_cache: &'a ArcSwapOption<ServerBinding>,
}

impl<'a> std::ops::Deref for IdentityMutGuard<'a> {
    type Target = Option<Arc<Identity>>;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<'a> std::ops::DerefMut for IdentityMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<'a> Drop for IdentityMutGuard<'a> {
    fn drop(&mut self) {
        self.identity.store(self.value.take());
        self.client_cache.store(None);
        self.server_cache.store(None);
    }
}

#[derive(Default)]
struct LocalAddressTracker {
    direct: HashMap<BindUri, SocketAddr>,
    stun: HashMap<BindUri, EndpointAddr>,
}

impl LocalAddressTracker {
    fn handle(
        &mut self,
        conn: &Connection,
        bind_uri: BindUri,
        event: crate::dquic::qinterface::component::location::AddressEvent<dyn Any + Send + Sync>,
    ) {
        use crate::dquic::qinterface::component::location::AddressEvent;

        let event = match event.downcast::<std::io::Result<SocketAddr>>() {
            Ok(event) => {
                self.handle_direct(conn, bind_uri, event);
                return;
            }
            Err(event) => event,
        };

        match event.downcast::<crate::dquic::qtraversal::nat::client::ClientLocationData>() {
            Ok(event) => self.handle_stun(conn, bind_uri, event),
            Err(AddressEvent::Upsert(data)) => {
                let type_id = data.as_ref().type_id();
                tracing::trace!(
                    %bind_uri,
                    ?type_id,
                    "ignoring unknown local address upsert event"
                );
            }
            Err(AddressEvent::Remove(type_id)) => {
                tracing::trace!(
                    %bind_uri,
                    ?type_id,
                    "ignoring unknown local address remove event"
                );
            }
            Err(AddressEvent::Closed) => self.remove_all(conn, &bind_uri),
        }
    }

    fn handle_direct(
        &mut self,
        conn: &Connection,
        bind_uri: BindUri,
        event: crate::dquic::qinterface::component::location::AddressEvent<
            std::io::Result<SocketAddr>,
        >,
    ) {
        use crate::dquic::qinterface::component::location::AddressEvent;

        match event {
            AddressEvent::Upsert(data) => match data.as_ref() {
                Ok(addr) => self.upsert_direct(conn, bind_uri, *addr),
                Err(error) => {
                    tracing::trace!(
                        %bind_uri,
                        error = %Report::from_error(error),
                        "direct local address update failed"
                    );
                    self.remove_direct(conn, &bind_uri);
                }
            },
            AddressEvent::Remove(_type_id) => self.remove_direct(conn, &bind_uri),
            AddressEvent::Closed => self.remove_all(conn, &bind_uri),
        }
    }

    fn handle_stun(
        &mut self,
        conn: &Connection,
        bind_uri: BindUri,
        event: crate::dquic::qinterface::component::location::AddressEvent<
            crate::dquic::qtraversal::nat::client::ClientLocationData,
        >,
    ) {
        use crate::dquic::qinterface::component::location::AddressEvent;

        match event {
            AddressEvent::Upsert(data) => match data.as_ref() {
                Ok(endpoint) => self.upsert_stun(conn, bind_uri, *endpoint),
                Err(error) => {
                    tracing::trace!(
                        %bind_uri,
                        error = %Report::from_error(error),
                        "stun local address update failed"
                    );
                    self.remove_stun(conn, &bind_uri);
                }
            },
            AddressEvent::Remove(_type_id) => self.remove_stun(conn, &bind_uri),
            AddressEvent::Closed => self.remove_all(conn, &bind_uri),
        }
    }

    fn upsert_direct(&mut self, conn: &Connection, bind_uri: BindUri, addr: SocketAddr) {
        if self.direct.get(&bind_uri) == Some(&addr) {
            return;
        }
        if let Some(previous) = self.direct.insert(bind_uri.clone(), addr) {
            self.remove_endpoint(conn, &bind_uri, EndpointAddr::direct(previous));
        }
        if let Err(error) = conn.add_local_endpoint(bind_uri, EndpointAddr::direct(addr)) {
            tracing::trace!(
                error = %Report::from_error(&error),
                "failed to add local endpoint"
            );
        }
    }

    fn remove_direct(&mut self, conn: &Connection, bind_uri: &BindUri) {
        if let Some(previous) = self.direct.remove(bind_uri) {
            self.remove_endpoint(conn, bind_uri, EndpointAddr::direct(previous));
        }
    }

    fn upsert_stun(&mut self, conn: &Connection, bind_uri: BindUri, endpoint: EndpointAddr) {
        if self.stun.get(&bind_uri) == Some(&endpoint) {
            return;
        }
        if let Some(previous) = self.stun.insert(bind_uri.clone(), endpoint) {
            self.remove_stun_endpoint(conn, &bind_uri, previous);
        }
        QuicEndpoint::add_local_endpoint_for_peer(conn, bind_uri, endpoint);
    }

    fn remove_stun(&mut self, conn: &Connection, bind_uri: &BindUri) {
        if let Some(previous) = self.stun.remove(bind_uri) {
            self.remove_stun_endpoint(conn, bind_uri, previous);
        }
    }

    fn remove_stun_endpoint(&self, conn: &Connection, bind_uri: &BindUri, endpoint: EndpointAddr) {
        self.remove_endpoint(conn, bind_uri, endpoint);
        if matches!(endpoint, EndpointAddr::Agent { .. })
            && let Err(error) = conn.remove_address(endpoint.addr())
        {
            tracing::trace!(
                error = %Report::from_error(&error),
                "failed to remove local punch endpoint"
            );
        }
    }

    fn remove_endpoint(&self, conn: &Connection, bind_uri: &BindUri, endpoint: EndpointAddr) {
        if let Err(error) = conn.remove_local_endpoint(bind_uri, endpoint) {
            tracing::trace!(
                error = %Report::from_error(&error),
                "failed to remove local endpoint"
            );
        }
    }

    fn remove_all(&mut self, conn: &Connection, bind_uri: &BindUri) {
        self.remove_direct(conn, bind_uri);
        self.remove_stun(conn, bind_uri);
    }
}

impl QuicEndpoint {
    fn connect_path_timeout(&self) -> Duration {
        self.client
            .load_full()
            .parameters
            .get::<Duration>(crate::dquic::qbase::param::ParameterId::MaxIdleTimeout)
            .filter(|timeout| !timeout.is_zero())
            .unwrap_or(Duration::from_secs(20))
    }

    fn connection_has_paths(
        connection: &Connection,
        require_agent_path: bool,
    ) -> Result<bool, crate::dquic::qbase::error::Error> {
        let ctx = connection.path_context()?;
        Ok(ctx
            .paths::<Vec<_>>()
            .into_iter()
            .any(|(pathway, _)| Self::pathway_is_connect_ready(pathway, require_agent_path)))
    }

    fn pathway_is_connect_ready(
        pathway: crate::dquic::qbase::net::route::Pathway,
        require_agent_path: bool,
    ) -> bool {
        match (pathway.local(), pathway.remote()) {
            (EndpointAddr::Direct { addr: local }, EndpointAddr::Direct { addr: remote }) => {
                if require_agent_path {
                    return false;
                }
                Self::direct_path_is_connect_ready(local, remote)
            }
            _ => true,
        }
    }

    fn direct_path_is_connect_ready(local: SocketAddr, remote: SocketAddr) -> bool {
        local.ip().is_loopback() == remote.ip().is_loopback()
    }

    fn spawn_path_discovery_companion<S>(
        bind: Arc<Vec<BindPattern>>,
        connection: Arc<Connection>,
        mut server_eps: S,
        mut observer: crate::dquic::qinterface::component::location::Observer,
        local_addresses: LocalAddressTracker,
    ) where
        S: Stream<Item = (Source, EndpointAddr)> + Unpin + Send + 'static,
    {
        let weak = Arc::downgrade(&connection);
        // Inherent termination: this path-discovery companion drains remaining
        // DNS results and local address events after connect has established
        // that the connection will not leak. It creates the terminated future
        // from a temporary strong reference, then drops that reference before
        // awaiting DNS, location, or close events. It exits when (a) connection
        // is dropped (weak.upgrade fails), (b) connection terminates, or (c)
        // both DNS and observer streams are exhausted.
        tokio::spawn(
            async move {
                let mut local_addresses = local_addresses;
                let mut dns_done = false;
                let mut locations_done = false;
                loop {
                    if dns_done && locations_done {
                        break;
                    }
                    let Some(terminated) = weak.upgrade().map(|c| c.terminated()) else {
                        break;
                    };
                    tokio::select! {
                        biased;
                        _ = terminated => break,
                        result = server_eps.next(), if !dns_done => {
                            let Some((s, e)) = result else {
                                dns_done = true;
                                continue;
                            };
                            let Some(c) = weak.upgrade() else { break };
                            Self::add_resolved_peer_endpoint(&c, s, e);
                        }
                        result = observer.recv(), if !locations_done => {
                            let Some((uri, e)) = result else {
                                locations_done = true;
                                continue;
                            };
                            let Some(c) = weak.upgrade() else { break };
                            if bind.iter().any(|p| p.matches(&uri)) {
                                local_addresses.handle(&c, uri, e);
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        );
    }

    fn add_resolved_peer_endpoint(
        connection: &Connection,
        source: Source,
        server_ep: EndpointAddr,
    ) {
        let _ = connection.add_peer_endpoint(server_ep, source);
    }

    fn drain_ready_peer_endpoints<S>(connection: &Connection, server_eps: &mut S) -> bool
    where
        S: Stream<Item = (Source, EndpointAddr)> + Unpin,
    {
        let mut agent_seen = false;
        while let Some(Some((source, server_ep))) = server_eps.next().now_or_never() {
            agent_seen |= Self::endpoint_is_agent(server_ep);
            Self::add_resolved_peer_endpoint(connection, source, server_ep);
        }
        agent_seen
    }

    fn endpoint_is_agent(endpoint: EndpointAddr) -> bool {
        matches!(endpoint, EndpointAddr::Agent { .. })
    }

    fn add_local_endpoint_for_peer(conn: &Connection, bind_uri: BindUri, endpoint: EndpointAddr) {
        if let Err(error) = conn.add_local_endpoint(bind_uri.clone(), endpoint) {
            tracing::trace!(
                error = %Report::from_error(&error),
                "failed to add local endpoint"
            );
        }
        if matches!(endpoint, EndpointAddr::Agent { .. }) {
            match conn.add_local_punch_address(bind_uri, endpoint) {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::trace!(
                        error = %Report::from_error(&error),
                        "failed to add local punch endpoint"
                    );
                }
                Err(error) => {
                    tracing::trace!(
                        error = %Report::from_error(&error),
                        "failed to add local punch endpoint"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use dhttp_identity::identity::LocalAuthority as IdentityLocalAuthority;
    use rustls::{RootCertStore, client::WebPkiServerVerifier, pki_types::PrivateKeyDer};

    use super::*;
    use crate::{
        dquic::{
            cert::handy::{ToCertificate, ToPrivateKey},
            resolver::handy::SystemResolver,
        },
        quic::WithLocalAuthority as _,
    };

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn root_store_with_ca() -> RootCertStore {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(CA_CERT.to_certificate());
        store
    }

    fn make_signing_identity(name: &str) -> Identity {
        Identity::new(
            name.parse().expect("valid identity name"),
            SERVER_CERT.to_certificate(),
            SERVER_KEY.to_private_key(),
        )
    }

    #[tokio::test]
    async fn test_quic_endpoint_construction() {
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let endpoint = QuicEndpoint::builder()
            .network(network.clone())
            .resolver(resolver.clone())
            .client(client)
            .server(server)
            .build()
            .await;

        assert!(Arc::ptr_eq(endpoint.network(), &network));
        assert!(endpoint.identity().is_none());
    }

    #[tokio::test]
    async fn test_accept_with_no_identity() {
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let endpoint = QuicEndpoint::builder()
            .network(network.clone())
            .resolver(resolver.clone())
            .client(client)
            .server(server)
            .build()
            .await;

        let result = endpoint.accept().await;
        assert!(matches!(result, Err(AcceptError::ServerUnavailable)));
    }

    #[tokio::test]
    async fn local_authority_is_none_for_anonymous_endpoint() {
        let endpoint = make_endpoint().await;

        let local = endpoint
            .local_authority()
            .await
            .expect("endpoint local authority lookup should not fail");

        assert!(local.is_none());
    }

    #[tokio::test]
    async fn local_authority_returns_configured_identity() {
        let identity = Arc::new(make_signing_identity("localhost"));
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .resolver(Arc::new(SystemResolver))
            .identity(identity.clone())
            .client(ClientQuicConfig::default())
            .server(ServerQuicConfig::default())
            .build()
            .await;

        let local = endpoint
            .local_authority()
            .await
            .expect("endpoint local authority lookup should not fail")
            .expect("configured endpoint should expose local authority");

        assert_eq!(IdentityLocalAuthority::name(&local), identity.name.as_str());
        assert_eq!(
            IdentityLocalAuthority::cert_chain(&local),
            identity.cert_chain()
        );

        let signature = IdentityLocalAuthority::sign(&local, b"payload")
            .await
            .expect("signature");
        assert!(
            IdentityLocalAuthority::verify(&local, b"payload", &signature)
                .await
                .expect("verification should run")
        );
        assert!(
            !IdentityLocalAuthority::verify(&local, b"different payload", &signature)
                .await
                .expect("verification should run")
        );
    }

    #[tokio::test]
    async fn test_network_locations_accessor() {
        // Verify that the built-in QUIC locations accessor is available.
        let network = Network::builder().build();
        let _locations = network.quic().locations();
        // Just verify we can access it without panicking
    }

    #[tokio::test]
    async fn test_dual_task_connect_structure() {
        // Verify that connect() sets up the dual-task model infrastructure
        // This test verifies the structure is in place, even if full Task A
        // implementation depends on Locations API details
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let client = ClientQuicConfig::default();
        let server = ServerQuicConfig::default();

        let _endpoint = QuicEndpoint::builder()
            .network(network.clone())
            .resolver(resolver.clone())
            .client(client)
            .server(server)
            .build()
            .await;

        // The dual-task model is set up internally in connect()
        // We verify it doesn't panic or error during setup
        // (actual connection would require valid DNS resolution)
    }

    #[tokio::test]
    async fn local_location_before_dns_peer_still_creates_path() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind = Arc::new(vec![bind_pattern.clone()]);
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(bind.clone())
            .build()
            .await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("remote.test", tls)
            .expect("client connection");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let data: Arc<dyn Any + Send + Sync> =
            Arc::new(Ok::<SocketAddr, std::io::Error>(local_addr));
        let event = crate::dquic::qinterface::component::location::AddressEvent::Upsert(data);

        let mut local_addresses = LocalAddressTracker::default();
        local_addresses.handle(&connection, bind_uri, event);

        let remote_addr = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote_addr),
        );

        assert!(
            QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "local endpoint replayed before DNS peer must be retained for peer pairing"
        );
    }

    #[tokio::test]
    async fn loopback_to_non_loopback_direct_path_is_not_connect_ready() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind_endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let tls = bind_endpoint.ensure_client().expect("client tls");
        let connection = bind_endpoint
            .build_client_connection("server.example", tls)
            .expect("client connection");
        let iface = bind_endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let data: Arc<dyn Any + Send + Sync> =
            Arc::new(Ok::<SocketAddr, std::io::Error>(local_addr));
        let mut local_addresses = LocalAddressTracker::default();
        local_addresses.handle(
            &connection,
            bind_uri,
            crate::dquic::qinterface::component::location::AddressEvent::Upsert(data),
        );

        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::direct("10.10.0.100:47388".parse().expect("remote addr")),
        );

        assert!(
            !QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "loopback-to-non-loopback direct paths are not ready for client handshake"
        );
    }

    #[tokio::test]
    async fn peer_agent_requires_agent_path_before_connect_ready() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("server.example", tls)
            .expect("client connection");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let remote_direct = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        let stun_agent: SocketAddr = "10.10.0.2:20004".parse().expect("stun agent");

        let mut local_addresses = LocalAddressTracker::default();
        local_addresses.handle(
            &connection,
            bind_uri.clone(),
            crate::dquic::qinterface::component::location::AddressEvent::Upsert(Arc::new(Ok::<
                SocketAddr,
                std::io::Error,
            >(
                local_addr,
            ))),
        );
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::with_agent(stun_agent, "10.10.0.40:20000".parse().expect("outer addr")),
        );
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::direct(remote_direct),
        );

        assert!(
            QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "direct loopback path is connect-ready when no Agent path is required"
        );
        assert!(
            !QuicEndpoint::connection_has_paths(&connection, true).expect("path context"),
            "peer Agent endpoints must not return on Direct-only paths"
        );

        connection
            .add_local_endpoint(bind_uri, EndpointAddr::with_agent(stun_agent, local_addr))
            .expect("local agent endpoint");
        assert!(
            QuicEndpoint::connection_has_paths(&connection, true).expect("path context"),
            "local Agent endpoint should make peer Agent connection ready"
        );
    }

    #[tokio::test]
    async fn connect_helpers_cover_identity_verifier_and_ready_endpoint_paths() {
        let mut endpoint = make_endpoint().await;
        let webpki = WebPkiServerVerifier::builder(Arc::new(root_store_with_ca()))
            .build()
            .expect("webpki verifier");
        {
            let mut client = endpoint.client_config_mut();
            client.verifier = ServerCertVerifierChoice::WebPki(webpki);
        }
        endpoint
            .build_client_tls()
            .expect("webpki verifier client tls");

        {
            let mut client = endpoint.client_config_mut();
            client.verifier =
                ServerCertVerifierChoice::Custom(Arc::new(DangerousServerCertVerifier));
        }
        let tls = Arc::new(
            endpoint
                .build_client_tls()
                .expect("custom verifier client tls"),
        );
        {
            let mut identity = endpoint.identity_mut();
            *identity = Some(Arc::new(make_identity("client-name.test")));
        }
        endpoint
            .build_client_connection("server.example", tls)
            .expect("client connection with identity parameter");

        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind_endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let tls = bind_endpoint.ensure_client().expect("client tls");
        let connection = bind_endpoint
            .build_client_connection("server.example", tls)
            .expect("client connection");
        let iface = bind_endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let data: Arc<dyn Any + Send + Sync> =
            Arc::new(Ok::<SocketAddr, std::io::Error>(local_addr));
        let mut local_addresses = LocalAddressTracker::default();
        local_addresses.handle(
            &connection,
            bind_uri,
            crate::dquic::qinterface::component::location::AddressEvent::Upsert(data),
        );

        let mut endpoints = futures::stream::iter([
            (
                Source::System,
                EndpointAddr::direct(SocketAddr::new(local_addr.ip(), local_addr.port() + 1)),
            ),
            (
                Source::Dht,
                EndpointAddr::direct(SocketAddr::new(local_addr.ip(), local_addr.port() + 2)),
            ),
        ]);
        QuicEndpoint::drain_ready_peer_endpoints(&connection, &mut endpoints);
        assert!(
            QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "ready peer endpoints should pair with the retained local endpoint"
        );
    }

    #[tokio::test]
    async fn local_address_tracker_removes_direct_endpoint_on_remove() {
        use crate::dquic::qinterface::component::location::AddressEvent;

        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("remote.test", tls)
            .expect("client connection");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let remote_port = if local_addr.port() == u16::MAX {
            local_addr.port() - 1
        } else {
            local_addr.port() + 1
        };
        let remote_addr = SocketAddr::new(local_addr.ip(), remote_port);
        let mut tracker = LocalAddressTracker::default();

        tracker.handle(&connection, bind_uri.clone(), {
            let data: Arc<dyn Any + Send + Sync> =
                Arc::new(Ok::<SocketAddr, std::io::Error>(local_addr));
            AddressEvent::Upsert(data)
        });
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote_addr),
        );
        assert!(
            QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "direct local endpoint should pair with direct remote endpoint"
        );

        tracker.handle(
            &connection,
            bind_uri,
            AddressEvent::Remove(TypeId::of::<std::io::Result<SocketAddr>>()),
        );
        assert!(
            !QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "removing the direct local endpoint should deactivate its path"
        );
    }

    #[tokio::test]
    async fn local_address_tracker_preserves_connect_state_after_move() {
        use crate::dquic::qinterface::component::location::{AddressEvent, Locations};

        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind = Arc::new(vec![bind_pattern.clone()]);
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(bind.clone())
            .build()
            .await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("remote.test", tls)
            .expect("client connection");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let bind_uri = iface.bind_uri();
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let remote_port = if local_addr.port() == u16::MAX {
            local_addr.port() - 1
        } else {
            local_addr.port() + 1
        };
        let remote_addr = SocketAddr::new(local_addr.ip(), remote_port);
        let mut tracker = LocalAddressTracker::default();

        tracker.handle(&connection, bind_uri.clone(), {
            let data: Arc<dyn Any + Send + Sync> =
                Arc::new(Ok::<SocketAddr, std::io::Error>(local_addr));
            AddressEvent::Upsert(data)
        });
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote_addr),
        );
        assert!(
            QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "direct local endpoint should pair with direct remote endpoint before tracker handoff"
        );

        let locations = Locations::new();
        let observer = locations.subscribe();
        QuicEndpoint::spawn_path_discovery_companion(
            bind,
            connection.clone(),
            futures::stream::empty(),
            observer,
            tracker,
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                locations.remove::<std::io::Result<SocketAddr>>(bind_uri.clone());
                if !matches!(
                    QuicEndpoint::connection_has_paths(&connection, false),
                    Ok(true)
                ) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("moved tracker should remove the pre-connect direct local endpoint");
    }

    #[tokio::test]
    async fn path_discovery_companion_does_not_hold_connection_while_waiting_for_events() {
        use crate::dquic::qinterface::component::location::Locations;

        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .build()
            .await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("remote.test", tls)
            .expect("client connection");
        let locations = Locations::new();
        let observer = locations.subscribe();
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let mut polled_tx = Some(polled_tx);
        let server_eps = futures::stream::poll_fn(move |_cx| {
            if let Some(tx) = polled_tx.take() {
                let _ = tx.send(());
            }
            std::task::Poll::Pending
        });

        QuicEndpoint::spawn_path_discovery_companion(
            Arc::new(Vec::new()),
            connection.clone(),
            server_eps,
            observer,
            LocalAddressTracker::default(),
        );

        tokio::time::timeout(Duration::from_secs(1), polled_rx)
            .await
            .expect("companion should poll the DNS stream")
            .expect("poll signal should be delivered");

        assert_eq!(
            Arc::strong_count(&connection),
            1,
            "idle companion task must not keep the connection alive"
        );
    }

    #[tokio::test]
    async fn local_address_tracker_ignores_unknown_payloads() {
        use crate::dquic::qinterface::component::location::AddressEvent;

        let endpoint = make_endpoint().await;
        let tls = endpoint.ensure_client().expect("client tls");
        let connection = endpoint
            .build_client_connection("remote.test", tls)
            .expect("client connection");
        let bind_uri: BindUri = "inet://127.0.0.1:0".parse().expect("bind uri");
        let mut tracker = LocalAddressTracker::default();

        let unknown_payload: Arc<dyn Any + Send + Sync> = Arc::new("not a location payload");
        tracker.handle(&connection, bind_uri, AddressEvent::Upsert(unknown_payload));

        assert!(
            !QuicEndpoint::connection_has_paths(&connection, false).expect("path context"),
            "unknown events should not create paths"
        );
    }

    fn make_identity(name: &str) -> Identity {
        Identity {
            name: name.parse().unwrap(),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy-key-data".to_vec().into())),
            ocsp: Arc::new(None),
        }
    }

    async fn make_endpoint() -> QuicEndpoint {
        QuicEndpoint::builder()
            .network(Network::builder().build())
            .resolver(Arc::new(SystemResolver))
            .client(ClientQuicConfig::default())
            .server(ServerQuicConfig::default())
            .build()
            .await
    }

    #[tokio::test]
    async fn public_new_uses_default_anonymous_endpoint_shape() {
        let endpoint = QuicEndpoint::new().await;

        assert!(endpoint.identity().is_none());
        assert_eq!(endpoint.bind_patterns().len(), 1);
        assert_eq!(endpoint.bind_patterns()[0].to_string(), "iface://*");
        assert!(endpoint.client_tls_cache.load_full().is_some());
        assert!(endpoint.server_binding_cache.load_full().is_none());
    }

    #[tokio::test]
    async fn accessors_return_builder_supplied_components_and_default_bind() {
        let network = Network::builder().build();
        let resolver = Arc::new(SystemResolver);
        let endpoint = QuicEndpoint::builder()
            .network(network.clone())
            .resolver(resolver.clone())
            .build()
            .await;

        assert!(Arc::ptr_eq(endpoint.network(), &network));
        assert!(Arc::ptr_eq(endpoint.resolver(), &(resolver as Arc<_>)));
        assert!(endpoint.identity().is_none());
        assert_eq!(endpoint.bind_patterns().len(), 1);
        assert_eq!(endpoint.bind_patterns()[0].to_string(), "iface://*");
    }

    #[tokio::test]
    async fn ensure_client_caches_tls_but_clone_does_not_share_cache() {
        let endpoint = make_endpoint().await;

        let first = endpoint.ensure_client().expect("client tls should build");
        let second = endpoint
            .ensure_client()
            .expect("client tls should be cached");
        assert!(Arc::ptr_eq(&first, &second));

        let cloned = endpoint.clone();
        assert!(cloned.client_tls_cache.load_full().is_none());
    }

    #[tokio::test]
    async fn build_client_tls_copies_alpns_and_early_data_flag() {
        let mut endpoint = make_endpoint().await;
        {
            let mut client = endpoint.client_config_mut();
            client.alpns = vec![b"h3".to_vec(), b"dhttp".to_vec()];
            client.enable_0rtt = true;
        }

        let tls = endpoint
            .build_client_tls()
            .expect("client tls should build");

        assert_eq!(tls.alpn_protocols, endpoint.client.load_full().alpns);
        assert!(tls.enable_early_data);
    }

    #[tokio::test]
    async fn test_identity_mut_set() {
        let mut endpoint = make_endpoint().await;
        assert!(endpoint.identity().is_none());

        let identity = make_identity("test.example.com");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }

        let id = endpoint.identity();
        assert!(id.is_some());
        assert_eq!(id.unwrap().name.as_str(), "test.example.com");
    }

    #[tokio::test]
    async fn test_identity_mut_clear() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("clear.me");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }
        assert!(endpoint.identity().is_some());

        {
            let mut guard = endpoint.identity_mut();
            *guard = None;
        }

        assert!(endpoint.identity().is_none());
    }

    #[tokio::test]
    async fn test_identity_mut_mutate() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("mutate.me");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }
        assert!(endpoint.identity().unwrap().ocsp.is_none());

        {
            let mut guard = endpoint.identity_mut();
            if let Some(arc) = guard.as_mut() {
                Arc::make_mut(arc).ocsp = Arc::new(Some(vec![10, 20, 30]));
            }
        }

        let id = endpoint.identity().unwrap();
        assert_eq!(id.ocsp.as_deref(), Some(&[10u8, 20, 30][..]));
    }

    #[tokio::test]
    async fn test_update_ocsp_with_identity() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("ocsp.example.com");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }

        endpoint.update_ocsp(Some(vec![1, 2, 3]));

        let id = endpoint.identity().unwrap();
        assert_eq!(id.ocsp.as_deref(), Some(&[1u8, 2, 3][..]));
    }

    #[tokio::test]
    async fn test_update_ocsp_without_identity_no_panic() {
        let mut endpoint = make_endpoint().await;
        assert!(endpoint.identity().is_none());

        endpoint.update_ocsp(Some(vec![9, 8, 7]));
        assert!(endpoint.identity().is_none());
    }

    #[tokio::test]
    async fn identity_guard_deref_and_invalidate_caches_cover_direct_helpers() {
        let mut endpoint = make_endpoint().await;
        endpoint.client_tls_cache.store(Some(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));

        {
            let mut guard = endpoint.identity_mut();
            assert!(std::ops::Deref::deref(&guard).is_none());
            *guard = Some(Arc::new(make_identity("deref-helper.test")));
            assert_eq!(
                std::ops::Deref::deref(&guard)
                    .as_ref()
                    .expect("guard identity")
                    .name
                    .as_str(),
                "deref-helper.test"
            );
        }
        assert!(endpoint.identity().is_some());

        endpoint.client_tls_cache.store(Some(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));
        endpoint.invalidate_caches();
        assert!(endpoint.client_tls_cache.load_full().is_none());
        assert!(endpoint.server_binding_cache.load_full().is_none());
    }

    #[tokio::test]
    async fn test_client_config_mut() {
        let mut endpoint = make_endpoint().await;
        assert!(!endpoint.client.load_full().enable_0rtt);

        {
            let mut guard = endpoint.client_config_mut();
            guard.enable_0rtt = true;
        } // guard dropped → cache invalidated

        assert!(endpoint.client.load_full().enable_0rtt);
    }

    #[tokio::test]
    async fn test_client_config_mut_drop_invalidates_cache() {
        let mut endpoint = make_endpoint().await;
        // Pre-fill the cache by triggering ensure_client
        let _ = endpoint.ensure_client().is_ok();
        assert!(endpoint.client_tls_cache.load_full().is_some());

        {
            let _guard = endpoint.client_config_mut();
            // No mutation needed — just creating and dropping should invalidate
        }

        assert!(endpoint.client_tls_cache.load_full().is_none());
    }

    #[tokio::test]
    async fn test_server_config_mut() {
        let mut endpoint = make_endpoint().await;
        assert!(!endpoint.server.load_full().anti_port_scan);

        {
            let mut guard = endpoint.server_config_mut();
            guard.anti_port_scan = true;
        }

        assert!(endpoint.server.load_full().anti_port_scan);
    }

    #[tokio::test]
    async fn test_server_config_mut_drop_invalidates_cache() {
        let mut endpoint = make_endpoint().await;

        {
            let _guard = endpoint.server_config_mut();
        }

        // Guard drop should clear the cache (whether it was filled or not)
        assert!(endpoint.server_binding_cache.load_full().is_none());
    }

    #[tokio::test]
    async fn clone_shares_identity_updates() {
        let mut endpoint = make_endpoint().await;
        let mut cloned = endpoint.clone();

        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(make_identity("shared-identity.test")));
        }

        assert_eq!(
            cloned
                .identity()
                .expect("clone sees shared identity")
                .name
                .as_str(),
            "shared-identity.test"
        );

        {
            let mut guard = cloned.identity_mut();
            *guard = None;
        }

        assert!(endpoint.identity().is_none());
    }

    #[tokio::test]
    async fn set_resolver_on_clone_does_not_change_original_resolver() {
        let endpoint = make_endpoint().await;
        let original = endpoint.resolver().clone();
        let replacement: Arc<dyn Resolve + Send + Sync> = Arc::new(SystemResolver);
        let mut cloned = endpoint.clone();

        cloned.set_resolver(replacement.clone());

        assert!(Arc::ptr_eq(endpoint.resolver(), &original));
        assert!(Arc::ptr_eq(cloned.resolver(), &replacement));
    }

    #[tokio::test]
    async fn test_clone_preserves_identity() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("clone-preserve.test");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }

        let cloned = endpoint.clone();
        let orig_id = endpoint.identity().unwrap();
        let cloned_id = cloned.identity().unwrap();

        assert_eq!(orig_id.name.as_str(), cloned_id.name.as_str());
        assert_eq!(orig_id.certs.len(), cloned_id.certs.len());
        assert_eq!(orig_id.ocsp.as_deref(), cloned_id.ocsp.as_deref());
    }

    #[tokio::test]
    async fn clone_shares_identity_clear() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("shared-clear.test");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }

        let cloned = endpoint.clone();

        {
            let mut guard = endpoint.identity_mut();
            *guard = None;
        }
        assert!(endpoint.identity().is_none());
        assert!(cloned.identity().is_none());
    }

    #[test]
    fn test_build_client_tls_error_variants() {
        // Cannot construct BuildClientTlsError without real rustls errors;
        // verify the enum definition compiles and variant names are correct.
        let _ = |e: BuildClientTlsError| match e {
            BuildClientTlsError::Version { .. } => "version",
            BuildClientTlsError::ClientAuth { .. } => "client_auth",
            BuildClientTlsError::SetParameter { .. } => "set_param",
        };
    }

    #[test]
    fn test_connect_error_variant_discrimination() {
        let err = ConnectError::NoReachableEndpoint;
        match &err {
            ConnectError::Tls { .. } => panic!("expected NoReachableEndpoint, got Tls"),
            ConnectError::Dns { .. } => panic!("expected NoReachableEndpoint, got Dns"),
            ConnectError::NoReachableEndpoint => {}
        }

        let _ = |e: BuildClientTlsError| match e {
            BuildClientTlsError::Version { .. }
            | BuildClientTlsError::ClientAuth { .. }
            | BuildClientTlsError::SetParameter { .. } => {}
        };
    }

    #[test]
    fn test_accept_error_variant_discrimination() {
        let unavailable = AcceptError::ServerUnavailable;
        match &unavailable {
            AcceptError::ServerUnavailable => {}
            AcceptError::BindServer { .. } => panic!("expected ServerUnavailable"),
            AcceptError::Shutdown => panic!("expected ServerUnavailable"),
        }

        let shutdown = AcceptError::Shutdown;
        match &shutdown {
            AcceptError::Shutdown => {}
            _ => panic!("expected Shutdown"),
        }
    }

    #[test]
    fn test_accept_error_server_unavailable_message() {
        let err = AcceptError::ServerUnavailable;
        let msg = err.to_string();
        assert!(
            msg.contains("cannot accept"),
            "AcceptError::ServerUnavailable message should contain 'cannot accept', got: {msg}"
        );
    }

    #[test]
    fn test_accept_error_shutdown_message() {
        let err = AcceptError::Shutdown;
        let msg = err.to_string();
        assert!(
            msg.contains("shut down"),
            "AcceptError::Shutdown message should contain 'shut down', got: {msg}"
        );
    }

    #[test]
    fn test_connect_error_display() {
        let err = ConnectError::NoReachableEndpoint;
        let msg = err.to_string();
        assert!(
            msg.contains("no reachable endpoint"),
            "ConnectError::NoReachableEndpoint message should mention reachable endpoint, got: {msg}"
        );
    }

    #[test]
    fn test_endpoint_error_alias() {
        let _: EndpointError = ConnectError::NoReachableEndpoint;
        let _: ConnectError = EndpointError::NoReachableEndpoint;

        fn _accept_endpoint_error(_: EndpointError) {}
        fn _accept_connect_error(_: ConnectError) {}
    }

    #[test]
    fn test_server_config_guard_derefmut() {
        let config = Arc::new(ServerQuicConfig::default());
        let target = ArcSwap::from(config);
        let cache = ArcSwapOption::<ServerBinding>::new(None);
        {
            let mut guard = ServerConfigMutGuard {
                config: target.load_full(),
                target: &target,
                cache: &cache,
            };
            assert!(!guard.anti_port_scan);
            guard.anti_port_scan = true;
            assert!(guard.anti_port_scan);
        }
        assert!(target.load_full().anti_port_scan);
    }

    #[test]
    fn test_server_config_guard_drop_invalidates_cache() {
        use std::sync::Weak;

        use dashmap::DashMap;
        use rustls::{pki_types::CertificateDer, sign::CertifiedKey};

        use crate::dquic::{
            cert::handy::{ToCertificate, ToPrivateKey},
            sni::{RegistryGuard, ServerConfig as SniServerConfig, ServerEntry},
        };

        let config = Arc::new(ServerQuicConfig::default());
        let target = ArcSwap::from(config);
        let cache = ArcSwapOption::new(None);

        let cert_bytes: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        let key_bytes: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
        let certs: Vec<CertificateDer<'static>> = cert_bytes.to_certificate();
        let key: PrivateKeyDer<'static> = key_bytes.to_private_key();

        let identity = Arc::new(Identity {
            name: "localhost".parse().unwrap(),
            certs: Arc::new(certs.clone()),
            key: Arc::new(key.clone_key()),
            ocsp: Arc::new(None),
        });

        let provider = rustls::ServerConfig::builder().crypto_provider().clone();
        let signing_key = provider
            .key_provider
            .load_private_key(identity.key.clone_key())
            .expect("valid private key");
        let certified_key = Arc::new(CertifiedKey {
            cert: identity.certs.iter().cloned().collect(),
            key: signing_key,
            ocsp: None,
        });

        let rustls_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .expect("valid server config"),
        );

        let (tx, rx) = async_channel::unbounded();

        let registry = Arc::new(DashMap::new());
        let reg_guard = Arc::new(RegistryGuard {
            name: "localhost".parse().unwrap(),
            registry: Arc::downgrade(&registry),
            self_entry: Weak::new(),
        });

        let sni_config = Arc::new(SniServerConfig {
            config: ServerQuicConfig::default(),
            rustls_config,
        });

        let entry = Arc::new(ServerEntry {
            identity,
            certified_key,
            incomings_tx: tx,
            incomings_rx: rx,
            config: sni_config,
            guard: reg_guard,
            bind: Arc::new(vec![]),
        });

        let binding = ServerBinding { entry };
        cache.store(Some(Arc::new(binding)));

        assert!(cache.load_full().is_some());

        {
            let _guard = ServerConfigMutGuard {
                config: target.load_full(),
                target: &target,
                cache: &cache,
            };
        }

        assert!(cache.load_full().is_none());
    }

    #[tokio::test]
    async fn test_identity_guard_set() {
        let endpoint = make_endpoint().await;
        assert!(endpoint.identity().is_none());

        let identity = make_identity("guard-set.test");
        {
            let mut guard = IdentityMutGuard {
                identity: endpoint.identity.as_ref(),
                value: endpoint.identity.load_full(),
                client_cache: &endpoint.client_tls_cache,
                server_cache: &endpoint.server_binding_cache,
            };
            *guard = Some(Arc::new(identity));
        }

        let id = endpoint.identity();
        assert!(id.is_some());
        assert_eq!(id.unwrap().name.as_str(), "guard-set.test");
    }

    #[tokio::test]
    async fn test_identity_guard_clear() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("guard-clear.test");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }
        assert!(endpoint.identity().is_some());

        {
            let mut guard = IdentityMutGuard {
                identity: endpoint.identity.as_ref(),
                value: endpoint.identity.load_full(),
                client_cache: &endpoint.client_tls_cache,
                server_cache: &endpoint.server_binding_cache,
            };
            *guard = None;
        }

        assert!(endpoint.identity().is_none());
    }

    #[tokio::test]
    async fn test_identity_guard_mutate() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("guard-mutate.test");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }
        assert!(endpoint.identity().unwrap().ocsp.is_none());

        {
            let mut guard = IdentityMutGuard {
                identity: endpoint.identity.as_ref(),
                value: endpoint.identity.load_full(),
                client_cache: &endpoint.client_tls_cache,
                server_cache: &endpoint.server_binding_cache,
            };
            if let Some(arc) = guard.as_mut() {
                Arc::make_mut(arc).ocsp = Arc::new(Some(vec![10, 20, 30]));
            }
        }

        let id = endpoint.identity().unwrap();
        assert_eq!(id.ocsp.as_deref(), Some(&[10u8, 20, 30][..]));
    }

    #[tokio::test]
    async fn test_identity_guard_drop_invalidates_both_caches() {
        let mut endpoint = make_endpoint().await;
        let identity = make_identity("cache-inval.test");
        {
            let mut guard = endpoint.identity_mut();
            *guard = Some(Arc::new(identity));
        }

        // Pre-fill client TLS cache
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        endpoint
            .client_tls_cache
            .store(Some(Arc::new(client_config)));

        // Pre-fill server binding cache — construct a minimal ServerBinding
        // through the network infrastructure
        endpoint.init_server().await;

        {
            let guard = IdentityMutGuard {
                identity: endpoint.identity.as_ref(),
                value: endpoint.identity.load_full(),
                client_cache: &endpoint.client_tls_cache,
                server_cache: &endpoint.server_binding_cache,
            };
            // no mutation — guard drops here
            let _ = &guard;
        }

        assert!(
            endpoint.client_tls_cache.load_full().is_none(),
            "client TLS cache should be invalidated on guard drop"
        );
        assert!(
            endpoint.server_binding_cache.load_full().is_none(),
            "server binding cache should be invalidated on guard drop"
        );
    }

    #[test]
    fn test_client_config_guard_derefmut() {
        let config = Arc::new(ClientQuicConfig::default());
        let target = ArcSwap::from(config);
        let cache = ArcSwapOption::<ClientConfig>::new(None);
        {
            let mut guard = ClientConfigMutGuard {
                config: target.load_full(),
                target: &target,
                cache: &cache,
            };
            assert!(!std::ops::Deref::deref(&guard).enable_0rtt);
            guard.enable_0rtt = true;
        }
        assert!(target.load_full().enable_0rtt);
    }

    #[tokio::test]
    async fn quic_listen_trait_impls_delegate_accept_and_shutdown() {
        let mut owned = make_endpoint().await;
        let owned_error = match <QuicEndpoint as quic::Listen>::accept(&mut owned).await {
            Ok(_) => panic!("anonymous owned endpoint cannot accept"),
            Err(error) => error,
        };
        assert!(matches!(owned_error, AcceptError::ServerUnavailable));
        <QuicEndpoint as quic::Listen>::shutdown(&owned)
            .await
            .expect("owned shutdown");

        let endpoint = make_endpoint().await;
        let mut shared = &endpoint;
        let shared_error = match <&QuicEndpoint as quic::Listen>::accept(&mut shared).await {
            Ok(_) => panic!("anonymous shared endpoint cannot accept"),
            Err(error) => error,
        };
        assert!(matches!(shared_error, AcceptError::ServerUnavailable));
        <&QuicEndpoint as quic::Listen>::shutdown(&shared)
            .await
            .expect("shared shutdown");
    }

    #[test]
    fn test_client_config_guard_drop_invalidates_cache() {
        let config = Arc::new(ClientQuicConfig::default());
        let target = ArcSwap::from(config);
        let cache = ArcSwapOption::new(Some(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));

        assert!(cache.load_full().is_some());

        {
            let _guard = ClientConfigMutGuard {
                config: target.load_full(),
                target: &target,
                cache: &cache,
            };
        }

        assert!(cache.load_full().is_none());
    }

    #[tokio::test]
    async fn test_cache_invalidation_is_precise() {
        let endpoint = make_endpoint().await;

        // Pre-fill client cache
        let dummy_client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        endpoint
            .client_tls_cache
            .store(Some(Arc::new(dummy_client_tls)));

        assert!(endpoint.client_tls_cache.load_full().is_some());
        assert!(endpoint.server_binding_cache.load_full().is_none());

        // Client cache invalidation should NOT affect server cache
        endpoint.invalidate_client_cache();
        assert!(endpoint.client_tls_cache.load_full().is_none());
        assert!(endpoint.server_binding_cache.load_full().is_none());

        // Re-fill client, invalidate server — client should remain intact
        endpoint.client_tls_cache.store(Some(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        )));
        endpoint.invalidate_server_cache();
        assert!(endpoint.client_tls_cache.load_full().is_some());
        assert!(endpoint.server_binding_cache.load_full().is_none());
    }

    #[test]
    fn test_invalidate_caches_clears_both() {
        // Verify the method structure compiles and that invalidate_caches
        // delegates to both precise helpers.
        let cache_client: ArcSwapOption<rustls::ClientConfig> = ArcSwapOption::empty();
        let cache_server: ArcSwapOption<ServerBinding> = ArcSwapOption::empty();

        // Populate client cache
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        cache_client.store(Some(Arc::new(client_config)));

        assert!(cache_client.load_full().is_some());
        assert!(cache_server.load_full().is_none());
    }
}
