//! QUIC-only endpoint built on top of a shared [`Network`].

use std::{
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

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
        identity::{self, Identity, Name},
        net::{ConnectionId, EndpointAddr},
        network::{BindHandle, BindServerError, Network, ServerBinding},
        resolver::{Resolve, Source},
        server::ServerQuicConfig,
        sni::{ServerCredentials, ServerOwner},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceIdentityOutcome {
    Updated,
    Unchanged,
}

/// Error returned when replacing a live endpoint identity.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum ReplaceIdentityError {
    /// Live replacement requires an existing named identity.
    #[snafu(display("cannot replace the identity of an anonymous endpoint"))]
    MissingCurrentIdentity,
    /// SNI ownership cannot change during live replacement.
    #[snafu(display("replacement identity name changed from {current} to {replacement}"))]
    NameChanged {
        current: Name<'static>,
        replacement: Name<'static>,
    },
    /// The replacement certificate and key could not be prepared for rustls.
    #[snafu(display("failed to prepare replacement identity"))]
    Prepare { source: BindServerError },
    /// The endpoint no longer owns the credentials it is trying to replace.
    #[snafu(display("server registration for {name} has newer credentials"))]
    StaleRegistration { name: Name<'static> },
}

/// Back-compat alias.
pub type EndpointError = ConnectError;

struct ClientRuntime {
    identity: Option<Arc<Identity>>,
    client: Arc<ClientQuicConfig>,
    tls: Arc<ClientConfig>,
}

/// Authoritative endpoint configuration. Runtime caches are derived from one
/// coherent read of this aggregate.
#[derive(Clone)]
struct EndpointConfig {
    identity: Option<Arc<Identity>>,
    client: Arc<ClientQuicConfig>,
    server: Arc<ServerQuicConfig>,
}

impl EndpointConfig {
    fn same_server_state(&self, other: &Self) -> bool {
        self.identity.as_deref() == other.identity.as_deref()
            && self.server.as_ref() == other.server.as_ref()
    }
}

/// State shared by an endpoint and its clones. Code taking multiple locks must
/// acquire `config` before either derived-state mutex.
struct EndpointState {
    config: RwLock<EndpointConfig>,
    client_runtime: Mutex<Option<Arc<ClientRuntime>>>,
    server_registration: Mutex<Option<ServerBinding>>,
    server_owner: Arc<ServerOwner>,
}

impl EndpointState {
    fn new(
        identity: Option<Arc<Identity>>,
        client: ClientQuicConfig,
        server: ServerQuicConfig,
    ) -> Self {
        Self {
            config: RwLock::new(EndpointConfig {
                identity,
                client: Arc::new(client),
                server: Arc::new(server),
            }),
            client_runtime: Mutex::new(None),
            server_registration: Mutex::new(None),
            server_owner: Arc::new(ServerOwner),
        }
    }
}

/// A QUIC-only endpoint backed by a shared [`Network`].
pub struct QuicEndpoint {
    /// Shared network infrastructure.
    pub(crate) network: Arc<Network>,
    state: Arc<EndpointState>,
    /// Resolver used when establishing outbound connections.
    pub(crate) resolver: Arc<dyn Resolve + Send + Sync>,
    /// Bind patterns for interface filtering (shared by client and server roles).
    pub(crate) bind: Arc<Vec<BindPattern>>,
    _binds: Arc<Vec<BindHandle>>,
}

impl Clone for QuicEndpoint {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            state: self.state.clone(),
            resolver: self.resolver.clone(),
            bind: self.bind.clone(),
            _binds: self._binds.clone(),
        }
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s client configuration.
///
/// If changed, dropping the guard invalidates the cached client runtime so the
/// next `connect()` call rebuilds the TLS configuration.
pub struct ClientConfigMutGuard<'a> {
    state: &'a EndpointState,
    original: Arc<ClientQuicConfig>,
    value: Arc<ClientQuicConfig>,
}

impl<'a> std::ops::Deref for ClientConfigMutGuard<'a> {
    type Target = ClientQuicConfig;
    fn deref(&self) -> &Self::Target {
        self.value.as_ref()
    }
}

impl<'a> std::ops::DerefMut for ClientConfigMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.value)
    }
}

impl<'a> Drop for ClientConfigMutGuard<'a> {
    fn drop(&mut self) {
        if self.value.as_ref() == self.original.as_ref() {
            return;
        }
        let mut config = self
            .state
            .config
            .write()
            .expect("endpoint config lock poisoned");
        config.client = self.value.clone();
        self.state
            .client_runtime
            .lock()
            .expect("client runtime mutex poisoned")
            .take();
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s server configuration.
///
/// If changed, dropping the guard unregisters the active server binding so the
/// next `accept()` call rebuilds it.
pub struct ServerConfigMutGuard<'a> {
    state: &'a EndpointState,
    original: Arc<ServerQuicConfig>,
    value: Arc<ServerQuicConfig>,
}

impl<'a> std::ops::Deref for ServerConfigMutGuard<'a> {
    type Target = ServerQuicConfig;
    fn deref(&self) -> &Self::Target {
        self.value.as_ref()
    }
}

impl<'a> std::ops::DerefMut for ServerConfigMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Arc::make_mut(&mut self.value)
    }
}

impl<'a> Drop for ServerConfigMutGuard<'a> {
    fn drop(&mut self) {
        if self.value.as_ref() == self.original.as_ref() {
            return;
        }
        let mut config = self
            .state
            .config
            .write()
            .expect("endpoint config lock poisoned");
        config.server = self.value.clone();
        self.state
            .server_registration
            .lock()
            .expect("server registration mutex poisoned")
            .take();
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
        self.state
            .config
            .read()
            .expect("endpoint config lock poisoned")
            .identity
            .clone()
    }

    /// Replace certificate and key material without unregistering the SNI.
    ///
    /// Existing connections keep their negotiated identity. New handshakes
    /// observe either the complete old credentials or the complete new
    /// credentials.
    pub async fn replace_identity(
        &self,
        identity: Arc<Identity>,
    ) -> Result<ReplaceIdentityOutcome, ReplaceIdentityError> {
        use replace_identity_error::PrepareSnafu;

        let mut config = self
            .state
            .config
            .write()
            .expect("endpoint config lock poisoned");
        let current = config
            .identity
            .as_ref()
            .ok_or(ReplaceIdentityError::MissingCurrentIdentity)?;
        if current.name != identity.name {
            return Err(ReplaceIdentityError::NameChanged {
                current: current.name.clone(),
                replacement: identity.name.clone(),
            });
        }
        if current.as_ref() == identity.as_ref() {
            return Ok(ReplaceIdentityOutcome::Unchanged);
        }
        let certified_key = identity::build_certified_key(&identity).context(PrepareSnafu)?;
        let credentials = Arc::new(ServerCredentials::new(identity.clone(), certified_key));
        let registration = self
            .state
            .server_registration
            .lock()
            .expect("server registration mutex poisoned");
        if let Some(registration) = registration.as_ref()
            && !registration.replace_credentials(current, credentials)
        {
            return Err(ReplaceIdentityError::StaleRegistration {
                name: registration.name().clone(),
            });
        }
        config.identity = Some(identity);
        self.state
            .client_runtime
            .lock()
            .expect("client runtime mutex poisoned")
            .take();
        Ok(ReplaceIdentityOutcome::Updated)
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
            state: Arc::new(EndpointState::new(identity, client, server)),
            resolver,
            bind,
            _binds: Arc::new(binds),
        };
        endpoint.init_client();
        endpoint.init_server().await;
        endpoint
    }
}

impl QuicEndpoint {
    fn ensure_client(&self) -> Result<Arc<ClientConfig>, BuildClientTlsError> {
        Ok(self.ensure_client_runtime()?.tls.clone())
    }

    fn ensure_client_runtime(&self) -> Result<Arc<ClientRuntime>, BuildClientTlsError> {
        let config = self
            .state
            .config
            .read()
            .expect("endpoint config lock poisoned");
        let mut cache = self
            .state
            .client_runtime
            .lock()
            .expect("client runtime mutex poisoned");
        if let Some(cached) = cache.as_ref() {
            return Ok(cached.clone());
        }

        let tls = Arc::new(Self::build_client_tls_from(
            &config.client,
            config.identity.as_deref(),
        )?);
        let runtime = Arc::new(ClientRuntime {
            identity: config.identity.clone(),
            client: config.client.clone(),
            tls,
        });
        *cache = Some(runtime.clone());
        Ok(runtime)
    }

    fn build_client_tls_from(
        client: &ClientQuicConfig,
        identity: Option<&Identity>,
    ) -> Result<ClientConfig, BuildClientTlsError> {
        use build_client_tls_error::{ClientAuthSnafu, VersionSnafu};

        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = ClientConfig::builder().crypto_provider().clone();
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13)
            .context(VersionSnafu)?;
        let builder = match &client.verifier {
            ServerCertVerifierChoice::Dangerous => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier)),
            ServerCertVerifierChoice::WebPki(v) => builder.with_webpki_verifier(v.clone()),
            ServerCertVerifierChoice::Custom(v) => builder
                .dangerous()
                .with_custom_certificate_verifier(v.clone()),
        };
        let mut tls = match identity {
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
    fn build_client_connection_from_runtime(
        &self,
        server_name: &str,
        runtime: &ClientRuntime,
    ) -> Result<Arc<Connection>, BuildClientTlsError> {
        use build_client_tls_error::SetParameterSnafu;

        let mut parameters = runtime.client.parameters.clone();
        if let Some(named) = runtime.identity.as_ref() {
            parameters
                .set(
                    crate::dquic::qbase::param::ParameterId::ClientName,
                    named.name.to_string(),
                )
                .context(SetParameterSnafu)?;
        }
        let builder =
            Connection::new_client(server_name.to_owned(), runtime.client.token_sink.clone())
                .with_parameters(parameters)
                .with_tls_config((*runtime.tls).clone())
                .with_streams_concurrency_strategy(runtime.client.stream_strategy_factory.as_ref())
                .with_zero_rtt(runtime.client.enable_0rtt);
        let connection = self
            .network
            .quic()
            .configure_connection(builder)
            .with_defer_idle_timeout(runtime.client.defer_idle_timeout)
            .with_heartbeat_interval(runtime.client.heartbeat_interval)
            .with_cids(ConnectionId::random_gen(8))
            .with_qlog(runtime.client.qlogger.clone())
            .run();
        Ok(connection)
    }
}

impl QuicEndpoint {
    async fn ensure_server(&self) -> Result<ServerBinding, AcceptError> {
        use accept_error::BindServerSnafu;

        loop {
            let (snapshot, identity) = {
                let config = self
                    .state
                    .config
                    .read()
                    .expect("endpoint config lock poisoned");
                let identity = config
                    .identity
                    .clone()
                    .ok_or(AcceptError::ServerUnavailable)?;
                let registration = self
                    .state
                    .server_registration
                    .lock()
                    .expect("server registration mutex poisoned");
                if let Some(binding) = registration.as_ref() {
                    return self
                        .network
                        .quic()
                        .reuse_owned_server_binding(
                            binding,
                            &self.state.server_owner,
                            &config.server,
                        )
                        .context(BindServerSnafu);
                }
                (config.clone(), identity)
            };

            let binding = self
                .network
                .quic()
                .bind_server_owned(
                    self.state.server_owner.clone(),
                    identity,
                    (*snapshot.server).clone(),
                    self.bind.clone(),
                )
                .await;

            let config = self
                .state
                .config
                .read()
                .expect("endpoint config lock poisoned");
            if !snapshot.same_server_state(&config) {
                continue;
            }
            let mut registration = self
                .state
                .server_registration
                .lock()
                .expect("server registration mutex poisoned");
            if let Some(existing) = registration.as_ref() {
                return self
                    .network
                    .quic()
                    .reuse_owned_server_binding(existing, &self.state.server_owner, &config.server)
                    .context(BindServerSnafu);
            }
            let binding = binding.context(BindServerSnafu)?;
            *registration = Some(binding.clone());
            return Ok(binding);
        }
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
        if self
            .state
            .config
            .read()
            .expect("endpoint config lock poisoned")
            .identity
            .is_some()
        {
            let _ = self.ensure_server().await;
        }
    }

    /// Accept an inbound connection, using the cached server binding.
    pub async fn accept(&self) -> Result<Arc<Connection>, AcceptError> {
        let binding = self.ensure_server().await?;
        let conn = binding.recv().await.ok_or(AcceptError::Shutdown)?;
        self.subscribe_connection_local_endpoints(conn.clone());
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

        let lookup_name = lookup_server_name(server);
        let transport_name = transport_server_name(server);

        tracing::debug!(
            logical_server = %server,
            lookup = %lookup_name,
            tls = transport_name,
            "connecting quic endpoint"
        );
        let runtime = self.ensure_client_runtime().context(TlsSnafu)?;
        let mut server_eps = futures::StreamExt::fuse(
            self.resolver
                .lookup(lookup_name, "", None)
                .await
                .context(DnsSnafu)?,
        );
        let connection = self
            .build_client_connection_from_runtime(transport_name, &runtime)
            .context(TlsSnafu)?;
        tracing::trace!(
            logical_server = %server,
            lookup = %lookup_name,
            tls = transport_name,
            timeout_ms = runtime
                .client
                .parameters
                .get::<Duration>(crate::dquic::qbase::param::ParameterId::MaxIdleTimeout)
                .filter(|timeout| !timeout.is_zero())
                .unwrap_or(Duration::from_secs(20))
                .as_millis(),
            bind_pattern_count = self.bind.len(),
            "waiting for quic path"
        );

        self.subscribe_connection_local_endpoints(connection.clone());

        let connect_timeout = tokio::time::sleep(
            runtime
                .client
                .parameters
                .get::<Duration>(crate::dquic::qbase::param::ParameterId::MaxIdleTimeout)
                .filter(|timeout| !timeout.is_zero())
                .unwrap_or(Duration::from_secs(20)),
        );
        tokio::pin!(connect_timeout);
        loop {
            tokio::select! {
                biased;
                _ = connection.terminated() => {
                    return Err(ConnectError::NoReachableEndpoint);
                }
                result = connection.handshaked() => {
                    result.map_err(|_| ConnectError::NoReachableEndpoint)?;
                    Self::spawn_peer_endpoint_companion(
                        connection.clone(),
                        server_eps,
                    );
                    tracing::debug!(server = %lookup_name, "quic endpoint handshaked");
                    return Ok(connection);
                }
                _ = &mut connect_timeout => {
                    connection
                        .validate()
                        .map_err(|_| ConnectError::NoReachableEndpoint)?;
                    Self::spawn_peer_endpoint_companion(
                        connection.clone(),
                        server_eps,
                    );
                    return Ok(connection);
                }
                Some((source, server_ep)) = server_eps.next() => {
                    tracing::trace!(
                        server = %lookup_name,
                        ?source,
                        endpoint = ?server_ep,
                        "resolved peer endpoint"
                    );
                    Self::add_resolved_peer_endpoint(
                        &connection,
                        source,
                        server_ep,
                    );
                    // Resolver streams often contain a batch of equivalent endpoints
                    // that are ready immediately. Install the ready batch before
                    // evaluating connection readiness.
                    Self::drain_ready_peer_endpoints(&connection, &mut server_eps);
                }
            }

            match connection.has_viable_path() {
                Ok(true) => {
                    Self::spawn_peer_endpoint_companion(connection.clone(), server_eps);
                    tracing::debug!(server = %lookup_name, "quic endpoint has at least one path");
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
        self.state
            .server_registration
            .lock()
            .expect("server registration mutex poisoned")
            .take();
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

impl QuicEndpoint {
    /// Obtain a mutable guard for the endpoint's identity.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting
    /// `Option<Arc<Identity>>`, so callers may inspect, mutate, set, or
    /// clear the identity. Dependent state is refreshed when a change is made.
    pub fn identity_mut(&mut self) -> IdentityMutGuard<'_> {
        let state = self.state.as_ref();
        let value = state
            .config
            .read()
            .expect("endpoint config lock poisoned")
            .identity
            .clone();
        IdentityMutGuard {
            state,
            original: value.clone(),
            value,
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
    /// When a changed guard is dropped, the cached client runtime is invalidated.
    pub fn client_config_mut(&mut self) -> ClientConfigMutGuard<'_> {
        let state = self.state.as_ref();
        let value = state
            .config
            .read()
            .expect("endpoint config lock poisoned")
            .client
            .clone();
        ClientConfigMutGuard {
            state,
            original: value.clone(),
            value,
        }
    }

    /// Obtain a mutable guard for the server configuration.
    ///
    /// The guard implements [`DerefMut`](std::ops::DerefMut) targeting
    /// [`ServerQuicConfig`], so callers can mutate fields directly.
    /// When a changed guard is dropped, the active server binding is unregistered.
    pub fn server_config_mut(&mut self) -> ServerConfigMutGuard<'_> {
        let state = self.state.as_ref();
        let value = state
            .config
            .read()
            .expect("endpoint config lock poisoned")
            .server
            .clone();
        ServerConfigMutGuard {
            state,
            original: value.clone(),
            value,
        }
    }
}

/// RAII guard for mutable access to [`QuicEndpoint`]'s identity.
///
/// On drop, commits a modified identity. A same-name identity updates an active
/// registration in place; clearing or renaming it drops that registration.
pub struct IdentityMutGuard<'a> {
    state: &'a EndpointState,
    original: Option<Arc<Identity>>,
    value: Option<Arc<Identity>>,
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
        if self.value.as_deref() == self.original.as_deref() {
            return;
        }

        let mut config = self
            .state
            .config
            .write()
            .expect("endpoint config lock poisoned");
        if self.value.as_deref() == config.identity.as_deref() {
            return;
        }
        let previous = config.identity.clone();
        let mut registration = self
            .state
            .server_registration
            .lock()
            .expect("server registration mutex poisoned");
        let can_reuse = match (
            registration.as_ref(),
            previous.as_ref(),
            self.value.as_ref(),
        ) {
            (Some(active), Some(previous), Some(identity))
                if active.name() == &identity.name && previous.name == identity.name =>
            {
                identity::build_certified_key(identity).is_ok_and(|certified_key| {
                    active.replace_credentials(
                        previous,
                        Arc::new(ServerCredentials::new(identity.clone(), certified_key)),
                    )
                })
            }
            _ => false,
        };
        if !can_reuse {
            registration.take();
        }
        config.identity = self.value.take();
        self.state
            .client_runtime
            .lock()
            .expect("client runtime mutex poisoned")
            .take();
    }
}

impl QuicEndpoint {
    fn subscribe_connection_local_endpoints(&self, connection: Arc<Connection>) {
        let mut subscriber = self.network.quic().local_endpoints().subscribe();
        let weak = Arc::downgrade(&connection);
        let bind = self.bind.clone();

        // Inherent termination: this task subscribes one h3x endpoint connection
        // to endpoint-selected local endpoint updates. It exits when the connection
        // drops, the connection terminates, or the subscriber channel is exhausted.
        tokio::spawn(
            async move {
                loop {
                    let Some(terminated) = weak.upgrade().map(|connection| connection.terminated())
                    else {
                        break;
                    };
                    tokio::select! {
                        biased;
                        _ = terminated => break,
                        update = subscriber.recv() => {
                            let Some((bind_uri, update)) = update else { break };
                            if !bind.iter().any(|pattern| pattern.matches(&bind_uri)) {
                                continue;
                            }
                            let Some(connection) = weak.upgrade() else {
                                break;
                            };
                            Self::handle_connection_local_endpoint_update(&connection, bind_uri, update);
                        }
                    }
                }
            }
            .in_current_span(),
        );
    }

    fn handle_connection_local_endpoint_update(
        connection: &Connection,
        bind_uri: crate::dquic::net::BindUri,
        update: crate::dquic::qinterface::component::local_endpoint::InterfaceEndpointUpdate,
    ) {
        let result = match update {
            crate::dquic::qinterface::component::local_endpoint::InterfaceEndpointUpdate::Upsert {
                key,
                endpoint,
            } => connection.upsert_local_endpoint(bind_uri, key, endpoint),
            crate::dquic::qinterface::component::local_endpoint::InterfaceEndpointUpdate::Remove {
                key,
            } => connection.remove_local_endpoint(&bind_uri, &key),
            crate::dquic::qinterface::component::local_endpoint::InterfaceEndpointUpdate::Close => {
                connection.close_local_endpoints(&bind_uri)
            }
        };

        if let Err(error) = result {
            tracing::trace!(
                error = %Report::from_error(&error),
                "failed to feed local endpoint update"
            );
        }
    }

    fn spawn_peer_endpoint_companion<S>(connection: Arc<Connection>, mut server_eps: S)
    where
        S: Stream<Item = (Source, EndpointAddr)> + Unpin + Send + 'static,
    {
        let weak = Arc::downgrade(&connection);
        // Inherent termination: this companion drains remaining DNS results
        // after connect has established that the connection will not leak. It
        // creates the terminated future from a temporary strong reference, then
        // drops that reference before awaiting DNS or close events. It exits
        // when (a) connection is dropped, (b) connection terminates, or (c)
        // the DNS stream is exhausted.
        tokio::spawn(
            async move {
                loop {
                    let Some(terminated) = weak.upgrade().map(|c| c.terminated()) else {
                        break;
                    };
                    tokio::select! {
                        biased;
                        _ = terminated => break,
                        result = server_eps.next() => {
                            let Some((s, e)) = result else {
                                break;
                            };
                            let Some(c) = weak.upgrade() else { break };
                            Self::add_resolved_peer_endpoint(&c, s, e);
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

    fn drain_ready_peer_endpoints<S>(connection: &Connection, server_eps: &mut S)
    where
        S: Stream<Item = (Source, EndpointAddr)> + Unpin,
    {
        while let Some(Some((source, server_ep))) = server_eps.next().now_or_never() {
            Self::add_resolved_peer_endpoint(connection, source, server_ep);
        }
    }
}

fn lookup_server_name(server: &http::uri::Authority) -> &str {
    let full = server.as_str();
    full.rsplit_once('@').map_or(full, |(_, host)| host)
}

fn transport_server_name(server: &http::uri::Authority) -> &str {
    server.host()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use dhttp_identity::identity::LocalAuthority as IdentityLocalAuthority;
    use http::uri::Authority;
    use rustls::{RootCertStore, client::WebPkiServerVerifier, pki_types::PrivateKeyDer};

    use super::*;
    use crate::{
        dquic::{
            cert::handy::{ToCertificate, ToPrivateKey},
            net::BindUri,
            qinterface::component::local_endpoint::{InterfaceEndpointKey, LocalEndpoints},
            resolver::handy::SystemResolver,
        },
        quic::WithLocalAuthority as _,
    };

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    #[test]
    fn authority_names_keep_selector_for_lookup_but_not_for_tls() {
        let authority: Authority = "alice@reimu.hakurei.dhttp.net:0".parse().unwrap();

        assert_eq!(lookup_server_name(&authority), "reimu.hakurei.dhttp.net:0");
        assert_eq!(transport_server_name(&authority), "reimu.hakurei.dhttp.net");
    }

    #[test]
    fn authority_names_without_port_remain_logical_names() {
        let authority: Authority = "reimu.hakurei.dhttp.net".parse().unwrap();

        assert_eq!(lookup_server_name(&authority), "reimu.hakurei.dhttp.net");
        assert_eq!(transport_server_name(&authority), "reimu.hakurei.dhttp.net");
    }

    #[test]
    fn authority_names_keep_real_transport_port_for_resolver_lookup() {
        let authority: Authority = "dns.genmeta.net:4433".parse().unwrap();

        assert_eq!(lookup_server_name(&authority), "dns.genmeta.net:4433");
        assert_eq!(transport_server_name(&authority), "dns.genmeta.net");
    }

    #[test]
    fn production_endpoint_does_not_inspect_or_create_paths() {
        let source = include_str!("endpoint.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module boundary");

        for forbidden in [
            ["path", "_context", "()"].concat(),
            ["add", "_path", "("].concat(),
            ["add", "_local", "_endpoint", "("].concat(),
            ["add", "_local", "_punch", "_address", "("].concat(),
            ["remove", "_address", "("].concat(),
            ["upsert", "_local", "_direct", "_endpoint", "("].concat(),
            ["upsert", "_local", "_stun", "_endpoint", "("].concat(),
            ["close", "_local", "_bind", "_uri", "("].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "h3x QuicEndpoint must not inspect or create dquic paths: {forbidden}"
            );
        }
    }

    #[test]
    fn production_endpoint_owns_local_endpoint_event_parsing() {
        let source = include_str!("endpoint.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module boundary");

        assert!(
            !production.contains(&["subscribe", "_local", "_endpoints"].concat()),
            "QuicEndpoint must not delegate local endpoint subscription into Connection"
        );
        assert!(
            production.contains("handle_connection_local_endpoint_update"),
            "QuicEndpoint should parse typed local endpoint updates and call Connection ingest APIs"
        );
        assert!(!production.contains(&["Local", "Endpoint", "Set"].concat()));
        assert!(!production.contains(&["Address", "Event"].concat()));
    }

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
    async fn test_network_local_endpoints_accessor() {
        // Verify that the built-in QUIC local endpoints accessor is available.
        let network = Network::builder().build();
        let _local_endpoints = network.quic().local_endpoints();
        // Just verify we can access it without panicking
    }

    #[tokio::test]
    async fn test_connection_owned_local_endpoint_structure() {
        // Verify that endpoint construction exposes the infrastructure needed
        // for connection-owned local endpoint subscription.
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
    }

    #[tokio::test]
    async fn connection_address_book_pairs_replayed_local_endpoint_with_later_peer_endpoint() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind = Arc::new(vec![bind_pattern.clone()]);
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(bind.clone())
            .build()
            .await;
        let connection = build_test_connection(&endpoint, "remote.test");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        endpoint.subscribe_connection_local_endpoints(connection.clone());

        let remote_addr = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote_addr),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if connection.has_viable_path().expect("connection path state") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("local endpoint replayed before DNS peer must be retained for peer pairing");
    }

    #[tokio::test]
    async fn loopback_to_non_loopback_direct_path_is_not_connect_ready() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind_endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let connection = build_test_connection(&bind_endpoint, "server.example");
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
        connection
            .upsert_local_endpoint(
                bind_uri,
                InterfaceEndpointKey::Direct,
                EndpointAddr::direct(local_addr),
            )
            .expect("local endpoint");

        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::direct("10.10.0.100:47388".parse().expect("remote addr")),
        );

        assert!(
            !connection.has_viable_path().expect("connection path state"),
            "loopback-to-non-loopback direct paths are not ready for client handshake"
        );
    }

    #[tokio::test]
    async fn peer_agent_endpoint_does_not_gate_direct_path_readiness() {
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let connection = build_test_connection(&endpoint, "server.example");
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

        connection
            .upsert_local_endpoint(
                bind_uri.clone(),
                InterfaceEndpointKey::Direct,
                EndpointAddr::direct(local_addr),
            )
            .expect("local endpoint");
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::mediate(stun_agent, "10.10.0.40:20000".parse().expect("outer addr")),
        );
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::H3 {
                server: Arc::from("https://dns.genmeta.net:4433"),
            },
            EndpointAddr::direct(remote_direct),
        );

        assert!(
            connection.has_viable_path().expect("connection path state"),
            "direct loopback path is connect-ready independently of peer Agent endpoints"
        );
        assert!(
            connection.has_viable_path().expect("connection path state"),
            "peer Agent endpoints must not make h3x wait for a local Agent endpoint"
        );
    }

    #[tokio::test]
    async fn connection_local_endpoint_subscription_applies_bind_filter() {
        let local_endpoints = Arc::new(LocalEndpoints::new());
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("bind pattern");
        let endpoint = QuicEndpoint::builder()
            .network(
                Network::builder()
                    .local_endpoints(local_endpoints.clone())
                    .build(),
            )
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let connection = build_test_connection(&endpoint, "server.example");
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");
        use crate::dquic::net::IO as _;
        let allowed_bind = iface.bind_uri();
        let allowed_local = iface.borrow().bound_addr().expect("allowed local");
        let rejected_bind: BindUri = "inet://127.0.0.1:40001".parse().expect("rejected bind");

        let allowed_publishers = local_endpoints.publisher(allowed_bind.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;
        endpoint.subscribe_connection_local_endpoints(connection.clone());

        let rejected_local: SocketAddr = "127.0.0.1:41001".parse().expect("rejected local");
        let remote: SocketAddr = "127.0.0.1:41002".parse().expect("remote");
        let rejected_publishers = local_endpoints.publisher(rejected_bind);
        let mut rejected_direct = rejected_publishers
            .direct_endpoint_publisher()
            .expect("rejected direct publisher");
        assert!(rejected_direct.upsert(rejected_local));
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !connection.has_viable_path().expect("connection path state"),
            "local endpoint events rejected by the endpoint bind filter must not reach the connection address book"
        );

        let mut allowed_direct = allowed_publishers
            .direct_endpoint_publisher()
            .expect("allowed direct publisher");
        assert!(allowed_direct.upsert(allowed_local));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if connection.has_viable_path().expect("connection path state") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("allowed local endpoint should pair with the retained peer endpoint");
    }

    #[tokio::test]
    async fn peer_agent_endpoint_does_not_create_local_stun_client() {
        #[derive(Debug)]
        struct SingleEndpointResolver(EndpointAddr);

        impl std::fmt::Display for SingleEndpointResolver {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("single endpoint resolver")
            }
        }

        impl Resolve for SingleEndpointResolver {
            fn lookup<'a>(
                &'a self,
                _hostname: &'a str,
                _servname: &'a str,
                _family: Option<crate::dquic::qresolve::Family>,
            ) -> crate::dquic::resolver::ResolveFuture<'a> {
                let endpoint = self.0;
                async move { Ok(futures::stream::iter([(Source::System, endpoint)]).boxed()) }
                    .boxed()
            }
        }

        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let mut client = ClientQuicConfig::default();
        client
            .parameters
            .set(
                crate::dquic::qbase::param::ParameterId::MaxIdleTimeout,
                Duration::from_millis(50),
            )
            .expect("max idle timeout parameter");
        let mut endpoint = QuicEndpoint::builder()
            .network(
                Network::builder()
                    .stun_server(Arc::from("127.0.0.1:9"))
                    .build(),
            )
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .client(client)
            .build()
            .await;
        let iface = endpoint
            .network()
            .quic()
            .get_interfaces(&bind_pattern)
            .expect("registered bind")
            .into_iter()
            .next()
            .expect("bound interface");

        use crate::dquic::net::IO as _;
        let local_addr = iface.borrow().bound_addr().expect("bound address");
        let stun_agent = SocketAddr::new(local_addr.ip(), local_addr.port() + 1);
        let has_agent_client = || {
            iface
                .borrow()
                .with_component(
                    |component: &crate::dquic::qtraversal::nat::client::StunClientComponent| {
                        component.with_client(|client| {
                            client.is_some_and(|client| client.agent_addr() == stun_agent)
                        })
                    },
                )
                .expect("interface was not rebound")
                .expect("stun clients component")
        };

        assert!(!has_agent_client());

        endpoint.set_resolver(Arc::new(SingleEndpointResolver(EndpointAddr::mediate(
            stun_agent, local_addr,
        ))));
        let authority: Authority = "server.example".parse().expect("authority");

        let result = quic::Connect::connect(&endpoint, &authority).await;

        assert!(matches!(result, Err(ConnectError::NoReachableEndpoint)));
        assert!(!has_agent_client());
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
            .ensure_client_runtime()
            .expect("webpki verifier client tls");

        {
            let mut client = endpoint.client_config_mut();
            client.verifier =
                ServerCertVerifierChoice::Custom(Arc::new(DangerousServerCertVerifier));
        }
        {
            let mut identity = endpoint.identity_mut();
            *identity = Some(Arc::new(make_tls_identity("client-name.test", None)));
        }
        let runtime = endpoint
            .ensure_client_runtime()
            .expect("custom verifier client runtime");
        endpoint
            .build_client_connection_from_runtime("server.example", &runtime)
            .expect("client connection with identity parameter");

        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind_endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .bind(Arc::new(vec![bind_pattern.clone()]))
            .build()
            .await;
        let connection = build_test_connection(&bind_endpoint, "server.example");
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
        connection
            .upsert_local_endpoint(
                bind_uri,
                InterfaceEndpointKey::Direct,
                EndpointAddr::direct(local_addr),
            )
            .expect("local endpoint");

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
            connection.has_viable_path().expect("connection path state"),
            "ready peer endpoints should pair with the retained local endpoint"
        );
    }

    #[tokio::test]
    async fn connection_local_endpoint_removal_does_not_remove_existing_path() {
        let local_endpoints = Arc::new(LocalEndpoints::new());
        let bind_pattern = BindPattern::from_str("inet://127.0.0.1:0").expect("valid bind pattern");
        let bind = Arc::new(vec![bind_pattern.clone()]);
        let endpoint = QuicEndpoint::builder()
            .network(
                Network::builder()
                    .local_endpoints(local_endpoints.clone())
                    .build(),
            )
            .bind(bind.clone())
            .build()
            .await;
        let connection = build_test_connection(&endpoint, "remote.test");
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
        let publishers = local_endpoints.publisher(bind_uri.clone());
        let mut direct = publishers
            .direct_endpoint_publisher()
            .expect("direct publisher");
        assert!(direct.upsert(local_addr));

        endpoint.subscribe_connection_local_endpoints(connection.clone());
        QuicEndpoint::add_resolved_peer_endpoint(
            &connection,
            Source::System,
            EndpointAddr::direct(remote_addr),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if connection.has_viable_path().expect("connection path state") {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("direct local endpoint should pair with direct remote endpoint");

        assert!(direct.remove());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            connection.has_viable_path().expect("connection path state"),
            "removing a local endpoint must not directly delete an existing path"
        );
    }

    #[tokio::test]
    async fn peer_endpoint_companion_does_not_hold_connection_while_waiting_for_dns() {
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .build()
            .await;
        let connection = build_test_connection(&endpoint, "remote.test");
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let mut polled_tx = Some(polled_tx);
        let server_eps = futures::stream::poll_fn(move |_cx| {
            if let Some(tx) = polled_tx.take() {
                let _ = tx.send(());
            }
            std::task::Poll::Pending
        });

        QuicEndpoint::spawn_peer_endpoint_companion(connection.clone(), server_eps);

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

    fn make_identity(name: &str) -> Identity {
        Identity {
            name: name.parse().unwrap(),
            certs: Arc::new(vec![]),
            key: Arc::new(PrivateKeyDer::Pkcs8(b"dummy-key-data".to_vec().into())),
            ocsp: Arc::new(None),
        }
    }

    fn make_tls_identity(name: &str, ocsp: Option<Vec<u8>>) -> Identity {
        use crate::dquic::cert::handy::{ToCertificate, ToPrivateKey};

        Identity {
            name: name.parse().unwrap(),
            certs: Arc::new(SERVER_CERT.to_certificate()),
            key: Arc::new(SERVER_KEY.to_private_key()),
            ocsp: Arc::new(ocsp),
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

    fn build_test_connection(endpoint: &QuicEndpoint, server_name: &str) -> Arc<Connection> {
        let runtime = endpoint
            .ensure_client_runtime()
            .expect("client runtime should build");
        endpoint
            .build_client_connection_from_runtime(server_name, &runtime)
            .expect("client connection should build")
    }

    #[tokio::test]
    async fn public_new_uses_default_anonymous_endpoint_shape() {
        let endpoint = QuicEndpoint::new().await;

        assert!(endpoint.identity().is_none());
        assert_eq!(endpoint.bind_patterns().len(), 1);
        assert_eq!(endpoint.bind_patterns()[0].to_string(), "iface://*");
        assert!(endpoint.state.client_runtime.lock().unwrap().is_some());
        assert!(endpoint.state.server_registration.lock().unwrap().is_none());
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
    async fn ensure_client_cache_is_shared_by_clones() {
        let endpoint = make_endpoint().await;

        let first = endpoint.ensure_client().expect("client tls should build");
        let second = endpoint
            .ensure_client()
            .expect("client tls should be cached");
        assert!(Arc::ptr_eq(&first, &second));

        let cloned = endpoint.clone();
        assert!(Arc::ptr_eq(
            &first,
            &cloned
                .ensure_client()
                .expect("clone should reuse client tls")
        ));
    }

    #[tokio::test]
    async fn client_runtime_snapshot_keeps_identity_and_config_coherent() {
        let mut endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("localhost", None)))
            .resolver(Arc::new(SystemResolver))
            .build()
            .await;
        let initial = endpoint
            .ensure_client_runtime()
            .expect("initial client runtime should build");
        assert!(!initial.client.enable_0rtt);
        assert_eq!(initial.identity.as_ref().unwrap().ocsp.as_deref(), None);

        {
            let mut client = endpoint.client_config_mut();
            client.enable_0rtt = true;
        }
        {
            let mut identity = endpoint.identity_mut();
            *identity = Some(Arc::new(make_tls_identity(
                "localhost",
                Some(vec![7, 8, 9]),
            )));
        }

        assert!(!initial.client.enable_0rtt);
        assert_eq!(initial.identity.as_ref().unwrap().ocsp.as_deref(), None);
        let current = endpoint
            .ensure_client_runtime()
            .expect("updated client runtime should build");
        assert!(current.client.enable_0rtt);
        assert_eq!(
            current.identity.as_ref().unwrap().ocsp.as_deref(),
            Some(&[7, 8, 9][..])
        );
        assert!(!Arc::ptr_eq(&initial, &current));
    }

    #[tokio::test]
    async fn replace_identity_updates_shared_binding_in_place() {
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("localhost", None)))
            .resolver(Arc::new(SystemResolver))
            .build()
            .await;
        let cloned = endpoint.clone();
        let binding = endpoint
            .state
            .server_registration
            .lock()
            .unwrap()
            .clone()
            .expect("named endpoint should be registered");
        let entry = binding.entry.clone();
        let old_client_tls = endpoint
            .ensure_client()
            .expect("initial client TLS should be cached");

        let outcome = cloned
            .replace_identity(Arc::new(make_tls_identity(
                "localhost",
                Some(vec![1, 2, 3]),
            )))
            .await
            .expect("same-name identity should replace");

        assert_eq!(outcome, ReplaceIdentityOutcome::Updated);
        assert_eq!(
            endpoint.identity().unwrap().ocsp.as_deref(),
            Some(&[1, 2, 3][..])
        );
        assert!(Arc::ptr_eq(
            &entry,
            &endpoint
                .state
                .server_registration
                .lock()
                .unwrap()
                .clone()
                .unwrap()
                .entry
        ));
        assert_eq!(
            entry.credentials.load_full().certified_key.ocsp.as_deref(),
            Some(&[1, 2, 3][..])
        );
        let new_client_tls = endpoint
            .ensure_client()
            .expect("replacement client TLS should rebuild");
        assert!(!Arc::ptr_eq(&old_client_tls, &new_client_tls));
        assert!(Arc::ptr_eq(
            &new_client_tls,
            &cloned
                .ensure_client()
                .expect("clone shares rebuilt client TLS")
        ));
    }

    #[tokio::test]
    async fn independent_endpoints_cannot_share_an_sni_by_reusing_an_identity_arc() {
        let network = Network::builder().build();
        let identity = Arc::new(make_tls_identity("localhost", None));
        let server = ServerQuicConfig::default();
        let first = QuicEndpoint::builder()
            .network(network.clone())
            .identity(identity.clone())
            .resolver(Arc::new(SystemResolver))
            .server(server.clone())
            .build()
            .await;
        let second = QuicEndpoint::builder()
            .network(network)
            .identity(identity)
            .resolver(Arc::new(SystemResolver))
            .server(server)
            .build()
            .await;
        let old_second_identity = second.identity().unwrap();
        let old_second_client_tls = second.ensure_client().expect("client TLS should be cached");
        assert!(first.state.server_registration.lock().unwrap().is_some());
        assert!(second.state.server_registration.lock().unwrap().is_none());
        assert!(matches!(
            second.ensure_server().await,
            Err(AcceptError::BindServer {
                source: BindServerError::SniInUse { .. }
            })
        ));

        first
            .replace_identity(Arc::new(make_tls_identity(
                "localhost",
                Some(vec![1, 2, 3]),
            )))
            .await
            .expect("first owner should replace the shared identity");

        assert!(Arc::ptr_eq(
            &second.identity().unwrap(),
            &old_second_identity
        ));
        let new_second_client_tls = second
            .ensure_client()
            .expect("the second owner's client TLS should remain cached");
        assert!(Arc::ptr_eq(&old_second_client_tls, &new_second_client_tls));
    }

    #[tokio::test]
    async fn replace_identity_rejects_name_change_without_mutation() {
        let endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("localhost", None)))
            .resolver(Arc::new(SystemResolver))
            .build()
            .await;

        let error = endpoint
            .replace_identity(Arc::new(make_tls_identity("other.test", None)))
            .await
            .expect_err("replacement must keep the registered SNI");

        assert!(matches!(error, ReplaceIdentityError::NameChanged { .. }));
        assert_eq!(endpoint.identity().unwrap().name.as_str(), "localhost");
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
            .ensure_client_runtime()
            .expect("client runtime should build")
            .tls
            .clone();

        assert_eq!(
            tls.alpn_protocols,
            endpoint.state.config.read().unwrap().client.alpns
        );
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
    async fn identity_guard_deref_commits_the_new_identity() {
        let mut endpoint = make_endpoint().await;

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
    }

    #[tokio::test]
    async fn test_client_config_mut() {
        let mut endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("client-config.test", None)))
            .build()
            .await;
        let server_entry = endpoint
            .state
            .server_registration
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .entry
            .clone();
        assert!(!endpoint.state.config.read().unwrap().client.enable_0rtt);

        {
            let mut guard = endpoint.client_config_mut();
            guard.enable_0rtt = true;
        } // guard dropped → cache invalidated

        assert!(endpoint.state.config.read().unwrap().client.enable_0rtt);
        assert!(endpoint.state.client_runtime.lock().unwrap().is_none());
        assert!(Arc::ptr_eq(
            &server_entry,
            &endpoint
                .state
                .server_registration
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .entry
        ));
    }

    #[tokio::test]
    async fn unmodified_client_config_guard_keeps_cached_runtime() {
        let mut endpoint = make_endpoint().await;
        // Pre-fill the cache by triggering ensure_client
        let _ = endpoint.ensure_client().is_ok();
        assert!(endpoint.state.client_runtime.lock().unwrap().is_some());

        {
            let _guard = endpoint.client_config_mut();
            // Reading through the guard is not a configuration change.
        }

        assert!(endpoint.state.client_runtime.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn test_server_config_mut() {
        let mut endpoint = make_endpoint().await;
        assert!(!endpoint.state.config.read().unwrap().server.anti_port_scan);

        {
            let mut guard = endpoint.server_config_mut();
            guard.anti_port_scan = true;
        }

        assert!(endpoint.state.config.read().unwrap().server.anti_port_scan);
    }

    #[tokio::test]
    async fn changed_server_config_drops_the_registration() {
        let mut endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("server-config.test", None)))
            .build()
            .await;
        assert!(endpoint.state.server_registration.lock().unwrap().is_some());
        let client_runtime = endpoint
            .state
            .client_runtime
            .lock()
            .unwrap()
            .clone()
            .unwrap();

        {
            let mut guard = endpoint.server_config_mut();
            guard.anti_port_scan = true;
        }

        assert!(endpoint.state.server_registration.lock().unwrap().is_none());
        assert!(Arc::ptr_eq(
            &client_runtime,
            endpoint
                .state
                .client_runtime
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
        ));
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
    async fn detached_guards_commit_only_their_own_config_field() {
        let mut endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("guard-fields.test", None)))
            .build()
            .await;
        let mut cloned = endpoint.clone();
        let mut identity = endpoint.identity_mut();
        let mut client = cloned.client_config_mut();

        *identity = Some(Arc::new(make_tls_identity(
            "guard-fields.test",
            Some(vec![1, 2, 3]),
        )));
        client.enable_0rtt = true;
        drop(identity);
        drop(client);

        assert_eq!(
            endpoint.identity().unwrap().ocsp.as_deref(),
            Some(&[1, 2, 3][..])
        );
        assert!(endpoint.state.config.read().unwrap().client.enable_0rtt);
    }

    #[tokio::test]
    async fn identity_guard_last_commit_wins_in_config_and_registration() {
        let mut endpoint = QuicEndpoint::builder()
            .network(Network::builder().build())
            .identity(Arc::new(make_tls_identity("guard-order.test", None)))
            .build()
            .await;
        let mut cloned = endpoint.clone();
        let mut first = endpoint.identity_mut();
        let mut second = cloned.identity_mut();

        *first = Some(Arc::new(make_tls_identity(
            "guard-order.test",
            Some(vec![1]),
        )));
        *second = Some(Arc::new(make_tls_identity(
            "guard-order.test",
            Some(vec![2]),
        )));
        drop(first);
        drop(second);

        assert_eq!(endpoint.identity().unwrap().ocsp.as_deref(), Some(&[2][..]));
        let credentials = endpoint
            .state
            .server_registration
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .entry
            .credentials
            .load_full();
        assert_eq!(credentials.identity.ocsp.as_deref(), Some(&[2][..]));
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
}
