//! QUIC-only endpoint built directly on the [`qconnection`](crate::dquic::qconnection)
//! builder API.
//!
//! [`QuicEndpoint`] pairs a shared [`Network`] with a TLS [`Identity`] and
//! role-specific QUIC configuration. Each call to [`connect`](Self::connect)
//! constructs a fresh [`Connection`] through the qconnection builder; for
//! inbound traffic the endpoint installs a per-router connectionless
//! dispatcher on first call to [`accept`](Self::accept).
//!
//! No `QuicClient` / `QuicListeners` instance is held internally — those types
//! are deliberately not used so endpoint state is not coupled to a single
//! pre-baked client/listener instance. TLS configurations are cached in
//! [`OnceLock`](std::sync::OnceLock) so each endpoint builds them at most once.

use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use futures::StreamExt;
use rustls::{
    ClientConfig, ServerConfig, pki_types::PrivateKeyDer, server::ResolvesServerCert,
    sign::CertifiedKey,
};
use snafu::{ResultExt, Snafu};
use tokio::sync::mpsc::{self, Receiver};

use super::{
    config::{ClientQuicConfig, ServerCertVerifierChoice, ServerQuicConfig},
    identity::Identity,
    network::Network,
};
use crate::{
    dquic::{
        prelude::{Connection, Resolve},
        qbase::{
            cid::ConnectionId,
            net::{
                Family,
                addr::{AddrKind, BoundAddr, EndpointAddr, SocketEndpointAddr},
                route::{Link, Pathway},
            },
            packet::{DataHeader, GetDcid, Packet, long::DataHeader as LongHeader},
        },
        qinterface::{bind_uri::BindUri, component::route::Way, io::IO},
        qresolve::Source,
    },
    quic,
    util::tls::DangerousServerCertVerifier,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error building the client-side TLS configuration.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BuildClientTlsError {
    /// rustls failed to choose a supported protocol version.
    #[snafu(display("failed to select TLS protocol version"))]
    Version { source: rustls::Error },
    /// rustls refused the provided client certificate / key.
    #[snafu(display("failed to load client authentication certificate"))]
    ClientAuth { source: rustls::Error },
}

/// Error building the server-side TLS configuration.
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum BuildServerTlsError {
    /// The endpoint identity is anonymous and cannot serve TLS.
    #[snafu(display("cannot build server TLS with an anonymous identity"))]
    Anonymous,
    /// rustls failed to choose a supported protocol version.
    #[snafu(display("failed to select TLS protocol version"))]
    Version { source: rustls::Error },
    /// Loading the private key material failed.
    #[snafu(display("failed to load server private key"))]
    LoadKey { source: rustls::Error },
}

/// Error returned by [`QuicEndpoint::connect`](quic::Connect::connect).
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum ConnectError {
    /// Failed to build the client TLS configuration.
    #[snafu(display("failed to build client TLS config"))]
    Tls { source: BuildClientTlsError },
    /// DNS resolution failed.
    #[snafu(display("dns lookup failed"))]
    Dns { source: std::io::Error },
    /// The resolver produced no reachable endpoint.
    #[snafu(display("no reachable endpoint found for server"))]
    NoReachableEndpoint,
    /// Failed to acquire a local interface for the discovered endpoint.
    #[snafu(display("failed to bind local interface"))]
    BindInterface { source: std::io::Error },
}

/// Error returned by [`QuicEndpoint::accept`](quic::Listen::accept).
#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum AcceptError {
    /// Failed to build the server TLS configuration.
    #[snafu(display("failed to build server TLS config"))]
    Tls { source: BuildServerTlsError },
    /// Another endpoint already owns the connectionless dispatcher of this
    /// network's QUIC router.
    #[snafu(display("connectionless dispatcher already installed on this network"))]
    DispatcherInUse,
    /// The endpoint has been shut down.
    #[snafu(display("endpoint has been shut down"))]
    Shutdown,
}

/// Back-compat alias — kept so public re-exports from `endpoint::mod` remain
/// stable. Prefer [`ConnectError`] or [`AcceptError`] in new code.
pub type EndpointError = ConnectError;

// ---------------------------------------------------------------------------
// QuicEndpoint
// ---------------------------------------------------------------------------

/// A QUIC-only endpoint.
#[derive(Clone)]
pub struct QuicEndpoint {
    /// Shared network infrastructure.
    pub network: Arc<Network>,
    /// TLS identity for this endpoint.
    pub identity: Identity,
    /// Resolver used when establishing outbound connections.
    pub resolver: Arc<dyn Resolve + Send + Sync>,
    /// Client-side configuration.
    pub client: ClientQuicConfig,
    /// Server-side configuration.
    pub server: ServerQuicConfig,
    /// Cached TLS configurations and server state.
    inner: Arc<QuicEndpointInner>,
}

struct QuicEndpointInner {
    client_tls: OnceLock<Arc<ClientConfig>>,
    server_tls: OnceLock<Arc<ServerConfig>>,
    server_state: ServerState,
}

struct ServerState {
    accept_rx: Mutex<Option<Receiver<Arc<Connection>>>>,
    installed: AtomicBool,
    tx_keepalive: Mutex<Option<mpsc::Sender<Arc<Connection>>>>,
}

impl QuicEndpoint {
    /// Construct a new endpoint.
    #[must_use]
    pub fn new(
        network: Arc<Network>,
        identity: Identity,
        resolver: Arc<dyn Resolve + Send + Sync>,
        client: ClientQuicConfig,
        server: ServerQuicConfig,
    ) -> Self {
        Self {
            network,
            identity,
            resolver,
            client,
            server,
            inner: Arc::new(QuicEndpointInner {
                client_tls: OnceLock::new(),
                server_tls: OnceLock::new(),
                server_state: ServerState {
                    accept_rx: Mutex::new(None),
                    installed: AtomicBool::new(false),
                    tx_keepalive: Mutex::new(None),
                },
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS construction (cached in OnceLock)
// ---------------------------------------------------------------------------

impl QuicEndpoint {
    fn client_tls(&self) -> Result<Arc<ClientConfig>, BuildClientTlsError> {
        if let Some(cfg) = self.inner.client_tls.get() {
            return Ok(cfg.clone());
        }
        let cfg = self.build_client_tls()?;
        let cfg = Arc::new(cfg);
        // First writer wins; other threads get the same Arc back.
        let stored = self.inner.client_tls.get_or_init(|| cfg.clone()).clone();
        Ok(stored)
    }

    fn server_tls(&self) -> Result<Arc<ServerConfig>, BuildServerTlsError> {
        if let Some(cfg) = self.inner.server_tls.get() {
            return Ok(cfg.clone());
        }
        let cfg = self.build_server_tls()?;
        let cfg = Arc::new(cfg);
        let stored = self.inner.server_tls.get_or_init(|| cfg.clone()).clone();
        Ok(stored)
    }

    fn build_client_tls(&self) -> Result<ClientConfig, BuildClientTlsError> {
        use build_client_tls_error::{ClientAuthSnafu, VersionSnafu};

        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = ClientConfig::builder().crypto_provider().clone();
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(TLS13)
            .context(VersionSnafu)?;
        let builder = match &self.client.own.verifier {
            ServerCertVerifierChoice::Dangerous => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(DangerousServerCertVerifier)),
            ServerCertVerifierChoice::WebPki(v) => builder.with_webpki_verifier(v.clone()),
            ServerCertVerifierChoice::Custom(v) => builder
                .dangerous()
                .with_custom_certificate_verifier(v.clone()),
        };
        let mut tls = match &self.identity {
            Identity::Anonymous => builder.with_no_client_auth(),
            Identity::Named(id) => builder
                .with_client_auth_cert(id.certs.clone(), clone_key(&id.key))
                .context(ClientAuthSnafu)?,
        };
        tls.alpn_protocols.clone_from(&self.client.own.alpns);
        tls.enable_early_data = self.client.common.enable_0rtt;
        Ok(tls)
    }

    fn build_server_tls(&self) -> Result<ServerConfig, BuildServerTlsError> {
        use build_server_tls_error::{LoadKeySnafu, VersionSnafu};

        let named = match &self.identity {
            Identity::Anonymous => return Err(BuildServerTlsError::Anonymous),
            Identity::Named(id) => id.clone(),
        };
        const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
        let provider = ServerConfig::builder().crypto_provider().clone();
        let builder = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(TLS13)
            .context(VersionSnafu)?;

        let key = provider
            .key_provider
            .load_private_key(clone_key(&named.key))
            .context(LoadKeySnafu)?;
        let certified_key = Arc::new(CertifiedKey {
            cert: named.certs.clone(),
            key,
            ocsp: None,
        });
        let resolver = Arc::new(SingleSniResolver {
            name: named.name.clone(),
            key: certified_key,
        });

        let mut tls = builder
            .with_client_cert_verifier(self.server.own.client_cert_verifier.clone())
            .with_cert_resolver(resolver);
        tls.alpn_protocols.clone_from(&self.server.own.alpns);
        if self.server.common.enable_0rtt {
            tls.max_early_data_size = 0xffff_ffff;
        }
        Ok(tls)
    }
}

// ---------------------------------------------------------------------------
// Client-side construction
// ---------------------------------------------------------------------------

impl QuicEndpoint {
    fn build_client_connection(
        &self,
        server_name: &str,
        tls: Arc<ClientConfig>,
    ) -> Arc<Connection> {
        Connection::new_client(server_name.to_owned(), self.client.own.token_sink.clone())
            .with_parameters(self.client.own.parameters.clone())
            .with_tls_config((*tls).clone())
            .with_streams_concurrency_strategy(self.client.common.stream_strategy_factory.as_ref())
            .with_zero_rtt(self.client.common.enable_0rtt)
            .with_iface_factory(self.network.io_factory().clone())
            .with_iface_manager(self.network.iface_manager().clone())
            .with_quic_router(self.network.quic_router().clone())
            .with_locations(self.network.locations().clone())
            .with_defer_idle_timeout(self.client.common.defer_idle_timeout)
            .with_cids(ConnectionId::random_gen(8))
            .with_qlog(self.client.common.qlogger.clone())
            .run()
    }

    /// Register a peer endpoint on the connection and (for direct endpoints)
    /// bind a matching local interface and attach a path.
    ///
    /// Returns `true` when at least one direct [`Path`](crate::dquic::qconnection::path::Path)
    /// was added. Agent endpoints return `false` — the puncher adds paths
    /// asynchronously after STUN discovery.
    async fn setup_server_endpoint(
        &self,
        connection: &Connection,
        source: Source,
        server_ep: EndpointAddr,
    ) -> Result<bool, ConnectError> {
        use connect_error::BindInterfaceSnafu;

        let _ = connection.add_peer_endpoint(server_ep, source.clone());

        let bind_uri = bind_uri_for(&source, &server_ep);
        let iface = self.network.bind(bind_uri).await;

        if matches!(
            server_ep,
            EndpointAddr::Socket(SocketEndpointAddr::Agent { .. })
        ) {
            return Ok(false);
        }

        let interface = iface.borrow();
        let bound_addr = interface.bound_addr().context(BindInterfaceSnafu)?;
        if bound_addr.kind() != server_ep.addr_kind() {
            return Ok(false);
        }
        let dst = match server_ep {
            EndpointAddr::Socket(s) => BoundAddr::Internet(*s),
            EndpointAddr::Ble(_) => return Ok(false),
        };
        let link = Link::new(bound_addr, dst);
        let pathway = Pathway::new(bound_addr.into(), server_ep);
        let _ = connection.add_path(iface.bind_uri(), link, pathway);
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Server-side: connectionless dispatcher
// ---------------------------------------------------------------------------

impl QuicEndpoint {
    fn ensure_server_dispatcher(&self) -> Result<(), AcceptError> {
        use accept_error::TlsSnafu;

        if self.inner.server_state.installed.load(Ordering::Acquire) {
            return Ok(());
        }

        let tls = self.server_tls().context(TlsSnafu)?;
        let backlog = self.server.own.backlog.max(1);
        let (tx, rx) = mpsc::channel(backlog);

        *self.inner.server_state.accept_rx.lock().unwrap() = Some(rx);
        *self.inner.server_state.tx_keepalive.lock().unwrap() = Some(tx.clone());

        let endpoint = self.clone();
        let installed =
            self.network
                .quic_router()
                .on_connectless_packets(move |packet: Packet, way: Way| {
                    endpoint.dispatch_initial_packet(packet, way, tls.clone(), tx.clone());
                });
        if !installed {
            *self.inner.server_state.accept_rx.lock().unwrap() = None;
            *self.inner.server_state.tx_keepalive.lock().unwrap() = None;
            return Err(AcceptError::DispatcherInUse);
        }
        self.inner
            .server_state
            .installed
            .store(true, Ordering::Release);
        Ok(())
    }

    /// Handle a connectionless packet hot-path callback: extract the origin
    /// DCID and spawn an async task that builds the connection, delivers the
    /// initial packet, and publishes the accepted connection.
    ///
    /// All heavy work (TLS clone, Connection construction, deliver, server
    /// name wait) happens inside [`tokio::spawn`] so the router callback
    /// returns immediately.
    fn dispatch_initial_packet(
        &self,
        packet: Packet,
        way: Way,
        tls: Arc<ServerConfig>,
        tx: mpsc::Sender<Arc<Connection>>,
    ) {
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

        let endpoint = self.clone();
        tokio::spawn(async move {
            // `Connection::run()` registers the DCID with the QUIC router
            // *synchronously* before returning, so the subsequent `deliver`
            // is guaranteed to route this very packet to the new connection
            // rather than re-entering the connectionless dispatcher.
            let connection = Connection::new_server(endpoint.server.own.token_provider.clone())
                .with_parameters(endpoint.server.own.parameters.clone())
                .with_client_auther(Box::new(endpoint.server.own.client_auther.clone()))
                .with_tls_config((*tls).clone())
                .with_streams_concurrency_strategy(
                    endpoint.server.common.stream_strategy_factory.as_ref(),
                )
                .with_zero_rtt(tls.max_early_data_size == 0xffff_ffff)
                .with_iface_factory(endpoint.network.io_factory().clone())
                .with_iface_manager(endpoint.network.iface_manager().clone())
                .with_quic_router(endpoint.network.quic_router().clone())
                .with_locations(endpoint.network.locations().clone())
                .with_defer_idle_timeout(endpoint.server.common.defer_idle_timeout)
                .with_cids(origin_dcid)
                .with_qlog(endpoint.server.common.qlogger.clone())
                .run();

            endpoint.network.quic_router().deliver(packet, way).await;
            match connection.server_name().await {
                Ok(_name) => {
                    let _ = connection.subscribe_local_address();
                    // Bounded send — drops the connection if the backlog is
                    // saturated, matching dquic's semaphore-based backpressure.
                    if tx.try_send(connection).is_err() {
                        tracing::debug!(
                            target: "h3x::endpoint",
                            "accept backlog full or endpoint shut down, dropping connection"
                        );
                    }
                }
                Err(error) => {
                    tracing::debug!(
                        target: "h3x::endpoint",
                        "failed to accept connection: {error}"
                    );
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// trait impls
// ---------------------------------------------------------------------------

impl quic::Connect for QuicEndpoint {
    type Connection = Connection;
    type Error = ConnectError;

    async fn connect(
        &self,
        server: &http::uri::Authority,
    ) -> Result<Arc<Self::Connection>, Self::Error> {
        use connect_error::{DnsSnafu, TlsSnafu};

        let server_str = match server.port_u16() {
            Some(port) => format!("{}:{}", server.host(), port),
            None => server.host().to_string(),
        };

        let tls = self.client_tls().context(TlsSnafu)?;

        let mut server_eps = self.resolver.lookup(&server_str).await.context(DnsSnafu)?;

        let connection = self.build_client_connection(&server_str, tls);
        if connection.subscribe_local_address().is_err() {
            // connection already closed — return immediately (not a connect
            // error, the caller will observe the closure via any subsequent
            // stream/datagram operation).
            return Ok(connection);
        }

        // Consume the DNS stream until we have at least one path added, or
        // exhaust all endpoints.
        //
        // - `Ok(true)`  → direct path added, connection lifecycle started.
        // - `Ok(false)` → agent endpoint registered; the puncher will build
        //                 paths asynchronously after STUN. Counts as viable.
        // - `Err(_)`    → remember the first probe failure as a fallback.
        let mut last_error: Option<ConnectError> = None;
        let mut any_viable = false;

        while let Some((source, server_ep)) = server_eps.next().await {
            match self
                .setup_server_endpoint(&connection, source, server_ep)
                .await
            {
                Ok(true) => {
                    any_viable = true;
                    last_error = None;
                    break;
                }
                Ok(false) => {
                    any_viable = true;
                    last_error = None;
                }
                Err(error) => {
                    last_error.get_or_insert(error);
                }
            }
        }
        if !any_viable {
            return Err(last_error.unwrap_or(ConnectError::NoReachableEndpoint));
        }

        // Background task: drain the rest of the DNS stream for late-arriving
        // endpoints. Uses a `Weak<Connection>` so this task does not keep the
        // connection alive when all external callers have dropped their Arc.
        tokio::spawn({
            let weak_connection = Arc::downgrade(&connection);
            let terminated = connection.terminated();
            let endpoint = self.clone();
            async move {
                tokio::pin!(terminated);
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut terminated => break,
                        next = server_eps.next() => {
                            let Some((source, server_ep)) = next else { break };
                            let Some(connection) = weak_connection.upgrade() else { break };
                            let _ = endpoint
                                .setup_server_endpoint(&connection, source, server_ep)
                                .await;
                        }
                    }
                }
            }
        });

        Ok(connection)
    }
}

impl quic::Listen for QuicEndpoint {
    type Connection = Connection;
    type Error = AcceptError;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        self.ensure_server_dispatcher()?;
        // Temporarily take the receiver out so we do not hold any lock
        // across `.await`. `accept` takes `&mut self`, so no two calls race.
        let mut rx = self
            .inner
            .server_state
            .accept_rx
            .lock()
            .unwrap()
            .take()
            .ok_or(AcceptError::Shutdown)?;
        let msg = rx.recv().await;
        // Put the receiver back for the next call unless shutdown ran
        // concurrently and already cleared the slot.
        let mut guard = self.inner.server_state.accept_rx.lock().unwrap();
        if guard.is_none() && self.inner.server_state.installed.load(Ordering::Acquire) {
            *guard = Some(rx);
        }
        msg.ok_or(AcceptError::Shutdown)
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        if self
            .inner
            .server_state
            .installed
            .swap(false, Ordering::AcqRel)
        {
            self.network.quic_router().drain_connectless();
            *self.inner.server_state.accept_rx.lock().unwrap() = None;
            *self.inner.server_state.tx_keepalive.lock().unwrap() = None;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clone_key(key: &Arc<PrivateKeyDer<'static>>) -> PrivateKeyDer<'static> {
    key.clone_key()
}

/// Pick a local [`BindUri`] for the given DNS [`Source`] and target endpoint.
///
/// Mirrors `QuicClient::bind_uri_for` so that mDNS endpoints bind on the
/// discovering NIC and other sources fall back to a wildcard address matching
/// the endpoint's family.
fn bind_uri_for(source: &Source, ep: &EndpointAddr) -> BindUri {
    use std::str::FromStr;

    match source {
        Source::Mdns { nic, family } => {
            let f = match family {
                Family::V4 => "v4",
                Family::V6 => "v6",
            };
            BindUri::from_str(&format!("iface://{f}.{nic}:0"))
                .expect("iface URI should be valid")
                .alloc_port()
        }
        _ => match ep.addr_kind() {
            AddrKind::Internet(Family::V4) => BindUri::from_str("inet://0.0.0.0:0")
                .expect("URL should be valid")
                .alloc_port(),
            AddrKind::Internet(Family::V6) => BindUri::from_str("inet://[::]:0")
                .expect("URL should be valid")
                .alloc_port(),
            _ => unreachable!("BLE and other address kinds are not supported yet"),
        },
    }
}

/// rustls `ResolvesServerCert` that returns the configured certificate only
/// when the client's SNI matches our identity name.
///
/// Comparison is ASCII-case-insensitive per RFC 6066 §3.
#[derive(Debug)]
struct SingleSniResolver {
    name: Arc<str>,
    key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SingleSniResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        sni.eq_ignore_ascii_case(self.name.as_ref())
            .then(|| self.key.clone())
    }
}
