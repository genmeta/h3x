//! QUIC-only endpoint built on top of a shared [`Network`].

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use futures::StreamExt;
use rustls::{ClientConfig, pki_types::PrivateKeyDer};
use snafu::{ResultExt, Snafu};

use super::{
    config::{ClientQuicConfig, ServerCertVerifierChoice, ServerQuicConfig},
    identity::{Identity, NamedIdentity},
    network::{BindServerError, Network, ServerBinding},
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
        },
        qinterface::{bind_uri::BindUri, io::IO},
        qresolve::Source,
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
    /// Failed to acquire a local interface for the discovered endpoint.
    #[snafu(display("failed to bind local interface"))]
    BindInterface {
        /// Underlying I/O error.
        source: std::io::Error,
    },
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
    pub network: Arc<Network>,
    /// TLS identity for this endpoint.
    pub identity: Identity,
    /// Resolver used when establishing outbound connections.
    pub resolver: Arc<dyn Resolve + Send + Sync>,
    /// Client-side configuration.
    pub client: ClientQuicConfig,
    /// Server-side configuration.
    pub server: ServerQuicConfig,
    client_tls_cache: ArcSwapOption<CachedClientTls>,
    server_binding_cache: ArcSwapOption<CachedServerBinding>,
}

struct CachedClientTls {
    key: ClientCacheKey,
    config: Arc<ClientConfig>,
}

#[derive(PartialEq, Eq)]
struct ClientCacheKey {
    identity_ptr: usize,
    client_own_ptr: usize,
    client_common_ptr: usize,
}

struct CachedServerBinding {
    key: ServerCacheKey,
    binding: ServerBinding,
}

#[derive(PartialEq, Eq)]
struct ServerCacheKey {
    network_ptr: usize,
    identity_ptr: usize,
    server_own_ptr: usize,
    server_common_ptr: usize,
}

impl Clone for QuicEndpoint {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            identity: self.identity.clone(),
            resolver: self.resolver.clone(),
            client: self.client.clone(),
            server: self.server.clone(),
            client_tls_cache: ArcSwapOption::empty(),
            server_binding_cache: ArcSwapOption::empty(),
        }
    }
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
            client_tls_cache: ArcSwapOption::empty(),
            server_binding_cache: ArcSwapOption::empty(),
        }
    }

    fn client_cache_key(&self) -> ClientCacheKey {
        ClientCacheKey {
            identity_ptr: identity_ptr(&self.identity),
            client_own_ptr: Arc::as_ptr(&self.client.own) as usize,
            client_common_ptr: Arc::as_ptr(&self.client.common) as usize,
        }
    }

    fn server_cache_key(&self) -> ServerCacheKey {
        ServerCacheKey {
            network_ptr: Arc::as_ptr(&self.network) as usize,
            identity_ptr: identity_ptr(&self.identity),
            server_own_ptr: Arc::as_ptr(&self.server.own) as usize,
            server_common_ptr: Arc::as_ptr(&self.server.common) as usize,
        }
    }
}

fn identity_ptr(identity: &Identity) -> usize {
    match identity {
        Identity::Anonymous => 0,
        Identity::Named(id) => Arc::as_ptr(id) as usize,
    }
}

impl QuicEndpoint {
    fn client_tls(&self) -> Result<Arc<ClientConfig>, BuildClientTlsError> {
        let key = self.client_cache_key();
        if let Some(cached) = self.client_tls_cache.load_full()
            && cached.key == key
        {
            return Ok(cached.config.clone());
        }
        let config = Arc::new(self.build_client_tls()?);
        self.client_tls_cache.store(Some(Arc::new(CachedClientTls {
            key,
            config: config.clone(),
        })));
        Ok(config)
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
}

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

impl QuicEndpoint {
    async fn server_binding(&self) -> Result<ServerBinding, AcceptError> {
        use accept_error::BindServerSnafu;

        let named = match &self.identity {
            Identity::Anonymous => return Err(AcceptError::ServerUnavailable),
            Identity::Named(id) => id.clone(),
        };
        let key = self.server_cache_key();
        if let Some(cached) = self.server_binding_cache.load_full()
            && cached.key == key
        {
            return Ok(cached.binding.clone());
        }
        let binding = self
            .network
            .bind_server(named as Arc<NamedIdentity>, self.server.clone())
            .await
            .context(BindServerSnafu)?;
        self.server_binding_cache
            .store(Some(Arc::new(CachedServerBinding {
                key,
                binding: binding.clone(),
            })));
        Ok(binding)
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

        let server_str = match server.port_u16() {
            Some(port) => format!("{}:{}", server.host(), port),
            None => server.host().to_string(),
        };

        let tls = self.client_tls().context(TlsSnafu)?;

        let mut server_eps = self.resolver.lookup(&server_str).await.context(DnsSnafu)?;

        let connection = self.build_client_connection(&server_str, tls);
        if connection.subscribe_local_address().is_err() {
            return Ok(connection);
        }

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
        let binding = self.server_binding().await?;
        binding.recv().await.ok_or(AcceptError::Shutdown)
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        self.server_binding_cache.store(None);
        Ok(())
    }
}

fn clone_key(key: &Arc<PrivateKeyDer<'static>>) -> PrivateKeyDer<'static> {
    key.clone_key()
}

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
