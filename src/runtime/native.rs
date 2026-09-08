// Native runtime owns identities, networking, services and their task lifetime.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use ::dquic::prelude::{QuicClient, QuicListeners};
use bytes::Bytes;
use futures::{StreamExt, stream::FuturesUnordered};
use http::uri::Authority;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use tokio::sync::watch;

use super::{
    dquic::{Authenticated, DquicTransport, authenticate, transport_error},
    pool::{Entry, Pool},
};
use crate::{Endpoint, Error, RemoteAuthority, Settings, transport::PendingTransport};

pub(super) type Key = (Option<String>, Authority);
pub(super) type Connected = Result<Arc<Connection>, Error>;

pub struct Runtime {
    pool: Pool,
    endpoints: HashMap<String, (Arc<Endpoint>, Arc<QuicClient>)>,
    anonymous: Arc<QuicClient>,
    listeners: Arc<QuicListeners>,
    services: Mutex<HashMap<String, Service>>,
    tasks: super::tasks::Tasks,
}

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HANDSHAKES: usize = 64;

type ResponseBody = UnsyncBoxBody<Bytes, crate::BoxError>;

type Service = Arc<
    dyn Fn(
            http::Request<crate::ChunkBody>,
        ) -> crate::platform::BoxFuture<
            'static,
            Result<http::Response<ResponseBody>, crate::BoxError>,
        > + Send
        + Sync,
>;

/// Register prepared QUIC clients/listeners and their immutable HTTP identities.
/// The caller configures TLS (including h3 ALPN), DNS and bindings before this call.
/// Registration is synchronous and all-or-nothing; network resources remain owned
/// by their caller as well as these shared handles. Reinitialization is not supported.
pub fn init(
    endpoints: Vec<(Arc<Endpoint>, Arc<QuicClient>)>,
    anonymous: Arc<QuicClient>,
    listeners: Arc<QuicListeners>,
) -> Result<(), Error> {
    if RUNTIME.get().is_some() {
        return Err(Error::AlreadyInitialized);
    }
    tokio::runtime::Handle::try_current().map_err(|_| Error::OwnerStopped)?;
    let mut registered = HashMap::new();
    for (endpoint, client) in endpoints {
        let server = listeners
            .get_server(endpoint.name())
            .ok_or_else(|| invalid_config("endpoint has no prepared listener"))?;
        let expected = endpoint.certificate();
        let actual = server.certified_key();
        if actual.cert != expected.cert
            || !Arc::ptr_eq(&actual.key, &expected.key)
            || actual.ocsp != expected.ocsp
        {
            return Err(Error::IdentityMismatch);
        }
        if registered
            .insert(endpoint.name().to_owned(), (endpoint, client))
            .is_some()
        {
            return Err(Error::IdentityInUse);
        }
    }
    if listeners.servers().len() != registered.len() {
        return Err(invalid_config("listener contains an unregistered endpoint"));
    }
    RUNTIME
        .set(Runtime {
            pool: Pool::default(),
            tasks: Default::default(),
            endpoints: registered,
            anonymous,
            listeners,
            services: Default::default(),
        })
        .map_err(|_| Error::AlreadyInitialized)?;
    let runtime = RUNTIME.get().expect("runtime just initialized");
    runtime.tasks.spawn(runtime.accept_connections())?;
    Ok(())
}

fn invalid_config(message: impl Into<String>) -> Error {
    Error::InvalidConfig {
        source: Arc::new(std::io::Error::other(message.into())),
    }
}

impl Runtime {
    fn instance() -> Result<&'static Self, Error> {
        RUNTIME.get().ok_or(Error::NotInitialized)
    }

    /// Reuse a connection, or share one in-flight dial for the same identity and target.
    pub async fn get(local: Option<Arc<Endpoint>>, target: &str) -> Result<Arc<Connection>, Error> {
        let pool = Self::instance()?;
        if pool.tasks.is_stopping() {
            return Err(Error::Draining);
        }
        pool.check_local(local.as_ref())?;
        // Name validation rejects ports, selectors and URLs instead of silently
        // dropping a caller's target constraints.
        let target: Authority =
            super::identity::normalize_name(target)?
                .parse()
                .map_err(|source| Error::InvalidEndpoint {
                    source: Arc::new(source),
                })?;
        let key = (local.as_ref().map(|local| local.name().to_owned()), target);
        let (entry, publish) = pool.pool.reserve(&key)?;
        if let Some(publish) = publish
            && let Err(error) = pool.tasks.spawn(pool.create(key.clone(), local, publish))
        {
            pool.pool.complete(key, &Err(error.clone()));
            return Err(error);
        }
        let mut waiting = match entry {
            Entry::Ready(connection) => return Ok(connection),
            Entry::Connecting { waiters } => waiters,
        };
        waiting
            .wait_for(Option::is_some)
            .await
            .map_err(|_| Error::OwnerStopped)?
            .clone()
            .expect("wait_for returned a completed result")
    }

    /// Admit an authenticated, initialized connection to the reuse cache.
    /// False means it remains usable but was not selected for caching.
    fn accept(&self, connection: Arc<Connection>) -> Result<bool, Error> {
        self.check_local(connection.local_endpoint())?;
        let Some(target) = connection.reuse_target() else {
            return Ok(false);
        };
        let key = (
            connection
                .local_endpoint()
                .map(|local| local.name().to_owned()),
            target.clone(),
        );
        Ok(self.pool.admit(key, connection))
    }

    async fn create(
        &'static self,
        key: Key,
        local: Option<Arc<Endpoint>>,
        publish: watch::Sender<Option<Connected>>,
    ) {
        let mut stopping = self.tasks.subscribe();
        let result = tokio::select! {
            biased;
            _ = stopping.wait_for(|value| *value) => Err(Error::Draining),
            result = tokio::time::timeout(CONNECT_TIMEOUT, self.connect(local, key.1.clone())) => match result {
                Ok(Ok(connection)) if connection.is_draining() => Err(Error::Draining),
                Ok(result) => result,
                Err(_) => Err(Error::TimedOut),
            },
        };
        self.pool.complete(key, &result);
        publish.send_replace(Some(result));
    }

    fn check_local(&self, local: Option<&Arc<Endpoint>>) -> Result<(), Error> {
        if let Some(local) = local {
            match self.endpoints.get(local.name()) {
                Some((registered, _)) if Arc::ptr_eq(registered, local) => {}
                _ => return Err(Error::IdentityInUse),
            }
        }
        Ok(())
    }

    async fn connect(
        &'static self,
        local: Option<Arc<Endpoint>>,
        target: Authority,
    ) -> Result<Arc<Connection>, Error> {
        let client = match &local {
            Some(local) => &self.endpoints[local.name()].1,
            None => &self.anonymous,
        };
        let raw = client
            .connect(target.host())
            .await
            .map_err(transport_error)?;
        let handshake = PendingTransport::new(DquicTransport(raw));
        let handshake = authenticate(handshake, local, Some(target)).await?;
        self.adopt(handshake).await
    }

    async fn adopt(&'static self, handshake: Authenticated) -> Result<Arc<Connection>, Error> {
        let Authenticated {
            transport,
            local,
            remote,
            target,
        } = handshake;
        // Observe termination before protocol cleanup waits for released bodies.
        let terminated = transport
            .transport
            .as_ref()
            .expect("authenticated transport")
            .clone();
        let (sender, connection) = crate::protocol::new(transport, Settings::default()).await?;
        let handle = Arc::new(Connection {
            terminated,
            sender,
            local,
            remote,
            target,
        });
        if let Err(error) = self
            .tasks
            .spawn(self.serve_connection(handle.clone(), connection))
        {
            handle
                .sender
                .close(crate::Code::H3_NO_ERROR, b"runtime stopping");
            return Err(error);
        }
        Ok(handle)
    }

    async fn accept_connections(&'static self) {
        let mut handshakes = FuturesUnordered::new();
        let mut stopping = self.tasks.subscribe();
        loop {
            tokio::select! {
                _ = stopping.wait_for(|value| *value) => break,
                incoming = self.listeners.accept(), if handshakes.len() < MAX_HANDSHAKES => {
                    let Ok((raw, name, _, _)) = incoming else { break };
                    let handshake = PendingTransport::new(DquicTransport(raw));
                    let Some((local, _)) = self.endpoints.get(&name) else { continue };
                    let local = local.clone();
                    handshakes.push(async move {
                        let _ = tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
                            let handshake = authenticate(handshake, Some(local), None).await?;
                            let connection = self.adopt(handshake).await?;
                            if let Err(error) = self.accept(connection.clone()) {
                                connection.sender.close(crate::Code::H3_INTERNAL_ERROR, b"invalid pool admission");
                                return Err(error);
                            }
                            Ok::<_, Error>(())
                        }).await;
                    });
                }
                _ = handshakes.next(), if !handshakes.is_empty() => {}
            }
        }
    }

    pub(crate) fn listen<S, B>(endpoint: &Arc<Endpoint>, service: S) -> Result<(), Error>
    where
        S: tower_service::Service<http::Request<crate::ChunkBody>, Response = http::Response<B>>
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<crate::BoxError>,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<crate::BoxError>,
    {
        let pool = Self::instance()?;
        if pool.tasks.is_stopping() {
            return Err(Error::Draining);
        }
        pool.check_local(Some(endpoint))?;
        let mut services = pool.services.lock().unwrap();
        if services.contains_key(endpoint.name()) {
            return Err(Error::AlreadyListening);
        }
        let service = Arc::new(tokio::sync::Mutex::new(service));
        services.insert(
            endpoint.name().to_owned(),
            Arc::new(move |request| {
                let service = service.clone();
                Box::pin(async move {
                    let response = {
                        let mut service = service.lock().await;
                        futures::future::poll_fn(|cx| service.poll_ready(cx))
                            .await
                            .map_err(Into::into)?;
                        service.call(request)
                    };
                    response
                        .await
                        .map(|response| {
                            response.map(|body| body.map_err(Into::into).boxed_unsync())
                        })
                        .map_err(Into::into)
                })
            }),
        );
        Ok(())
    }

    async fn serve_connection(
        &'static self,
        handle: Arc<Connection>,
        mut connection: crate::protocol::Connection<DquicTransport>,
    ) {
        let mut tasks = tokio::task::JoinSet::new();
        let mut accepting = true;
        let mut stopping = self.tasks.subscribe();
        loop {
            tokio::select! {
                _ = stopping.wait_for(|value| *value) => {
                    handle.sender.close(crate::Code::H3_NO_ERROR, b"runtime stopping");
                    break;
                },
                incoming = connection.accept(), if accepting => {
                    match incoming {
                        Ok(Some((mut request, reply))) => {
                            request.extensions_mut().remove::<crate::RequestAuthority>();
                            request.extensions_mut().remove::<RemoteAuthority>();
                            if let Some(remote) = handle.remote_authority() {
                                request.extensions_mut().insert(crate::RequestAuthority::Peer(remote.clone()));
                                request.extensions_mut().insert(remote.clone());
                            }
                            let service = handle.local_endpoint().and_then(|local| {
                                self.services.lock().unwrap().get(local.name()).cloned()
                            });
                            tasks.spawn(async move {
                                let response = match service {
                                    Some(service) => service(request).await.unwrap_or_else(|_| {
                                        empty_response(http::StatusCode::INTERNAL_SERVER_ERROR)
                                    }),
                                    None => empty_response(http::StatusCode::NOT_FOUND),
                                };
                                let _ = reply.send(response).await;
                            });
                        }
                        Ok(None) => accepting = false,
                        Err(_) => break,
                    }
                }
                _ = crate::transport::Connection::closed(&handle.terminated) => break,
                _ = handle.sender.closed() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if matches!(result, Some(Err(_))) {
                        handle.sender.close(crate::Code::H3_INTERNAL_ERROR, b"service task failed");
                        break;
                    }
                }
                else => break,
            }
            if !accepting && tasks.is_empty() {
                break;
            }
        }
        tasks.shutdown().await;
        let _ = handle.sender.closed().await;
    }
}

fn empty_response(status: http::StatusCode) -> http::Response<ResponseBody> {
    let mut response =
        http::Response::new(Empty::<Bytes>::new().map_err(Into::into).boxed_unsync());
    *response.status_mut() = status;
    response
}

/// Stops runtime admission, closes connections, cancels and joins services and dialing.
/// Unlike protocol Sender::closed, this includes application service tasks.
/// Cancellation of this wait does not resume the runtime; call again to finish joining.
pub async fn shutdown() -> Result<(), Error> {
    let runtime = Runtime::instance()?;
    let result = runtime.tasks.shutdown().await;
    runtime.pool.clear();
    result
}

/// Runtime association of a protocol connection and its authenticated identity.
/// Protocol state never points back to this object or Endpoint.
pub struct Connection {
    terminated: DquicTransport,
    sender: crate::protocol::Sender<DquicTransport>,
    local: Option<Arc<Endpoint>>,
    remote: Option<RemoteAuthority>,
    target: Option<Authority>,
}
impl Connection {
    pub fn sender(&self) -> &crate::protocol::Sender<DquicTransport> {
        &self.sender
    }

    pub fn local_endpoint(&self) -> Option<&Arc<Endpoint>> {
        self.local.as_ref()
    }

    pub fn remote_authority(&self) -> Option<&RemoteAuthority> {
        self.remote.as_ref()
    }

    pub fn reuse_target(&self) -> Option<&Authority> {
        self.target.as_ref()
    }

    pub fn is_draining(&self) -> bool {
        self.sender.is_draining()
    }
}
