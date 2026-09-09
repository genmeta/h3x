// Native runtime owns identities, networking, services and their task lifetime.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use ::dquic::prelude::{QuicClient, QuicListeners};
use bytes::Bytes;
use futures::{StreamExt, stream::FuturesUnordered};
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use tokio::sync::watch;

use super::{
    dquic::{Authenticated, authenticate, transport_error},
    pool::{Entry, Pool},
};
use crate::{Endpoint, Error, LocalAuthority, RemoteAuthority, Settings, transport::CloseOnDrop};

pub(super) type Key = (Option<String>, String);
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
const MAX_REQUESTS: usize = 256;

type ResponseBody = UnsyncBoxBody<Bytes, crate::BoxError>;

type Service = Arc<
    dyn Fn(
            crate::server::Request<crate::ChunkBody>,
        ) -> futures::future::BoxFuture<
            'static,
            Result<crate::server::Response<ResponseBody>, crate::BoxError>,
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
        let runtime = Self::instance()?;
        if runtime.tasks.is_stopping() {
            return Err(Error::Draining);
        }
        runtime.check_local(local.as_ref())?;
        // Name validation rejects ports, selectors and URLs instead of silently
        // dropping a caller's target constraints.
        let target = super::identity::normalize_name(target)?;
        let key = (local.as_ref().map(|local| local.name().to_owned()), target);
        let (entry, publish) = runtime.pool.reserve(&key)?;
        if let Some(publish) = publish
            && let Err(error) = runtime
                .tasks
                .spawn(runtime.create(key.clone(), local, publish))
        {
            runtime.pool.complete(key, &Err(error.clone()));
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
    fn cache_connection(&self, connection: Arc<Connection>) -> Result<bool, Error> {
        self.check_local(connection.local_endpoint())?;
        let Some(remote) = connection.remote_authority() else {
            return Ok(false);
        };
        if remote.name() != "dhttp.net" && !remote.name().ends_with(".dhttp.net") {
            return Ok(false);
        }
        let key = (
            connection
                .local_endpoint()
                .map(|local| local.name().to_owned()),
            remote.name().to_owned(),
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
        target: String,
    ) -> Result<Arc<Connection>, Error> {
        let client = match &local {
            Some(local) => &self.endpoints[local.name()].1,
            None => &self.anonymous,
        };
        let handshake = client.connect(&target).await.map_err(transport_error)?;
        let mut close_guard = CloseOnDrop(
            Some(Arc::new(handshake.clone())),
            crate::Code::H3_REQUEST_CANCELLED,
        );
        let handshake = authenticate(handshake, local, Some(&target)).await?;
        let connection = Self::adopt_connection(handshake).await?;
        self.tasks
            .spawn(self.serve_connection(connection.clone()))?;
        close_guard.0.take();
        Ok(connection)
    }

    async fn adopt_connection(handshake: Authenticated) -> Result<Arc<Connection>, Error> {
        let Authenticated {
            transport,
            local,
            remote,
        } = handshake;
        let protocol = crate::protocol::new(transport, Settings::default()).await?;
        let handle = Arc::new(Connection {
            protocol,
            local: local.map(LocalAuthority),
            remote,
        });
        Ok(handle)
    }

    async fn accept_connection(
        &'static self,
        handshake: Arc<::dquic::prelude::Connection>,
        local: Arc<Endpoint>,
    ) -> Result<(), Error> {
        let handshake = authenticate(handshake, Some(local), None).await?;
        let connection = Self::adopt_connection(handshake).await?;
        self.tasks
            .spawn(self.serve_connection(connection.clone()))?;
        if let Err(error) = self.cache_connection(connection.clone()) {
            connection
                .protocol
                .close(crate::Code::H3_INTERNAL_ERROR, b"invalid pool admission");
            return Err(error);
        }
        Ok(())
    }

    async fn accept_connections(&'static self) {
        let mut handshakes = FuturesUnordered::new();
        let mut stopping = self.tasks.subscribe();
        loop {
            tokio::select! {
                _ = stopping.wait_for(|value| *value) => break,
                incoming = self.listeners.accept(), if handshakes.len() < MAX_HANDSHAKES => {
                    let Ok((handshake, name, _, _)) = incoming else { break };
                    let mut close_guard = CloseOnDrop(
                        Some(Arc::new(handshake.clone())), crate::Code::H3_REQUEST_CANCELLED,
                    );
                    let Some((local, _)) = self.endpoints.get(&name) else { continue };
                    let local = local.clone();
                    handshakes.push(async move {
                        let result = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT, self.accept_connection(handshake, local),
                        ).await;
                        if matches!(result, Ok(Ok(()))) {
                            close_guard.0.take();
                        }
                    });
                }
                _ = handshakes.next(), if !handshakes.is_empty() => {}
            }
        }
    }

    pub(crate) fn listen<S, B>(endpoint: &Arc<Endpoint>, service: S) -> Result<(), Error>
    where
        S: tower_service::Service<
                crate::server::Request<crate::ChunkBody>,
                Response = crate::server::Response<B>,
            > + Send
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

    async fn serve_connection(&'static self, connection: Arc<Connection>) {
        let mut tasks = tokio::task::JoinSet::new();
        let mut stopping = self.tasks.subscribe();
        loop {
            tokio::select! {
                _ = stopping.wait_for(|value| *value) => {
                    connection.protocol.close(crate::Code::H3_NO_ERROR, b"runtime stopping");
                    break;
                },
                incoming = crate::transport::Connection::accept_bi(connection.protocol.transport()),
                    if tasks.len() < MAX_REQUESTS => {
                    let (id, (recv, send)) = match incoming {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let request = connection.protocol.read_request(id, recv, send);
                    let connection = connection.clone();
                    tasks.spawn(async move {
                        let Ok(Some((request, reply))) = request.await else {
                            return;
                        };
                        let Some(local) = connection.local.as_ref() else {
                            let _ = reply.send(empty_response(http::StatusCode::NOT_FOUND)).await;
                            return;
                        };
                        let req = crate::server::Request::new(
                            request, local.clone(), connection.remote.clone(),
                        );
                        let service = self.services.lock().unwrap().get(local.0.name()).cloned();
                        let fallback = |status| crate::server::Response::new(
                            empty_response(status), local.clone(), connection.remote.clone(),
                        );
                        let response = match service {
                            Some(service) => service(req).await.unwrap_or_else(|_| {
                                fallback(http::StatusCode::INTERNAL_SERVER_ERROR)
                            }),
                            None => fallback(http::StatusCode::NOT_FOUND),
                        };
                        let response = if response.matches_authorities(local, connection.remote.as_ref()) {
                            response
                        } else {
                            fallback(http::StatusCode::INTERNAL_SERVER_ERROR)
                        };
                        let _ = reply.send(response.into_http()).await;
                    });
                }
                _ = connection.protocol.closed() => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if matches!(result, Some(Err(_))) {
                        connection.protocol.close(crate::Code::H3_INTERNAL_ERROR, b"service task failed");
                        break;
                    }
                }
            }
        }
        tasks.shutdown().await;
        let _ = connection.protocol.closed().await;
    }
}

fn empty_response(status: http::StatusCode) -> http::Response<ResponseBody> {
    let mut response =
        http::Response::new(Empty::<Bytes>::new().map_err(Into::into).boxed_unsync());
    *response.status_mut() = status;
    response
}

/// Stops runtime admission, closes connections, cancels and joins services and dialing.
/// Unlike protocol Connection::closed, this includes application service tasks.
/// Cancellation of this wait does not resume the runtime; call again to finish joining.
pub async fn shutdown() -> Result<(), Error> {
    let runtime = Runtime::instance()?;
    let result = runtime.tasks.shutdown().await;
    runtime.pool.clear();
    result
}

/// Runtime association of a protocol connection and its authenticated identity.
/// Protocol state never points back to this object or Endpoint.
/// TODO：dquic 直接实现 带身份的 Connection
pub struct Connection {
    protocol: crate::protocol::Connection<Arc<::dquic::prelude::Connection>>,
    local: Option<LocalAuthority>,
    remote: Option<RemoteAuthority>,
}

impl Connection {
    pub fn protocol(&self) -> &crate::protocol::Connection<Arc<::dquic::prelude::Connection>> {
        &self.protocol
    }

    pub fn local_endpoint(&self) -> Option<&Arc<Endpoint>> {
        self.local.as_ref().map(|local| &local.0)
    }

    pub fn remote_authority(&self) -> Option<&RemoteAuthority> {
        self.remote.as_ref()
    }

    pub fn is_draining(&self) -> bool {
        self.protocol.is_draining()
    }
}
