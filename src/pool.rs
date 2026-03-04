use std::{
    error::Error,
    pin::pin,
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use futures::{StreamExt, never::Never};
use http::uri::Authority;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;

use crate::{connection::Connection, dhttp::settings::Settings, quic, util::watch::Watch};

#[derive(Debug)]
pub struct ReuseableConnection<C: quic::Connection> {
    connection: Watch<Arc<Connection<C>>>,
    task: AsyncMutex<Option<AbortOnDropHandle<()>>>,
}

type ConnectionIdentifier = (Authority, Arc<Settings>);
type ReuseableConnections<C> = DashMap<ConnectionIdentifier, Arc<ReuseableConnection<C>>>;

impl<C: quic::Connection> ReuseableConnection<C> {
    pub fn pending() -> Self {
        Self {
            connection: Watch::new(),
            task: AsyncMutex::new(None),
        }
    }

    pub fn peek(&self) -> Option<Arc<Connection<C>>> {
        self.connection.peek()
    }

    pub fn reuse(&self) -> Option<Arc<Connection<C>>> {
        let connection = self.peek()?;
        // peer goaway, connection cannot be reused: cannot open new streams
        if let Some(peer_goaway) = connection.peek_peer_goaway()
            && let Some(max_received_stream_id) = connection.max_received_stream_id()
            && peer_goaway.stream_id() <= max_received_stream_id
        {
            return None;
        }
        Some(connection)
    }

    pub async fn insert(&self, connection: Arc<Connection<C>>, task: AbortOnDropHandle<()>) {
        self.insert_with(async || (connection, task)).await
    }

    pub async fn insert_with(
        &self,
        f: impl AsyncFnOnce() -> (Arc<Connection<C>>, AbortOnDropHandle<()>),
    ) {
        self.try_insert_with::<Never>(async || Ok(f().await))
            .await
            .ok();
    }

    pub async fn try_insert_with<E>(
        &self,
        f: impl AsyncFnOnce() -> Result<(Arc<Connection<C>>, AbortOnDropHandle<()>), E>,
    ) -> Result<(), E> {
        let mut task_guard = self.task.lock().await;
        let (connection, task) = f().await?;
        self.connection.set(connection);
        *task_guard = Some(task);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Pool<C: quic::Connection> {
    connections: Arc<ReuseableConnections<C>>,
}

impl<C: quic::Connection> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            connections: self.connections.clone(),
        }
    }
}

impl<C: quic::Connection> Pool<C> {
    pub fn empty() -> Self {
        Self {
            connections: Default::default(),
        }
    }

    pub fn global() -> &'static Self {
        use std::any::{Any, TypeId};

        static POOLS: LazyLock<DashMap<TypeId, &'static (dyn Any + Send + Sync)>> =
            LazyLock::new(DashMap::new);
        POOLS
            .entry(TypeId::of::<C>())
            .or_insert_with(|| Box::leak(Box::new(Pool::<C>::empty())))
            .downcast_ref::<Pool<C>>()
            .expect("type id collision")
    }
}

impl<C: quic::Connection> Default for Pool<C> {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ConnectError<E: Error + 'static> {
    #[snafu(display("failed to initial QUIC connection"))]
    Connector { source: E },
    #[snafu(transparent)]
    H3 { source: quic::ConnectionError },
    #[snafu(display("peer name mismatch: expected {expected}, actual {}", match actual {
        Some(name) => name,
        None => "<anonymous>", 
    }))]
    IncorrectIdentify {
        expected: String,
        actual: Option<String>,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InsertError {
    #[snafu(transparent)]
    Quic { source: quic::ConnectionError },
    #[snafu(display("peer does not provide identity"))]
    MissingIdentify,
    #[snafu(display("peer provided invalid identity(cannot be parsed as Authority"))]
    InvalidIdentify,
}

impl<C: quic::Connection> Pool<C> {
    fn spawn_try_release(self, identify: ConnectionIdentifier) {
        tokio::task::spawn_blocking(move || {
            (self.connections.as_ref())
                .remove_if(&identify, |_, connection| connection.reuse().is_none());
        });
    }

    #[tracing::instrument(level = "debug", skip(self, connector), err)]
    pub async fn reuse_or_connect_with<Client>(
        &self,
        connector: &Client,
        settings: Arc<Settings>,
        server: Authority,
    ) -> Result<Arc<Connection<C>>, ConnectError<Client::Error>>
    where
        Client: quic::Connect<Connection = C> + ?Sized,
    {
        let reuseable_connection = self
            .connections
            .entry((server.clone(), settings.clone()))
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()))
            .clone();
        // break borrow of dashmap::Entry to avoid deadlock

        let result = {
            let mut connections = pin!(reuseable_connection.connection.watch());

            loop {
                tracing::debug!("(Re)trying to reuse connection");
                if let Some(connection) = reuseable_connection.reuse() {
                    tracing::debug!("Found reusable connection, gogogo");
                    break Ok(connection);
                }

                let try_connect = async || {
                    let quic_conn = connector
                        .connect(&server)
                        .await
                        .context(connect_error::ConnectorSnafu)?;
                    let connection = Connection::new(settings.clone(), quic_conn).await?;

                    tracing::debug!("H3 connection established, verifying peer identity");
                    let remote_agent = connection.remote_agent().await?;
                    let actual_peer_name = remote_agent.as_ref().map(|agent| agent.name());
                    if actual_peer_name.as_ref() != Some(&server.host()) {
                        return connect_error::IncorrectIdentifySnafu {
                            expected: server.host().to_string(),
                            actual: actual_peer_name.map(ToOwned::to_owned),
                        }
                        .fail();
                    }

                    let connection = Arc::new(connection);
                    // its ok to replace the connection, reference of replaced connection still in task until closed
                    let task = AbortOnDropHandle::new(tokio::spawn({
                        let connection = connection.clone();
                        let pool = self.clone();
                        let server = server.clone();
                        let settings = settings.clone();
                        async move {
                            connection.closed().await;
                            pool.spawn_try_release((server, settings));
                        }
                    }));
                    Ok((connection, task))
                };

                tokio::select! {
                    biased;
                    _new_conn = connections.next() => {
                        tracing::debug!("Entry updated, try to reuse connection");
                    }
                    result = reuseable_connection.try_insert_with(try_connect) => {
                        result?;
                        tracing::debug!("New connection inserted");
                    }
                }
            }
        };

        match &result {
            Ok(..) => tracing::debug!("Connection ready to use"),
            Err(..) => self.clone().spawn_try_release((server, settings)),
        }

        result
    }

    pub async fn try_insert(&self, connection: Arc<Connection<C>>) -> Result<(), InsertError> {
        let remote_agent = connection
            .remote_agent()
            .await?
            .context(insert_error::MissingIdentifySnafu)?;
        let settings = connection.settings().clone();
        let client = remote_agent
            .name()
            .parse()
            .ok()
            .context(insert_error::InvalidIdentifySnafu)?;

        let identity = (client, settings);
        let reuseable_connection = self
            .connections
            .entry(identity.clone())
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()))
            .clone();

        let pool = self.clone();
        reuseable_connection
            .insert(
                connection.clone(),
                AbortOnDropHandle::new(tokio::spawn(async move {
                    connection.closed().await;
                    pool.spawn_try_release(identity);
                })),
            )
            .await;
        Ok(())
    }
}
