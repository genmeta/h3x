use std::{
    error::Error,
    pin::pin,
    sync::{Arc, LazyLock, Mutex as SyncMutex},
};

use dashmap::DashMap;
use futures::StreamExt;
use http::uri::Authority;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};

use crate::{
    connection::{Connection, settings::Settings},
    quic,
    util::watch::Watch,
};

#[derive(Debug)]
pub struct ReuseableConnection<C: quic::Connection> {
    connection: Watch<Arc<Connection<C>>>,
    connect: AsyncMutex<()>,
}

impl<C: quic::Connection> ReuseableConnection<C> {
    pub fn with(connection: Arc<Connection<C>>) -> Self {
        Self {
            connection: Watch::with(connection),
            connect: AsyncMutex::new(()),
        }
    }

    pub fn pending() -> Self {
        Self {
            connection: Watch::new(),
            connect: AsyncMutex::new(()),
        }
    }

    pub fn peek(&self) -> Option<Arc<Connection<C>>> {
        self.connection.peek()
    }

    pub fn reuse(&self) -> Option<Arc<Connection<C>>> {
        let connection = self.peek()?;
        // peer goaway, connection cannot be reused: cannot open new streams
        if let Some(peer_goaway) = connection.peer_goaway()
            && let Some(max_received_stream_id) = connection.max_received_stream_id()
            && peer_goaway.stream_id() <= max_received_stream_id
        {
            return None;
        }
        Some(connection)
    }

    pub async fn reuse_or_initial<E>(
        &self,
        mut try_initial: impl AsyncFnMut() -> Result<Arc<Connection<C>>, E>,
    ) -> Result<Arc<Connection<C>>, E> {
        let mut connections = pin!(self.connection.watch());

        loop {
            tracing::debug!("(Re)trying to reuse connection");
            if let Some(connection) = self.reuse() {
                return Ok(connection);
            }
            tokio::select! {
                biased;
                _new_conn = connections.next() => {
                    tracing::debug!("Entry updated, try to reuse connection");
                    continue;
                }
                _guard = self.connect.lock() => {
                    tracing::debug!("Acquired connection lock, try to initial connection");
                    // its ok to replace the connection, reference of replaced connection still in task until closed
                    let connection = try_initial().await?;
                    tracing::debug!("Initialed new connection, gogogo");
                    self.connection.set(connection.clone());
                }
            }
        }
    }
}

type ConnectionIdentifier = (Authority, Arc<Settings>);
type ReuseableConnections<C> = DashMap<ConnectionIdentifier, Arc<ReuseableConnection<C>>>;

#[derive(Debug)]
pub struct Pool<C: quic::Connection> {
    connections: Arc<ReuseableConnections<C>>,
    tasks: Arc<SyncMutex<JoinSet<()>>>,
}

impl<C: quic::Connection> Clone for Pool<C> {
    fn clone(&self) -> Self {
        Self {
            connections: self.connections.clone(),
            tasks: self.tasks.clone(),
        }
    }
}

impl<C: quic::Connection> Pool<C> {
    pub fn empty() -> Self {
        Self {
            connections: Default::default(),
            tasks: Default::default(),
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
            .expect("TypeId collision")
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
    #[snafu(display("Failed to initial QUIC connection"))]
    Connector { source: E },
    #[snafu(transparent)]
    H3 { source: quic::ConnectionError },
    #[snafu(display("Peer name mismatch: expected {expected}, actual {}", match actual {
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
    #[snafu(display("Peer does not provide identity"))]
    MissingIdentify,
    #[snafu(display("Peer provided invalid identity(cannot be parsed as Authority"))]
    InvalidIdentify,
}

impl<C: quic::Connection> Pool<C> {
    fn try_release(connections: Arc<ReuseableConnections<C>>, identify: ConnectionIdentifier) {
        tokio::task::spawn_blocking(move || {
            (connections.as_ref())
                .remove_if(&identify, |_, connection| connection.reuse().is_none());
        });
    }

    pub async fn reuse_or_connect_with<E: Error + 'static>(
        &self,
        server: Authority,
        settings: Arc<Settings>,
        mut try_connect: impl AsyncFnMut() -> Result<C, E>,
    ) -> Result<Arc<Connection<C>>, ConnectError<E>> {
        let reuseable_connection = self
            .connections
            .entry((server.clone(), settings.clone()))
            .or_insert_with(|| Arc::new(ReuseableConnection::pending()))
            .clone();
        // break borrow of dashmap::Entry to avoid deadlock
        let result = reuseable_connection
            .reuse_or_initial(async || {
                tracing::debug!("Trying to connect to {server}");
                let connection = (try_connect)()
                    .await
                    .context(connect_error::ConnectorSnafu)?;
                tracing::debug!("QUIC connection established, try to upgrade to H3");
                let connection = Connection::new(settings.clone(), connection).await?;
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

                Ok(Arc::new(connection))
            })
            .await;

        match &result {
            Ok(connection) => {
                let connection = connection.clone();
                let connections = self.connections.clone();
                self.tasks.lock().unwrap().spawn(async move {
                    connection.closed().await;
                    Self::try_release(connections, (server, settings));
                });
            }
            Err(..) => {
                Self::try_release(self.connections.clone(), (server, settings));
            }
        }

        result
    }

    pub async fn try_insert(&self, connection: Arc<Connection<C>>) -> Result<(), InsertError> {
        let remote_agent = connection
            .remote_agent()
            .await?
            .context(insert_error::MissingIdentifySnafu)?;
        let settings = connection.settings().clone();
        let authority = remote_agent
            .name()
            .parse()
            .ok()
            .context(insert_error::InvalidIdentifySnafu)?;
        self.connections
            .entry((authority, settings))
            .or_insert(Arc::new(ReuseableConnection::with(connection)));
        Ok(())
    }
}
