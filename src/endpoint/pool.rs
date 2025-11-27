use std::{
    error::Error,
    pin::pin,
    sync::{Arc, Mutex as SyncMutex},
};

use dashmap::DashMap;
use futures::StreamExt;
use snafu::{ResultExt, Snafu};
use tokio::{sync::Mutex as AsyncMutex, task::JoinSet};

use crate::{
    connection::{Connection, settings::Settings},
    quic::{self, identity, identity::WithIdentityExt},
    util::watch::Watch,
};

pub struct PoolEntry<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> {
    connection: Watch<Arc<Connection<C>>>,
    connect: AsyncMutex<()>,
}

impl<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> std::fmt::Debug
    for PoolEntry<C>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolEntry")
            .field("connection", &self.connection)
            .field("connect", &self.connect)
            .finish()
    }
}

impl<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> PoolEntry<C> {
    pub fn pending() -> Self {
        Self {
            connection: Watch::new(),
            connect: AsyncMutex::new(()),
        }
    }

    pub async fn reuse_or_connect<E>(
        &self,
        mut try_connect: impl AsyncFnMut() -> Result<Connection<C>, E>,
    ) -> Result<Arc<Connection<C>>, E> {
        if let Some(raw_connection) = self.connection.peek() {
            return Ok(raw_connection);
        }

        let mut connections = pin!(self.connection.watch());

        loop {
            tokio::select! {
                biased;
                _guard = self.connect.lock() => {
                    // its ok to replace the connection, reference of replaced connection still in task until closed
                    self.connection.set(Arc::new(try_connect().await?));
                }
                connection = connections.next() => {
                    let Some(connection) = connection else {
                        // this should not happen as the watch never closes
                        continue;
                    };
                    // todo: test whether to reuse the connection or reconnect
                    return Ok(connection)
                }
            }
        }
    }
}

pub struct Pool<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> {
    settings: Settings,
    connections: Arc<DashMap<String, PoolEntry<C>>>,
    tasks: SyncMutex<JoinSet<()>>,
}

impl<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> std::fmt::Debug
    for Pool<C>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pool")
            .field("settings", &self.settings)
            .field("connections", &self.connections)
            .field("tasks", &self.tasks)
            .finish()
    }
}

impl<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> Pool<C> {
    fn new(settings: Settings) -> Self {
        Self {
            settings,
            connections: Arc::default(),
            tasks: SyncMutex::default(),
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ConnectError<E: Error + 'static> {
    #[snafu(display("Failed to establish QUIC connection"))]
    QuicConnect { source: E },
    #[snafu(display("Failed to initial HTTP3 connection"))]
    H3Connect { source: quic::ConnectionError },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum AcceptError<E: Error + 'static> {
    #[snafu(display("Failed to establish QUIC connection"))]
    QuicConnect { source: E },
    #[snafu(display("Failed to identify connection"))]
    Identify { source: quic::ConnectionError },
    #[snafu(display("Failed to initial HTTP3 connection"))]
    H3Connect { source: quic::ConnectionError },
}

impl<C: quic::ManageStream + quic::Close + identity::WithIdentity + Unpin> Pool<C> {
    fn insert<E>(
        &self,
        name: &str,
        result: Result<Arc<Connection<C>>, E>,
    ) -> Result<Arc<Connection<C>>, E>
    where
        C: Send + 'static,
    {
        match &result {
            Ok(h3_connection) => {
                let name = name.to_string();
                let connections = self.connections.clone();
                let h3_connection = h3_connection.clone();
                self.tasks.lock().unwrap().spawn(async move {
                    h3_connection.closed().await;
                    connections.remove_if(&name, |_, PoolEntry { connection, .. }| {
                        connection.peek().is_none_or(|exist_connection| {
                            Arc::ptr_eq(&exist_connection, &h3_connection)
                        })
                    });
                });
            }
            Err(..) => {
                self.connections
                    .remove_if(name, |_, PoolEntry { connection, .. }| {
                        connection.peek().is_none()
                    });
            }
        }

        result
    }

    pub async fn reuse_or_connect<Q>(
        &self,
        connector: &Q,
        name: &str,
    ) -> Result<Arc<Connection<C>>, ConnectError<Q::Error>>
    where
        Q: quic::Connect<Connection = C>,
        C: Send + 'static,
        C::StreamReader: Send,
        C::StreamWriter: Send,
    {
        let result = self
            .connections
            .entry(name.to_string())
            .or_insert_with(PoolEntry::pending)
            .downgrade()
            .reuse_or_connect(async move || {
                let quic_connection = connector
                    .connect(name)
                    .await
                    .context(connect_error::QuicConnectSnafu)?;
                Connection::new(self.settings.clone(), quic_connection)
                    .await
                    .context(connect_error::H3ConnectSnafu)
            })
            .await;

        self.insert(name, result)
    }

    pub async fn accept_one<Q>(
        &self,
        acceptor: &Q,
    ) -> Result<(Arc<Connection<C>>, String), AcceptError<Q::Error>>
    where
        Q: quic::Listen<Connection = C>,
        C: Send + 'static,
        C::StreamReader: Send,
        C::StreamWriter: Send,
    {
        let (mut quic_connection, connected_server) = acceptor
            .accept()
            .await
            .context(accept_error::QuicConnectSnafu)?;

        let name = quic_connection
            .name()
            .await
            .context(accept_error::IdentifySnafu)?;

        let result = Connection::new(self.settings.clone(), quic_connection)
            .await
            .context(accept_error::H3ConnectSnafu)
            .map(Arc::new);

        self.insert(&name, result)
            .map(|connection| (connection, connected_server))
    }
}
