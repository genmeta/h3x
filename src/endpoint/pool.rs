use std::{
    error::Error,
    pin::pin,
    sync::{Arc, LazyLock, Mutex as SyncMutex},
};

use dashmap::DashMap;
use futures::StreamExt;
use snafu::{ResultExt, Snafu};
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
        let connection = self.peek();
        // TDOO: check whether the connection is still valid
        connection
    }

    pub async fn reuse_or_initial<E>(
        &self,
        mut try_initial: impl AsyncFnMut() -> Result<Arc<Connection<C>>, E>,
    ) -> Result<Arc<Connection<C>>, E> {
        if let Some(connection) = self.reuse() {
            return Ok(connection);
        }

        let mut connections = pin!(self.connection.watch());

        loop {
            tokio::select! {
                biased;
                _guard = self.connect.lock() => {
                    // its ok to replace the connection, reference of replaced connection still in task until closed
                    self.connection.set(try_initial().await?);
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

type ConnectionIdentifier = (String, Arc<Settings>);

#[derive(Debug)]
pub struct Pool<C: quic::Connection> {
    connections: Arc<DashMap<ConnectionIdentifier, ReuseableConnection<C>>>,
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
        Self::global().clone()
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ConnectError<E: Error + 'static> {
    #[snafu(display("Failed to initial QUIC connection"))]
    Connector { source: E },
    #[snafu(transparent)]
    H3 { source: quic::ConnectionError },
    #[snafu(display("Peer name mismatch: expected {expected}, actual {actual}"))]
    IncorrectIdentify { expected: String, actual: String },
}

impl<C: quic::Connection> Pool<C> {
    pub async fn reuse_or_connect_with<E: Error + 'static>(
        &self,
        peer_name: &str,
        settings: Arc<Settings>,
        mut connector: impl AsyncFnMut(&str) -> Result<C, E>,
    ) -> Result<Arc<Connection<C>>, ConnectError<E>> {
        let peer_name = peer_name.to_string();
        let result = self
            .connections
            .entry((peer_name.clone(), settings.clone()))
            .or_insert_with(ReuseableConnection::pending)
            .downgrade()
            .reuse_or_initial(async || {
                let connection = (connector)(&peer_name)
                    .await
                    .context(connect_error::ConnectorSnafu)?;
                let connection = Connection::new(settings.clone(), connection).await?;
                let actual_peer_name = connection.peer_name().await?;
                if actual_peer_name != peer_name {
                    return connect_error::IncorrectIdentifySnafu {
                        expected: peer_name.to_string(),
                        actual: actual_peer_name,
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
                    connections.remove_if(&(peer_name, settings), |_, connection| {
                        connection.reuse().is_none()
                    });
                });
            }
            Err(..) => {
                self.connections
                    .remove_if(&(peer_name, settings), |_, connection| {
                        connection.peek().is_none()
                    });
            }
        }

        result
    }

    pub async fn try_insert<E>(
        &self,
        connection: Arc<Connection<C>>,
    ) -> Result<(), quic::ConnectionError> {
        let peer_name = connection.peer_name().await?;
        let settings = connection.settings().clone();
        self.connections
            .entry((peer_name, settings))
            .or_insert(ReuseableConnection::with(connection));
        Ok(())
    }
}
