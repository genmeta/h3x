use std::{
    collections::hash_map::DefaultHasher,
    error::Error,
    hash::{Hash, Hasher},
    pin::pin,
    sync::{Arc, LazyLock},
};

use dashmap::DashMap;
use futures::{StreamExt, never::Never};
use http::uri::Authority;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use crate::{
    connection::{Connection, ConnectionBuilder},
    quic,
    util::watch::Watch,
};

#[derive(Debug)]
pub struct ReuseableConnection<C: quic::Connection> {
    connection: Watch<Arc<Connection<C>>>,
    task: AsyncMutex<Option<AbortOnDropHandle<()>>>,
}

type ConnectionIdentifier = (Authority, u64);
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
        // proactively check if the QUIC connection is still alive
        if connection.check().is_err() {
            return None;
        }
        if connection.peek_peer_goaway().is_some() {
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
    #[snafu(display("failed to initialize QUIC connection"))]
    Connector { source: E },
    #[snafu(transparent)]
    H3 { source: quic::ConnectionError },
    #[snafu(display("peer name mismatch: expected {expected}, actual {}", match actual {
        Some(name) => name,
        None => "<anonymous>", 
    }))]
    IncorrectIdentity {
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
    MissingIdentity,
    #[snafu(display("peer provided invalid identity (cannot be parsed as Authority)"))]
    InvalidIdentity,
}

impl<C: quic::Connection> Pool<C> {
    fn spawn_try_release(self, identify: ConnectionIdentifier) {
        tokio::spawn(
            async move {
                (self.connections.as_ref())
                    .remove_if(&identify, |_, connection| connection.reuse().is_none());
            }
            .in_current_span(),
        );
    }

    #[tracing::instrument(level = "debug", skip(self, connector), err)]
    pub async fn reuse_or_connect_with<Client>(
        &self,
        connector: &Client,
        builder: Arc<ConnectionBuilder<C>>,
        server: Authority,
    ) -> Result<Arc<Connection<C>>, ConnectError<Client::Error>>
    where
        Client: quic::Connect<Connection = C>,
    {
        let builder_hash = {
            let mut hasher = DefaultHasher::new();
            builder.hash(&mut hasher);
            Hasher::finish(&hasher)
        };
        let reuseable_connection = self
            .connections
            .entry((server.clone(), builder_hash))
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
                    let connection = builder.build(quic_conn).await?;

                    tracing::debug!("H3 connection established, verifying peer identity");
                    let remote_agent = connection.remote_agent().await?;
                    let actual_peer_name = remote_agent.as_ref().map(|agent| agent.name());
                    if actual_peer_name.as_ref() != Some(&server.host()) {
                        return connect_error::IncorrectIdentitySnafu {
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
                        async move {
                            connection.closed().await;
                            pool.spawn_try_release((server, builder_hash));
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
            Err(..) => self.clone().spawn_try_release((server, builder_hash)),
        }

        result
    }

    pub async fn try_insert(
        &self,
        connection: Arc<Connection<C>>,
        builder_hash: u64,
    ) -> Result<(), InsertError> {
        let remote_agent = connection
            .remote_agent()
            .await?
            .context(insert_error::MissingIdentitySnafu)?;

        let client = remote_agent
            .name()
            .parse()
            .ok()
            .context(insert_error::InvalidIdentitySnafu)?;

        let identity = (client, builder_hash);
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    #[cfg(feature = "gm-quic")]
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use tokio_util::task::AbortOnDropHandle;

    use super::ReuseableConnection;
    #[cfg(feature = "gm-quic")]
    use crate::{
        connection::ConnectionBuilder,
        dhttp::settings::{Setting, Settings},
    };
    use crate::{
        connection::{Connection, ConnectionState},
        dhttp::{goaway::Goaway, protocol::DHttpProtocol},
        quic,
        varint::VarInt,
    };

    #[cfg(feature = "gm-quic")]
    fn hash_of<T: Hash>(val: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        val.hash(&mut hasher);
        hasher.finish()
    }

    #[cfg(feature = "gm-quic")]
    type C = gm_quic::prelude::Connection;

    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_different_builders_different_entries() {
        let s1 = Arc::new(Settings::default());
        let mut s2_inner = Settings::default();
        s2_inner.set(Setting::max_field_section_size(VarInt::from_u32(9999)));
        let s2 = Arc::new(s2_inner);

        let builder_a = ConnectionBuilder::<C>::new(s1);
        let builder_b = ConnectionBuilder::<C>::new(s2);

        let key_a = hash_of(&builder_a);
        let key_b = hash_of(&builder_b);
        assert_ne!(
            key_a, key_b,
            "different protocol stacks must produce different pool keys"
        );
    }

    #[cfg(feature = "gm-quic")]
    #[test]
    fn pool_key_same_builder_same_entry() {
        let s = Arc::new(Settings::default());
        let builder_a = ConnectionBuilder::<C>::new(s.clone());
        let builder_b = ConnectionBuilder::<C>::new(s);

        let key_a = hash_of(&builder_a);
        let key_b = hash_of(&builder_b);
        assert_eq!(
            key_a, key_b,
            "identical protocol stacks must produce the same pool key"
        );
    }

    fn test_connection_error(reason: &str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.to_owned().into(),
            },
        }
    }

    fn abort_handle() -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async {}))
    }

    async fn reusable_connection(
        connection: Connection<crate::connection::tests::MockConnection>,
    ) -> Arc<ReuseableConnection<crate::connection::tests::MockConnection>> {
        let reusable = Arc::new(ReuseableConnection::pending());
        reusable.insert(Arc::new(connection), abort_handle()).await;
        reusable
    }

    #[tokio::test]
    async fn reuse_returns_none_when_connection_is_unhealthy() {
        let quic = crate::connection::tests::MockConnection::new();
        quic.set_check_result(Err(test_connection_error("broken")));

        let state = ConnectionState::new_for_test(
            Arc::new(quic),
            Arc::new(crate::protocol::Protocols::new()),
        );
        let reusable = reusable_connection(Connection::from_state_for_test(state)).await;

        assert!(reusable.reuse().is_none());
    }

    #[tokio::test]
    async fn pool_reuse_returns_none_after_peer_goaway_observed() {
        let quic = crate::connection::tests::MockConnection::new();
        quic.set_check_result(Ok(()));

        let protocols = {
            let mut protocols = crate::protocol::Protocols::new();
            protocols.insert(DHttpProtocol::new_for_test(Arc::new(quic.clone())));
            Arc::new(protocols)
        };
        let state = ConnectionState::new_for_test(Arc::new(quic), protocols);
        let dhttp = state.dhttp();
        dhttp.peer_goaway.set(Goaway::new(VarInt::from_u32(123)));

        let reusable = reusable_connection(Connection::from_state_for_test(state)).await;
        assert!(reusable.reuse().is_none());
    }
}
