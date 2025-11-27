use std::{collections::HashMap, sync::Arc};

use tokio::task::JoinSet;

use crate::{
    connection::Connection,
    endpoint::{
        pool::{AcceptError, Pool},
        server::entity::UnresolvedRequest,
    },
    quic::{self},
};

mod entity;
mod route;

pub struct Server<L: quic::Listen> {
    acceptor: L,
    pool: Arc<Pool<L::Connection>>,
    router: HashMap<String, route::Router>,
}

impl<L: quic::Listen> Server<L> {
    pub fn new(acceptor: L, pool: Arc<Pool<L::Connection>>) -> Self {
        Self {
            acceptor,
            pool,
            router: HashMap::new(),
        }
    }

    pub fn register(&mut self, domain: impl Into<String>, router: route::Router) -> &mut Self {
        self.router.insert(domain.into(), router);
        self
    }

    pub async fn run(&self) -> Result<(), L::Error>
    where
        L::Connection: Send + 'static,
        <L::Connection as quic::ManageStream>::StreamReader: Send,
        <L::Connection as quic::ManageStream>::StreamWriter: Send,
    {
        struct AbortAllOnDropSet<T: 'static>(JoinSet<T>);

        impl<T: 'static> Default for AbortAllOnDropSet<T> {
            fn default() -> Self {
                Self(JoinSet::new())
            }
        }

        impl<T: 'static> std::ops::Deref for AbortAllOnDropSet<T> {
            type Target = JoinSet<T>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T: 'static> std::ops::DerefMut for AbortAllOnDropSet<T> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<T: 'static> Drop for AbortAllOnDropSet<T> {
            fn drop(&mut self) {
                self.0.abort_all();
            }
        }

        let mut tasks = AbortAllOnDropSet::default();
        let router = Arc::new(self.router.clone());

        let mut spawn_route_task = |connection: Arc<Connection<_>>, connected_server: String| {
            let router = router.clone();
            tasks.spawn(async move {
                let Some(router) = router.get(&connected_server) else {
                    todo!("fallback: connected server not exist");
                };
                while let Ok((rs, ws)) = connection.accept_request_stream().await
                    && let Ok((req, rsp)) = UnresolvedRequest::new(rs, ws).resolve().await
                {
                    router.handle(req, rsp).await;
                }
            });
        };

        loop {
            match self.pool.accept_one(&self.acceptor).await {
                Ok((connection, connected_server)) => {
                    spawn_route_task(connection, connected_server)
                }
                Err(AcceptError::QuicConnect { source }) => return Err(source),
                Err(_) => { /* Ignore other errors  */ }
            }
        }
    }
}
