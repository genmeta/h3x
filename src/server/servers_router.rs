use std::{
    collections::HashMap,
    error::Error,
    task::{Context, Poll},
};

use futures::future::{self, BoxFuture};
use snafu::Snafu;

use crate::server::UnresolvedRequest;

#[derive(Debug, Clone, Snafu)]
#[snafu(visibility(pub))]
pub enum ServersRouterDispatchError {
    #[snafu(display("service not found for server name: {server_name}"))]
    MissingService { server_name: String },
}

#[derive(Debug, Clone)]
pub struct ServersRouter<S> {
    router: std::sync::Arc<HashMap<String, S>>,
}

impl<S> Default for ServersRouter<S> {
    fn default() -> Self {
        Self {
            router: Default::default(),
        }
    }
}

impl<S> ServersRouter<S> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains(&self, domain: &str) -> bool {
        self.router.contains_key(domain)
    }
}

impl<S: Clone> ServersRouter<S> {
    fn router_mut(&mut self) -> &mut HashMap<String, S> {
        std::sync::Arc::make_mut(&mut self.router)
    }

    pub fn insert(&mut self, domain: impl Into<String>, service: S) -> Option<S> {
        self.router_mut().insert(domain.into(), service)
    }

    pub fn serve(&mut self, domain: impl Into<String>, service: S) -> &mut Self {
        _ = self.insert(domain, service);
        self
    }
}

impl<S> tower_service::Service<UnresolvedRequest> for ServersRouter<S>
where
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    type Response = ();

    type Error = Box<dyn Error + Send + Sync>;

    type Future = BoxFuture<'static, Result<(), Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: UnresolvedRequest) -> Self::Future {
        let router = self.router.clone();
        Box::pin(async move {
            // Resolve the server name lazily from the connection instead of
            // carrying it on `UnresolvedRequest`. The local agent watch is
            // already populated by the time the first request arrives, so
            // this is effectively a clone.
            let local_agent = match req.connection.local_agent().await {
                Ok(Some(agent)) => agent,
                Ok(None) => {
                    return Err(ServersRouterDispatchError::MissingService {
                        server_name: String::new(),
                    }
                    .into());
                }
                Err(error) => return Err(Box::new(error) as _),
            };
            let server_name = local_agent.name().to_string();
            let Some(mut service) = router.get(server_name.as_str()).cloned() else {
                return Err(ServersRouterDispatchError::MissingService { server_name }.into());
            };

            future::poll_fn(|cx| service.poll_ready(cx))
                .await
                .map_err(Into::into)?;
            service.call(req).await.map_err(Into::into)
        })
    }
}
