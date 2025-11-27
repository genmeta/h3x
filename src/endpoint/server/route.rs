use futures::future::BoxFuture;
use http::StatusCode;

use crate::endpoint::server::entity::{Request, Response};

pub trait Service {
    type Future: Future<Output = ()>;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future;
}

impl<Fn, Fut> Service for Fn
where
    Fn: FnMut(Request, Response) -> Fut,
    Fut: Future<Output = ()>,
{
    type Future = Fut;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        (self)(request, response)
    }
}

trait CloneableService: Service {
    fn clone_box(&self) -> Box<dyn CloneableService<Future = Self::Future> + Send + Sync>;
}

impl<H: Service + Clone + Send + Sync + 'static> CloneableService for H {
    fn clone_box(&self) -> Box<dyn CloneableService<Future = Self::Future> + Send + Sync> {
        Box::new(self.clone())
    }
}

type BoxHandleFuture = BoxFuture<'static, ()>;
type BoxService = Box<dyn CloneableService<Future = BoxHandleFuture> + Send + Sync>;

impl Clone for BoxService {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

async fn default_fallback(_request: Request, mut response: Response) {
    async { response.set_status(StatusCode::NOT_FOUND)?.close().await }.await;
}

#[derive(Debug, Clone, Copy)]
struct ErasedService<H>(H);

impl<H> ErasedService<H>
where
    H: Service<Future: Send + 'static> + Clone + Send + Sync + 'static,
{
    fn new(handle: H) -> Self {
        Self(handle)
    }

    fn boxed(self) -> BoxService {
        Box::new(self)
    }
}

impl<H: Service<Future: Send + 'static>> Service for ErasedService<H> {
    type Future = BoxHandleFuture;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        Box::pin(self.0.handle(request, response))
    }
}

#[derive(Clone)]
pub struct Router {
    router: matchit::Router<BoxService>,
    fallback: BoxService,
}

impl Router {
    pub fn register<H>(&mut self, path: &str, handler: H)
    where
        H: Service<Future: Send + 'static> + Clone + Send + Sync + 'static,
    {
        self.router
            .insert(path, ErasedService::new(handler).boxed())
            .expect("Failed to register route");
    }

    pub fn handle(&self, request: Request, response: Response) -> BoxHandleFuture {
        let Some(path_and_query) = request.path() else {
            return self.fallback.clone().handle(request, response);
        };
        let Ok(endpoint) = self.router.at(path_and_query.path()) else {
            return self.fallback.clone().handle(request, response);
        };

        endpoint.value.clone().handle(request, response)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self {
            router: Default::default(),
            fallback: ErasedService::new(default_fallback).boxed(),
        }
    }
}

impl Service for Router {
    type Future = BoxHandleFuture;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        Router::handle(self, request, response)
    }
}
