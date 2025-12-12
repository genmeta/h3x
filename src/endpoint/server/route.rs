use std::sync::{Arc, RwLock};

use http::{Method, StatusCode};

use crate::endpoint::server::{
    BoxService, BoxServiceFuture, IntoBoxService, MethodRouter, Request, Response, Service,
    box_service,
};

async fn default_fallback(_request: Request, mut response: Response) {
    _ = async { response.set_status(StatusCode::NOT_FOUND)?.close().await }.await;
}

#[derive(Debug, Clone)]
struct Fallback<S>(Arc<RwLock<S>>);

impl<S> Fallback<S> {
    pub fn new(service: S) -> Self {
        Self(Arc::new(RwLock::new(service)))
    }

    pub fn set(&mut self, service: S) {
        *self.0.write().unwrap() = service;
    }

    pub fn get(&self) -> S
    where
        S: Clone,
    {
        self.0.read().unwrap().clone()
    }

    pub fn handle(&self, request: Request, response: Response) -> S::Future
    where
        S: Service + Clone,
    {
        self.get().handle(request, response)
    }
}

impl<S: Service + Clone> Service for Fallback<S> {
    type Future = S::Future;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        self.get().handle(request, response)
    }
}

#[derive(Debug, Clone)]
struct RouterInner {
    router: matchit::Router<BoxService>,
    fallback: Fallback<BoxService>, // Fal
}

impl Default for RouterInner {
    fn default() -> Self {
        Self {
            router: Default::default(),
            fallback: Fallback::new(box_service(default_fallback)),
        }
    }
}

impl RouterInner {
    fn route(&mut self, path: &str, service: impl IntoBoxService) {
        self.router
            .insert(path, service.into_box_service())
            .expect("Failed to register route");
    }

    pub fn on(&mut self, method: Method, path: &str, service: impl IntoBoxService) {
        match self.router.at_mut(path) {
            Ok(exist_service) => {
                if let Some(router) = exist_service
                    .value
                    .downcast_mut::<MethodRouter<BoxService>>()
                {
                    router.set(method, service.into_box_service());
                } else {
                    let fallback = exist_service.value.clone();
                    let mut router = MethodRouter::new(fallback);
                    router.set(method, service.into_box_service());
                    *exist_service.value = router.into_box_service();
                }
            }
            Err(..) => {
                let mut router = MethodRouter::new(self.fallback.clone().into_box_service());
                router.set(method, service.into_box_service());
                self.route(path, router)
            }
        }
    }

    fn handle(&self, request: Request, response: Response) -> BoxServiceFuture {
        let Some(path_and_query) = request.path() else {
            return self.fallback.clone().handle(request, response);
        };
        let Ok(endpoint) = self.router.at(path_and_query.path()) else {
            return self.fallback.clone().handle(request, response);
        };

        endpoint.value.clone().handle(request, response)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Router {
    inner: Arc<RouterInner>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    fn inner_ref(&self) -> &RouterInner {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut RouterInner {
        Arc::make_mut(&mut self.inner)
    }

    pub fn route(mut self, path: &str, service: impl IntoBoxService) -> Self {
        self.inner_mut().route(path, service.into_box_service());
        self
    }

    pub fn on(mut self, method: Method, path: &str, service: impl IntoBoxService) -> Self {
        self.inner_mut()
            .on(method, path, service.into_box_service());
        self
    }

    pub fn fallback(mut self, service: impl IntoBoxService) -> Self {
        self.inner_mut().fallback.set(service.into_box_service());
        self
    }

    pub fn options(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::OPTIONS, path, service)
    }
    pub fn get(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::GET, path, service)
    }
    pub fn post(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::POST, path, service)
    }
    pub fn put(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::PUT, path, service)
    }
    pub fn delete(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::DELETE, path, service)
    }
    pub fn head(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::HEAD, path, service)
    }
    pub fn trace(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::TRACE, path, service)
    }
    pub fn connect(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::CONNECT, path, service)
    }
    pub fn patch(self, path: &str, service: impl IntoBoxService) -> Self {
        self.on(Method::PATCH, path, service)
    }

    pub fn handle(&self, request: Request, response: Response) -> BoxServiceFuture {
        self.inner_ref().handle(request, response)
    }
}

impl Service for Router {
    type Future = BoxServiceFuture;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        Router::handle(self, request, response)
    }
}
