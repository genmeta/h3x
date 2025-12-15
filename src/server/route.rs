use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use http::{Method, StatusCode};

use crate::server::{
    BoxService, BoxServiceFuture, IntoBoxService, Request, Response, Service, box_service,
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

    pub fn serve(&self, request: Request, response: Response) -> S::Future
    where
        S: Service + Clone,
    {
        self.get().serve(request, response)
    }
}

impl<S: Service + Clone> Service for Fallback<S> {
    type Future = S::Future;

    fn serve(&mut self, request: Request, response: Response) -> Self::Future {
        self.get().serve(request, response)
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

    fn serve(&self, request: Request, response: Response) -> BoxServiceFuture {
        let Some(path_and_query) = request.path() else {
            return self.fallback.clone().serve(request, response);
        };
        let Ok(endpoint) = self.router.at(path_and_query.path()) else {
            return self.fallback.clone().serve(request, response);
        };

        endpoint.value.clone().serve(request, response)
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

    pub fn serve(&self, request: Request, response: Response) -> BoxServiceFuture {
        self.inner_ref().serve(request, response)
    }
}

impl Service for Router {
    type Future = BoxServiceFuture;

    fn serve(&mut self, request: Request, response: Response) -> Self::Future {
        Router::serve(self, request, response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRouter<S> {
    options: Option<S>,
    get: Option<S>,
    post: Option<S>,
    put: Option<S>,
    delete: Option<S>,
    head: Option<S>,
    trace: Option<S>,
    connect: Option<S>,
    patch: Option<S>,
    extension: HashMap<Method, S>,
    fallback: S,
}

impl<S> MethodRouter<S> {
    pub fn new(fallback: S) -> Self {
        Self {
            options: None,
            get: None,
            post: None,
            put: None,
            delete: None,
            head: None,
            trace: None,
            connect: None,
            patch: None,
            extension: HashMap::new(),
            fallback,
        }
    }

    pub fn service(&self, method: Method) -> Option<&S> {
        match method {
            Method::OPTIONS => self.options.as_ref(),
            Method::GET => self.get.as_ref(),
            Method::POST => self.post.as_ref(),
            Method::PUT => self.put.as_ref(),
            Method::DELETE => self.delete.as_ref(),
            Method::HEAD => self.head.as_ref(),
            Method::TRACE => self.trace.as_ref(),
            Method::CONNECT => self.connect.as_ref(),
            Method::PATCH => self.patch.as_ref(),
            _ => self.extension.get(&method),
        }
    }

    pub fn service_mut(&mut self, method: Method) -> Option<&mut S> {
        match method {
            Method::OPTIONS => self.options.as_mut(),
            Method::GET => self.get.as_mut(),
            Method::POST => self.post.as_mut(),
            Method::PUT => self.put.as_mut(),
            Method::DELETE => self.delete.as_mut(),
            Method::HEAD => self.head.as_mut(),
            Method::TRACE => self.trace.as_mut(),
            Method::CONNECT => self.connect.as_mut(),
            Method::PATCH => self.patch.as_mut(),
            _ => self.extension.get_mut(&method),
        }
    }

    pub fn set(&mut self, method: Method, service: S) {
        match method {
            Method::OPTIONS => self.options = Some(service),
            Method::GET => self.get = Some(service),
            Method::POST => self.post = Some(service),
            Method::PUT => self.put = Some(service),
            Method::DELETE => self.delete = Some(service),
            Method::HEAD => self.head = Some(service),
            Method::TRACE => self.trace = Some(service),
            Method::CONNECT => self.connect = Some(service),
            Method::PATCH => self.patch = Some(service),
            _ => _ = self.extension.insert(method, service),
        }
    }

    pub fn set_fallback(&mut self, service: S) {
        self.fallback = service;
    }
}

impl<S> Service for MethodRouter<S>
where
    S: Service,
{
    type Future = S::Future;

    fn serve(&mut self, request: super::Request, response: super::Response) -> Self::Future {
        match self.service_mut(request.method()) {
            Some(service) => service.serve(request, response),
            None => self.fallback.serve(request, response),
        }
    }
}
