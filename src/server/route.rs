use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use http::{Method, StatusCode};

use crate::server::{
    BoxService, BoxServiceFuture, IntoBoxService, Request, Response, Service, box_service,
};

#[tracing::instrument(skip_all)]
pub async fn default_fallback(_request: &mut Request, response: &mut Response) {
    _ = response.set_status(StatusCode::NOT_FOUND)
}

#[derive(Debug, Clone)]
struct Fallback(Arc<RwLock<BoxService>>);

impl Fallback {
    pub fn new(service: BoxService) -> Self {
        Self(Arc::new(RwLock::new(service)))
    }

    pub fn set(&mut self, service: BoxService) {
        *self.0.write().unwrap() = service;
    }
}

impl Service for Fallback {
    type Future<'s> = BoxServiceFuture<'s>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        self.0.read().unwrap().serve(request, response)
    }
}

#[derive(Debug, Clone)]
struct RouterInner {
    router: matchit::Router<BoxService>,
    fallback: Fallback,
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

    fn serve<'s>(
        &self,
        request: &'s mut Request,
        response: &'s mut Response,
    ) -> BoxServiceFuture<'s> {
        let Some(path_and_query) = request.path() else {
            return self.fallback.serve(request, response);
        };
        let Ok(endpoint) = self.router.at(path_and_query.path()) else {
            return self.fallback.serve(request, response);
        };

        endpoint.value.serve(request, response)
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

    pub fn serve<'s>(
        &self,
        request: &'s mut Request,
        response: &'s mut Response,
    ) -> BoxServiceFuture<'s> {
        self.inner_ref().serve(request, response)
    }
}

impl Service for Router {
    type Future<'s> = BoxServiceFuture<'s>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        Router::serve(self, request, response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRouter<S> {
    // most used methods are stored separately for faster access
    options: Option<S>,
    get: Option<S>,
    post: Option<S>,
    put: Option<S>,
    delete: Option<S>,
    head: Option<S>,
    trace: Option<S>,
    connect: Option<S>,
    patch: Option<S>,
    // other
    extensions: HashMap<Method, S>,
    // fallback service when no method match
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
            extensions: HashMap::new(),
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
            _ => self.extensions.get(&method),
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
            _ => self.extensions.get_mut(&method),
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
            _ => _ = self.extensions.insert(method, service),
        }
    }

    pub fn set_fallback(&mut self, service: S) {
        self.fallback = service;
    }
}

impl<S> Service for MethodRouter<S>
where
    S: Clone + for<'s> Service<Future<'s>: Send> + Send + 'static,
{
    type Future<'s> = BoxServiceFuture<'s>;

    fn serve<'s>(
        &self,
        request: &'s mut super::Request,
        response: &'s mut super::Response,
    ) -> Self::Future<'s> {
        let method = request.method();
        let service = match method {
            Method::OPTIONS => self.options.as_ref().unwrap_or(&self.fallback),
            Method::GET => self.get.as_ref().unwrap_or(&self.fallback),
            Method::POST => self.post.as_ref().unwrap_or(&self.fallback),
            Method::PUT => self.put.as_ref().unwrap_or(&self.fallback),
            Method::DELETE => self.delete.as_ref().unwrap_or(&self.fallback),
            Method::HEAD => self.head.as_ref().unwrap_or(&self.fallback),
            Method::TRACE => self.trace.as_ref().unwrap_or(&self.fallback),
            Method::CONNECT => self.connect.as_ref().unwrap_or(&self.fallback),
            Method::PATCH => self.patch.as_ref().unwrap_or(&self.fallback),
            _ => self.extensions.get(&method).unwrap_or(&self.fallback),
        }
        .clone();
        Box::pin(async move { service.serve(request, response).await })
    }
}
