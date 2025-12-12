use std::collections::HashMap;

use http::Method;

use crate::endpoint::server::Service;

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

    fn handle(&mut self, request: super::Request, response: super::Response) -> Self::Future {
        match self.service_mut(request.method()) {
            Some(service) => service.handle(request, response),
            None => self.fallback.handle(request, response),
        }
    }
}
