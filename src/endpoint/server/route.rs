use std::sync::Arc;

use http::StatusCode;

use crate::endpoint::server::{
    entity::{Request, Response},
    service::{BoxService, BoxServiceFuture, IntoBoxService, Service, box_service},
};

async fn default_fallback(_request: Request, mut response: Response) {
    _ = async { response.set_status(StatusCode::NOT_FOUND)?.close().await }.await;
}

#[derive(Debug, Clone)]
struct RouterInner {
    router: matchit::Router<BoxService>,
    fallback: BoxService,
}

impl Default for RouterInner {
    fn default() -> Self {
        Self {
            router: Default::default(),
            fallback: box_service(default_fallback),
        }
    }
}

impl RouterInner {
    fn route(&mut self, path: &str, service: impl IntoBoxService) {
        self.router
            .insert(path, service.into_box_service())
            .expect("Failed to register route");
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

    pub fn fallback(mut self, service: impl IntoBoxService) -> Self {
        self.inner_mut().fallback = service.into_box_service();
        self
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
