use std::any::Any;

use futures::future::BoxFuture;

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

trait CloneableService: Service + Any {
    fn clone_box(&self) -> Box<dyn CloneableService<Future = Self::Future> + Send + Sync>;
}

impl<H: Service + Any + Clone + Send + Sync> CloneableService for H {
    fn clone_box(&self) -> Box<dyn CloneableService<Future = Self::Future> + Send + Sync> {
        Box::new(self.clone())
    }
}

pub type BoxServiceFuture = BoxFuture<'static, ()>;

pub struct BoxService(Box<dyn CloneableService<Future = BoxServiceFuture> + Send + Sync>);

impl std::fmt::Debug for BoxService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoxService").finish()
    }
}

impl BoxService {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        (self.0.as_ref() as &dyn Any).downcast_ref()
    }

    pub fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        (self.0.as_mut() as &mut dyn Any).downcast_mut()
    }

    pub fn downcast<T: Any>(self) -> Result<Box<T>, BoxService> {
        match (self.0.as_ref() as &dyn Any).is::<T>() {
            // SAFETY: checked by is::<T>()
            true => Ok(unsafe { (self.0 as Box<dyn Any>).downcast().unwrap_unchecked() }),
            false => Err(self),
        }
    }
}

impl Service for BoxService {
    type Future = BoxServiceFuture;

    fn handle(&mut self, request: Request, response: Response) -> Self::Future {
        self.0.handle(request, response)
    }
}

impl Clone for BoxService {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

pub fn box_service<S>(service: S) -> BoxService
where
    S: Service<Future: Send + 'static> + Clone + Send + Sync + 'static,
{
    #[derive(Clone, Copy)]
    struct ErasedService<S>(S);

    impl<S: Service<Future: Send + 'static>> Service for ErasedService<S> {
        type Future = BoxServiceFuture;

        fn handle(&mut self, request: Request, response: Response) -> Self::Future {
            Box::pin(self.0.handle(request, response))
        }
    }

    BoxService(Box::new(ErasedService(service)))
}
