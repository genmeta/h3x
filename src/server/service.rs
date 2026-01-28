use std::any::Any;

use futures::future::BoxFuture;

use crate::server::{Request, Response};

pub trait Service {
    type Future<'s>: Future<Output = ()>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s>;
}

/// A helper trait to allow using async closures as services.
pub trait ServiceFn<'s> {
    type Future: Future<Output = ()> + 's;

    fn call(&self, req: &'s mut Request, res: &'s mut Response) -> Self::Future;
}

impl<'s, F, Fut> ServiceFn<'s> for F
where
    F: Fn(&'s mut Request, &'s mut Response) -> Fut,
    Fut: Future<Output = ()> + Send + 's,
{
    type Future = Fut;

    fn call(&self, req: &'s mut Request, res: &'s mut Response) -> Self::Future {
        (self)(req, res)
    }
}

impl<S> Service for S
where
    S: for<'s> ServiceFn<'s>,
{
    type Future<'s> = <S as ServiceFn<'s>>::Future;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        self.call(request, response)
    }
}

trait CloneableService: Any {
    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> BoxFuture<'s, ()>;

    fn clone_box(&self) -> Box<dyn CloneableService + Send + Sync>;
}

impl<H: for<'s> Service<Future<'s>: Send> + Any + Clone + Send + Sync> CloneableService for H {
    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> BoxFuture<'s, ()> {
        Box::pin(self.serve(request, response))
    }

    fn clone_box(&self) -> Box<dyn CloneableService + Send + Sync> {
        Box::new(self.clone())
    }
}

pub trait IntoBoxService:
    for<'s> Service<Future<'s>: Send> + Clone + Send + Sync + 'static
{
    fn into_box_service(self) -> BoxService {
        BoxService(Box::new(self))
    }
}

impl<S: for<'s> Service<Future<'s>: Send> + Clone + Send + Sync + 'static> IntoBoxService for S {}

pub type BoxServiceFuture<'s> = BoxFuture<'s, ()>;
type DynService = dyn CloneableService + Send + Sync;

pub struct BoxService(Box<DynService>);

impl std::fmt::Debug for BoxService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoxService").finish()
    }
}

impl BoxService {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        (self.0.as_ref() as &dyn Any).downcast_ref::<T>()
    }

    pub fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        (self.0.as_mut() as &mut dyn Any).downcast_mut::<T>()
    }

    pub fn downcast<T: Any>(self) -> Result<Box<T>, BoxService> {
        match (self.0.as_ref() as &dyn Any).is::<T>() {
            true => {
                // SAFETY: checked by is::<T>()
                Ok(unsafe { (self.0 as Box<dyn Any>).downcast::<T>().unwrap_unchecked() })
            }
            false => Err(self),
        }
    }
}

impl Service for BoxService {
    type Future<'s> = BoxServiceFuture<'s>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        self.0.serve(request, response)
    }
}

impl Clone for BoxService {
    fn clone(&self) -> Self {
        Self(self.0.clone_box())
    }
}

pub fn box_service(service: impl IntoBoxService) -> BoxService {
    service.into_box_service()
}
