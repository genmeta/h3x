use std::any::Any;

use futures::future::BoxFuture;

use crate::server::{Request, Response};

pub trait Service {
    type Future: Future<Output = ()>;

    fn serve(&mut self, request: Request, response: Response) -> Self::Future;
}

impl<Fn, Fut> Service for Fn
where
    Fn: FnMut(Request, Response) -> Fut,
    Fut: Future<Output = ()>,
{
    type Future = Fut;

    fn serve(&mut self, request: Request, response: Response) -> Self::Future {
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

pub trait IntoBoxService: Service<Future: Send + 'static> + Clone + Send + Sync + 'static {
    fn into_box_service(self) -> BoxService {
        box_service(self)
    }
}

impl<S: Service<Future: Send + 'static> + Clone + Send + Sync + 'static> IntoBoxService for S {}

pub type BoxServiceFuture = BoxFuture<'static, ()>;
type DynService = dyn CloneableService<Future = BoxServiceFuture> + Send + Sync;

// transparent wrapper to erase the concrete type of Service
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ErasedService<S: ?Sized>(S);

impl<S: Service<Future: Send + 'static> + ?Sized> Service for ErasedService<S> {
    type Future = BoxServiceFuture;

    #[inline]
    fn serve(&mut self, request: Request, response: Response) -> Self::Future {
        Box::pin(self.0.serve(request, response))
    }
}

pub struct BoxService(Box<DynService>);

impl std::fmt::Debug for BoxService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BoxService").finish()
    }
}

impl BoxService {
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        (self.0.as_ref() as &dyn Any)
            .downcast_ref::<ErasedService<T>>()
            .map(|ErasedService(s)| s)
    }

    pub fn downcast_mut<T: Any>(&mut self) -> Option<&mut T> {
        (self.0.as_mut() as &mut dyn Any)
            .downcast_mut::<ErasedService<T>>()
            .map(|ErasedService(s)| s)
    }

    pub fn downcast<T: Any>(self) -> Result<Box<T>, BoxService> {
        match (self.0.as_ref() as &dyn Any).is::<ErasedService<T>>() {
            true => {
                // SAFETY: checked by is::<T>()
                let erased_service = unsafe {
                    (self.0 as Box<dyn Any>)
                        .downcast::<ErasedService<T>>()
                        .unwrap_unchecked()
                };
                // SAFETY: ErasedService<T> is a transparent wrapper around T
                Ok(unsafe { std::mem::transmute::<Box<ErasedService<T>>, Box<T>>(erased_service) })
            }
            false => Err(self),
        }
    }
}

impl Service for BoxService {
    type Future = BoxServiceFuture;

    fn serve(&mut self, request: Request, response: Response) -> Self::Future {
        self.0.serve(request, response)
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
    BoxService(Box::new(ErasedService(service)))
}
