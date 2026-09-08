//! Native execution support. A WASM executor is deferred until a concrete host adapter exists.

pub trait MaybeSend: Send {}
impl<T: Send + ?Sized> MaybeSend for T {}
pub trait MaybeSync: Sync {}
impl<T: Sync + ?Sized> MaybeSync for T {}

pub(crate) use futures::future::BoxFuture;
#[cfg(feature = "webtransport")]
pub(crate) type KeepAlive = std::sync::Arc<dyn Send + Sync>;
