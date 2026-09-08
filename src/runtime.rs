#[cfg(not(target_arch = "wasm32"))]
mod dquic;
pub(crate) mod identity;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
pub mod pool;
#[cfg(not(target_arch = "wasm32"))]
pub use dquic::DquicTransport;
#[cfg(not(target_arch = "wasm32"))]
pub use native::{Connection, Runtime, init, shutdown};
#[cfg(not(target_arch = "wasm32"))]
pub use pool::Pool;

#[cfg(not(target_arch = "wasm32"))]
mod tasks;
