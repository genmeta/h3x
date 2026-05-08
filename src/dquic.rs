#[cfg(feature = "dquic")]
mod endpoint;
#[cfg(feature = "dquic")]
pub mod network;
#[cfg(feature = "dquic")]
pub mod identity;
#[cfg(feature = "dquic")]
pub mod sni;
#[cfg(feature = "dquic")]
pub mod quic_config;
#[cfg(feature = "dquic")]
pub mod binds;

mod shim;

pub use dquic::*;
#[cfg(feature = "dquic")]
pub use endpoint::*;
#[cfg(feature = "dquic")]
pub use identity::*;
#[cfg(feature = "dquic")]
pub use network::*;
#[cfg(feature = "dquic")]
pub use quic_config::*;

use std::error::Error;

use tower_service::Service;

use crate::endpoint::server::UnresolvedRequest;

/// Type alias for the default `H3Endpoint<QuicEndpoint>`.
#[cfg(feature = "dquic")]
pub type H3Endpoint = crate::endpoint::H3Endpoint<QuicEndpoint>;

#[cfg(feature = "dquic")]
impl crate::endpoint::H3Endpoint<QuicEndpoint> {
    /// Serve HTTP/3 requests on `&self`, constructing a temporary
    /// `H3Endpoint<&QuicEndpoint>` internally to drive the generic
    /// [`serve_inner(&mut self)`] path.
    ///
    /// [`serve_inner(&mut self)`]: crate::endpoint::H3Endpoint::serve_inner
    pub async fn serve<S>(&self, service: S) -> Result<(), crate::dquic::endpoint::AcceptError>
    where
        S: Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
        S::Future: Send,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut ref_ep = crate::endpoint::H3Endpoint::new(
            &self.quic,
            self.pool.clone(),
            self.builder.clone(),
        );
        ref_ep.serve_inner(service).await
    }
}
