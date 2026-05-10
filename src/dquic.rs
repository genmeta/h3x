pub mod binds;
mod endpoint;
pub mod identity;
pub mod network;
pub mod quic_config;
pub mod sni;

mod shim;

pub use dquic::*;
pub use endpoint::*;
pub use identity::*;
pub use network::*;
pub use quic_config::*;

/// Type alias for the default `H3Endpoint<QuicEndpoint>`.
pub type H3Endpoint = crate::endpoint::H3Endpoint<QuicEndpoint>;
