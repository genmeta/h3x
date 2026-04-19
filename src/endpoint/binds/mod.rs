//! Extended bind pattern for flexible BindUri generation.
//!
//! [`Bind`] is a pattern-like extension of
//! [`BindUri`](crate::dquic::qinterface::bind_uri::BindUri) that provides:
//!
//! 1. **Glob host** — `iface://v4.en*:8080` matches all interfaces starting with "en"
//! 2. **Omitted family** — `iface://enp17s0:8080` implies both V4 and V6
//! 3. **Omitted scheme** — `v4.enp17s0:8080` infers `iface://`, `127.0.0.1:8080` infers `inet://`
//! 4. **Omitted port** — `iface://v4.enp17s0` defaults to port 0 (system-assigned)
//! 5. **IPv6 bracket syntax** — `inet://[::1]:8080`, `[fe80::1]:443` (brackets required
//!    for IPv6 addresses with port, because `:` is a port separator)
//! 6. **Bare IP address** — `::1`, `::`, `127.0.0.1` are recognized directly as inet
//!    (no port, no path-and-query)
//!
//! All extensions compose freely: `en*:8080`, `*`, `v4.*:8080`, `[ew]*`, `[::1]:8080`, etc.

mod collection;
mod error;
mod host;
mod pattern;
pub mod setup;

pub use std::net::IpAddr;

pub use collection::Binds;
pub use error::BindConflictError;
pub use host::BindHost;
pub use pattern::Bind;
pub use setup::{
    BindSetup, setup_bind_interfaces, setup_bind_interfaces_with, watch_bind_interfaces,
};

#[cfg(test)]
mod tests;
