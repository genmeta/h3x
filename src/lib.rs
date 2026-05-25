#![doc = include_str!("../README.md")]

pub mod buflist;
pub mod codec;
pub mod connection;
pub mod dhttp;
pub mod error;
pub mod extended_connect;
pub mod message;
pub mod pool;
pub mod protocol;
pub mod qpack;
pub mod quic;
pub mod stream_id;
mod util;
pub mod varint;

#[cfg(feature = "dquic")]
pub mod dquic;

pub mod endpoint;
pub mod server;

#[cfg(feature = "hyper")]
pub mod hyper;

#[cfg(feature = "ipc")]
pub mod ipc;

#[cfg(feature = "rpc")]
pub mod rpc;

#[cfg(feature = "webtransport")]
pub mod webtransport;
