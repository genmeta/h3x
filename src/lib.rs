#![doc = include_str!("../README.md")]

pub mod agent;
pub mod buflist;
pub mod client;
pub mod codec;
pub mod connection;
pub mod error;
pub mod frame;
pub mod message;
pub mod pool;
pub mod qpack;
pub mod quic;
pub mod server;
mod util;
pub mod varint;

#[cfg(feature = "gm-quic")]
pub mod gm_quic;
