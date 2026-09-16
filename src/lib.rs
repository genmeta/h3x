#![doc = include_str!("../README.md")]

pub mod client;
mod common;
mod error;
mod protocol;
pub mod server;

pub use common::message::{
    ReadBody, ReadRequest, ReadResponse, ReadStream, WriteBody, WriteRequest, WriteResponse,
    WriteStream,
};
pub use error::{ErrorCode, Result};
pub use protocol::{
    connection::{H3Connection, Settings},
    frame::Goaway,
    qpack::Qpack,
    stream::{read::H3ReadStream, write::H3WriteStream},
    transport::{Role, Transport},
};

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";

#[cfg(test)]
extern crate self as h3x;
#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

/// Shared body storage, also available under its original ArcWndBuf name.
pub use common::wnd_buf::ArcWndBuf;
pub use common::{Read as R, Write as W, body::Body, wnd_buf::ArcWndBuf as WndBuf};
