#![doc = include_str!("../README.md")]

pub mod client;
mod common;
mod error;
mod protocol;
pub mod server;
mod wnd_buf;

pub use common::message::{
    ReadBody, ReadRequest, ReadResponse, ReadStream, WriteBody, WriteRequest, WriteResponse,
    WriteStream,
};
pub use error::{Error, Result};
pub use protocol::{
    frame::Goaway,
    qpack::Qpack,
    stream::{read::H3ReadStream, write::H3WriteStream},
};
pub use wnd_buf::ArcWndBuf;

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";
