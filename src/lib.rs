#![doc = include_str!("../README.md")]

pub mod client;
mod common;
mod error;
pub mod pool;
mod protocol;
pub mod server;

pub use common::message::{
    ReadBody, ReadRequest, ReadResponse, ReadStream, WriteBody, WriteRequest, WriteResponse,
    WriteStream,
};
pub use error::{Error, ErrorCode, Result};
pub use pool::{Pool, PoolConfig, PoolError, PoolResult};
pub use protocol::{
    connection::{H3Connection, Settings},
    frame::Goaway,
    qpack::{ArcQpack, Qpack},
    stream::{read::H3ReadStream, write::H3WriteStream},
    transport::{Role, Transport},
};

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// Shared body storage, also available under its original ArcWndBuf name.
pub use common::wnd_buf::ArcWndBuf;
pub use common::{Protocol, Read as R, Write as W, body::Body, wnd_buf::ArcWndBuf as WndBuf};
