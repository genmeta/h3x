#![doc = include_str!("../README.md")]

mod common;
pub(crate) mod connection;
mod error;
pub(crate) mod frame;
pub mod pool;
pub(crate) mod qpack;
pub(crate) mod stream;
pub(crate) mod transport;

pub use common::{
    request::{ReadRequest, WriteRequest},
    response::{ReadResponse, WriteResponse},
};
pub use connection::{H3Connection, Settings};
pub use error::{Error, ErrorCode, Result};
pub use frame::Goaway;
pub use pool::Pool;
pub use qpack::{ArcQpack, Qpack};
pub use stream::{read::H3ReadStream, write::H3WriteStream};
pub use transport::{Role, Transport};

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// Shared body storage, also available under its original ArcWndBuf name.
pub use common::wnd_buf::ArcWndBuf;
pub use common::{
    Read as R, Write as W, request::Request, response::Response, wnd_buf::ArcWndBuf as WndBuf,
};
