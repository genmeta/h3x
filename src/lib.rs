#![doc = include_str!("../README.md")]

mod common;
mod error;
pub mod pool;
mod protocol;

pub use common::message::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
pub use error::{Error, ErrorCode, Result};
pub use pool::Pool;
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
pub use common::{Read as R, Write as W, body::Body, wnd_buf::ArcWndBuf as WndBuf};

/// Outgoing request with explicit body storage.
pub type Request<B> = common::request::Request<W, B>;
/// Outgoing response with explicit body storage.
pub type Response<B> = common::response::Response<W, B>;
pub type IncomingRequest = common::Request<R>;
pub type IncomingResponse = common::Response<R>;
