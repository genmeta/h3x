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
pub use connection::{H3Connection, Settings, UnreusableCallback};
pub use error::{Error, ErrorCode, ErrorDetail, Result};
pub use frame::Goaway;
pub use pool::Pool;
pub use qpack::{ArcQpack, Qpack};
pub use stream::{read::H3ReadStream, write::H3WriteStream};
pub use transport::{Role, Transport, TransportError};

/// SETTINGS identifier for the peer's QPACK dynamic-table capacity, in bytes.
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY as u64;
/// SETTINGS identifier for the peer's maximum uncompressed field-section size.
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = frame::SETTINGS_MAX_FIELD_SECTION_SIZE as u64;
/// SETTINGS identifier for the peer's limit on QPACK-blocked streams.
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = frame::SETTINGS_QPACK_BLOCKED_STREAMS as u64;
/// SETTINGS identifier advertising Extended CONNECT support when its value is 1.
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = frame::SETTINGS_ENABLE_CONNECT_PROTOCOL as u64;

/// ALPN token used by HTTP/3.
pub const ALPN: &[u8] = b"h3";

/// Shared body storage, also available under its original ArcWndBuf name.
pub use common::wnd_buf::ArcWndBuf;
pub use common::{trailers::Trailers, wnd_buf::ArcWndBuf as WndBuf};

pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, BoxError>;
