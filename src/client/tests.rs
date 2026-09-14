use std::io::Cursor;

use http::{HeaderValue, Method, header};
use tokio::io::{AsyncReadExt, duplex};

use super::*;
use crate::{
    ReadStream,
    common::message::{ReadResponse, WriteRequest, WriteStream},
    protocol::qpack::{self, WriteFieldSection},
};

mod request;
mod response;
