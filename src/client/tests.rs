use std::{io::Cursor, sync::Arc};

use http::{HeaderValue, Method, header};
use tokio::io::{AsyncReadExt, duplex};

use super::*;
use crate::{
    ReadStream,
    common::message::{ReadResponse, WriteRequest, WriteStream},
    protocol::qpack::{self, ArcQpack, WriteFieldSection},
};

mod errors;
mod lifecycle;
mod request;
mod response;

use std::pin::Pin;

use crate::common::message::ArcMessage;
fn request<RS, WS, R>(
    request: R,
    recv: H3ReadStream<RS>,
    send: H3WriteStream<WS>,
    qpack: ArcQpack,
) -> impl Future<Output = Result<Response>> + Send
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin + Send + 'static,
    R: Into<common::Request<Write>>,
{
    match request.into() {
        common::Request::Bytes(request) => Box::pin(
            write_bytes_request(request, send, recv, qpack)
                .unwrap()
                .into_future(),
        )
            as Pin<Box<dyn Future<Output = Result<Response>> + Send>>,
        common::Request::Streaming(request) => Box::pin(
            write_streaming_request(request, send, recv, qpack)
                .unwrap()
                .into_future(),
        ),
    }
}
