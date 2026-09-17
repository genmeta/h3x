use std::{io::Cursor, sync::Arc};

use http::{HeaderValue, Method, header};
use tokio::io::{AsyncReadExt, duplex};

use super::*;
use crate::{
    ReadStream,
    common::message::{ReadResponse, WriteRequest, WriteStream},
    protocol::{
        frame::be_frame,
        qpack::{self, ArcQpack, WriteFieldSection},
    },
};

mod errors;
mod lifecycle;
mod request;
mod response;

use std::pin::Pin;

fn request<RS, WS, R>(
    request: R,
    recv: H3ReadStream<RS>,
    send: H3WriteStream<WS>,
    qpack: ArcQpack,
) -> impl Future<Output = Result<Response>> + Send
where
    RS: qrecovery::recv::StopSending + AsyncRead + Unpin + Send + 'static,
    WS: qrecovery::send::CancelStream + AsyncWrite + Unpin + Send + 'static,
    R: Into<common::Request<Write>>,
{
    match request.into() {
        common::Request::Bytes(request) => {
            Box::pin(write_bytes_request(request, send, recv, qpack).unwrap())
                as Pin<Box<dyn Future<Output = Result<Response>> + Send>>
        }
        common::Request::Streaming(request)
            if crate::ReadRequest::method(&request) == Method::CONNECT =>
        {
            Box::pin(async move {
                match connect(request, send, recv, qpack).await {
                    Ok(response) | Err(ConnectError::Rejected(response)) => Ok(response),
                    Err(ConnectError::H3(error)) => Err(error),
                }
            })
        }
        common::Request::Streaming(request) => {
            Box::pin(write_streaming_request(request, send, recv, qpack).unwrap())
        }
    }
}
