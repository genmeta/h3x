//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
use std::future::Future;

use bytes::Bytes;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    ArcWndBuf, Error, ErrorCode, Result,
    common::{
        Read, Write, body::ContentType, request::WriteRequest as _, response::ReadResponse as _,
    },
    protocol::{
        qpack::ArcQpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

/// Outgoing request selected by body storage.
pub type Request<B> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

pub fn write_bytes_request<RS, WS>(
    request: Request<Bytes>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<impl Future<Output = Result<Response>> + Send>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    tokio::spawn(ws.write_bytes_request(request, qpack.clone()));
    Ok(rs.read_response(qpack, Some(method)))
}

pub fn write_streaming_request<RS, WS>(
    request: Request<ArcWndBuf>,
    ws: H3WriteStream<WS>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<impl Future<Output = Result<Response>> + Send>
where
    RS: AsyncRead + StopSending + Unpin + Send + 'static,
    WS: AsyncWrite + CancelStream + Unpin + Send + 'static,
{
    use crate::ReadRequest;
    let method = request.method();
    let response: std::pin::Pin<Box<dyn Future<Output = Result<Response>> + Send>> = if method
        == http::Method::CONNECT
    {
        Box::pin(async move {
            let mut ws = ws;
            let mut rs = rs;
            let body = request.message.body();
            let result = {
                let sending = async {
                    ws.write_request_head(&request, &qpack).await?;
                    ws.flush().await?;
                    Ok::<_, Error>(())
                };
                let receiving = rs.read_response_head(&qpack, Some(&method));
                tokio::pin!(receiving);
                tokio::select! {
                    biased;
                    error = body.wait_error() => Err(error),
                    head = &mut receiving => head,
                    sent = sending => match sent {
                        Err(error) => Err(error),
                        Ok(()) => tokio::select! {
                            biased;
                            error = body.wait_error() => Err(error),
                            head = &mut receiving => head,
                        },
                    },
                }
            };
            let (head, mode) = result.inspect_err(|error| {
                (&ws).cancel(error.code.as_u64());
                request.message.body().on_error(error.clone());
            })?;

            if mode == ContentType::Connect {
                tokio::spawn(async move { ws.write_request_streaming_body(&request, mode).await });
            } else {
                request
                    .message
                    .body()
                    .on_error(ErrorCode::H3_REQUEST_CANCELLED.reason("CONNECT rejected"));
            }
            Ok(rs.read_response_body(head, mode, qpack))
        })
    } else {
        tokio::spawn(ws.write_streaming_request(request, qpack.clone()));
        Box::pin(rs.read_response(qpack, Some(method)))
    };
    Ok(response)
}
