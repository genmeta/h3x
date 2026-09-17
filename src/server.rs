//! Incoming requests and responses on the original stream.

use std::future::Future;

use bytes::Bytes;
use http::Method;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    ArcQpack, ArcWndBuf, Error, Result,
    common::{self, Read, Write, head, request::ReadRequest as _, response::WriteResponse as _},
    protocol::stream::{H3ReadStream, H3WriteStream},
};

pub type Request = crate::common::Request<Read>;
pub type Response<B> = crate::common::response::Response<Write, B>;

/// Read an HTTP request using the receive stream's ID and shared QPACK state.
pub async fn read_request<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<Request> {
    rs.read_request(qpack).await
}

/// Start body reception after read_request_head has consumed HEADERS.
/// `rs` and `qpack` must belong to the request whose metadata is supplied here.
pub fn read_request_body<RS: AsyncRead + StopSending + Unpin + Send + 'static>(
    request: http::Request<()>,
    rs: H3ReadStream<RS>,
    qpack: ArcQpack,
) -> Result<Request> {
    let (parts, ()) = request.into_parts();
    let head = head::RequestHead::from(parts);
    rs.read_request_body(head, qpack)
}

/// Read only initial HEADERS, leaving the receive direction with the caller.
/// No body task is started and no bytes beyond the field section are prefetched.
/// After success pass the same stream to read_request_body.
/// If this future is cancelled, discard the stream: a partial header may be consumed.
pub async fn read_request_head<RS: AsyncRead + StopSending + Unpin>(
    rs: &mut H3ReadStream<RS>,
    qpack: &ArcQpack,
) -> Result<http::Request<()>> {
    let head = common::request::read_head(rs, qpack).await?;
    let parts = http::request::Parts::from(head);
    Ok(http::Request::from_parts(parts, ()))
}

/// Send a buffered response. The method belongs to the original request.
/// Validate metadata/body and send when polled.
/// Validation errors are returned by the future.
pub fn write_bytes_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    method: &Method,
) -> impl Future<Output = Result<()>> + use<WS> {
    let method = method.clone();
    async move {
        let result = async {
            ws.write_response_head(&response, &qpack, &method).await?;
            ws.write_response_bytes_body(&response).await?;
            ws.shutdown().await?;
            Ok::<_, Error>(())
        }
        .await;
        if let Err(error) = &result {
            (&ws).cancel(error.code.as_u64());
        }
        result
    }
}

/// Send a streaming response. Keep a body producer until finish/reset and drive
/// this future concurrently with production. Use reset to cancel the body explicitly.
/// Validation runs when polled, before HEADERS are sent. Errors wake the
/// producer and are returned by the future.
pub fn write_streaming_response<WS: AsyncWrite + CancelStream + Unpin>(
    response: Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: ArcQpack,
    request_method: &Method,
) -> impl Future<Output = Result<()>> + use<WS> {
    let body = response.message.body();
    let request_method = request_method.clone();
    async move {
        let cancellation = body.clone();
        let sending = async {
            let mode = ws
                .write_response_head(&response, &qpack, &request_method)
                .await?;
            ws.flush().await?;
            ws.write_response_streaming_body(&response, mode).await?;
            ws.shutdown().await?;
            Ok::<_, Error>(())
        };
        let result = tokio::select! {
            biased;
            error = cancellation.wait_error() => Err(error),
            result = sending => result,
        };
        if let Err(error) = &result {
            (&ws).cancel(error.code.as_u64());
            body.on_error(error.clone());
        }
        result
    }
}
