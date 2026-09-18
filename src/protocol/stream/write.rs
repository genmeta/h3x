use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Method;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use super::{Goaway, H3ReadStream, H3Stream};
use crate::{
    ArcQpack, ArcWndBuf, Error, ErrorCode, Result,
    common::{
        Write,
        body::ContentType,
        request::{Request, WriteRequest as _},
        response::{ReadResponse as _, Response, WriteResponse as _},
    },
};

/// Application-owned write direction, observed weakly by the connection.
pub struct H3WriteStream<W: CancelStream> {
    id: u64,
    pub(super) state: Arc<Mutex<std::result::Result<H3Stream<W>, Goaway>>>,
    finished: Arc<Notify>,
}

impl<W: CancelStream> H3WriteStream<W> {
    pub fn new(stream_id: u64, stream: W) -> Self {
        Self::new_observed(stream_id, stream, Arc::default())
    }

    pub(super) fn new_observed(stream_id: u64, stream: W, finished: Arc<Notify>) -> Self {
        Self {
            id: stream_id,
            state: Arc::new(Mutex::new(Ok(H3Stream::new(stream)))),
            finished,
        }
    }

    pub fn stream_id(&self) -> u64 {
        self.id
    }
}

impl<W: CancelStream> CancelStream for &H3WriteStream<W> {
    fn cancel(&mut self, error_code: u64) {
        let mut state = self.state.lock().unwrap();
        let was_finished = super::is_finished(&state);
        let waker = super::terminate(&mut state, |io| io.cancel(error_code));
        let finished = !was_finished && super::is_finished(&state);
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        if finished {
            self.finished.notify_waiters();
        }
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> H3WriteStream<W> {
    fn poll_io<O>(
        &mut self,
        cx: &mut Context<'_>,
        finish: bool,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<O>>,
    ) -> Poll<io::Result<O>> {
        let mut inner = self.state.lock().unwrap();
        let was_finished = super::is_finished(&inner);
        let result = super::poll_io(&mut *inner, cx, poll);
        if finish && matches!(result, Poll::Ready(Ok(_))) {
            super::finish(&mut *inner);
        }
        let finished = !was_finished && super::is_finished(&inner);
        drop(inner);
        if finished {
            self.finished.notify_waiters();
        }
        result
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> AsyncWrite for H3WriteStream<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, false, |send, cx| send.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_io(cx, true, |send, cx| send.poll_shutdown(cx))
    }
}

impl<W: CancelStream> Drop for H3WriteStream<W> {
    fn drop(&mut self) {
        (&*self).cancel(ErrorCode::H3_REQUEST_CANCELLED.as_u64());
    }
}

impl<W: AsyncWrite + CancelStream + Unpin + Send + 'static> H3WriteStream<W> {
    /// Start a buffered upload and receive the response on the paired read stream.
    pub fn write_bytes_request<RS>(
        self,
        request: Request<Write, Bytes>,
        rs: H3ReadStream<RS>,
        qpack: ArcQpack,
    ) -> impl Future<Output = crate::Result<crate::IncomingResponse>> + Send
    where
        RS: AsyncRead + StopSending + Unpin + Send + 'static,
    {
        use crate::ReadRequest;
        let ws = self;
        let method = request.method();
        tokio::spawn(crate::common::request::WriteRequest::write_bytes_request(
            ws,
            request,
            qpack.clone(),
        ));
        rs.read_response(qpack, Some(method))
    }

    /// Start an upload, waiting for acceptance before sending CONNECT data.
    /// Ordinary uploads continue independently of the returned response future.
    pub fn write_streaming_request<RS>(
        self,
        request: Request<Write, ArcWndBuf>,
        rs: H3ReadStream<RS>,
        qpack: ArcQpack,
    ) -> impl Future<Output = crate::Result<crate::IncomingResponse>> + Send
    where
        RS: AsyncRead + StopSending + Unpin + Send + 'static,
    {
        use crate::ReadRequest;
        let ws = self;
        let method = request.method();
        let ordinary = method != http::Method::CONNECT;
        // Start ordinary uploads immediately; CONNECT must await acceptance first.
        let connect = if ordinary {
            tokio::spawn(
                crate::common::request::WriteRequest::write_streaming_request(
                    ws,
                    request,
                    qpack.clone(),
                ),
            );
            None
        } else {
            Some((ws, request))
        };
        async move {
            if let Some((ws, request)) = connect {
                let mut ws = ws;
                let mut rs = rs;
                let body = request.message.body();
                let (head, mode) = {
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
                }
                .inspect_err(|error| {
                    (&ws).cancel(error.code.as_u64());
                    request.message.body().on_error(error.clone());
                })?;

                if mode == ContentType::Connect {
                    tokio::spawn(
                        async move { ws.write_request_streaming_body(&request, mode).await },
                    );
                } else {
                    request
                        .message
                        .body()
                        .on_error(ErrorCode::H3_REQUEST_CANCELLED.reason("CONNECT rejected"));
                }
                Ok(rs.read_response_body(head, mode, qpack))
            } else {
                rs.read_response(qpack, Some(method)).await
            }
        }
    }
}

impl<W: AsyncWrite + CancelStream + Unpin> H3WriteStream<W> {
    /// Send a buffered response. The method belongs to the original request.
    /// Validate metadata/body and send when polled.
    /// Validation errors are returned by the future.
    pub fn write_bytes_response(
        self,
        response: Response<Write, Bytes>,
        qpack: ArcQpack,
        method: &Method,
    ) -> impl Future<Output = Result<()>> + use<W> {
        let mut ws = self;
        let method = method.clone();
        async move {
            async {
                ws.write_response_head(&response, &qpack, &method).await?;
                ws.write_response_bytes_body(&response).await?;
                ws.shutdown().await?;
                Ok::<_, Error>(())
            }
            .await
            .inspect_err(|error| (&ws).cancel(error.code.as_u64()))
        }
    }

    /// Send a streaming response. Keep a body producer until finish/reset and drive
    /// this future concurrently with production. Use reset to cancel the body explicitly.
    /// Validation runs when polled, before HEADERS are sent. Errors wake the
    /// producer and are returned by the future.
    pub fn write_streaming_response(
        self,
        response: Response<Write, ArcWndBuf>,
        qpack: ArcQpack,
        request_method: &Method,
    ) -> impl Future<Output = Result<()>> + use<W> {
        let mut ws = self;
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
            tokio::select! {
                biased;
                error = cancellation.wait_error() => Err(error),
                result = sending => result,
            }
            .inspect_err(|error| {
                (&ws).cancel(error.code.as_u64());
                body.on_error(error.clone());
            })
        }
    }
}
