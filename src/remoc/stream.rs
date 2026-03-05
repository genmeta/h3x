use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture};

use crate::{
    quic::{CancelStream, GetStreamId, StopStream, StreamError},
    varint::VarInt,
};

use super::RemoteError;

/// Remote trait for reading from a QUIC stream over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone` (remoc uses
/// internal channels for mutation).
#[remoc::rtc::remote]
pub trait RemoteRead: Send + Sync {
    async fn stream_id(&self) -> Result<VarInt, RemoteError>;
    async fn read(&self) -> Result<Option<Vec<u8>>, RemoteError>;
    async fn stop(&self, code: VarInt) -> Result<(), RemoteError>;
}

/// Remote trait for writing to a QUIC stream over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone` (remoc uses
/// internal channels for mutation).
#[remoc::rtc::remote]
pub trait RemoteWrite: Send + Sync {
    async fn stream_id(&self) -> Result<VarInt, RemoteError>;
    async fn write(&self, data: Vec<u8>) -> Result<(), RemoteError>;
    async fn flush(&self) -> Result<(), RemoteError>;
    async fn shutdown(&self) -> Result<(), RemoteError>;
    async fn cancel(&self, code: VarInt) -> Result<(), RemoteError>;
}

/// Wraps a [`RemoteReadClient`] to implement the poll-based [`ReadStream`](quic::ReadStream) traits.
///
/// All fields are owned or boxed, so this type is `Unpin` without pin projection.
pub struct RemoteReadStream {
    client: RemoteReadClient,
    stream_id: Option<VarInt>,
    pending_read: Option<BoxFuture<'static, Result<Option<Vec<u8>>, RemoteError>>>,
    pending_stop: Option<BoxFuture<'static, Result<(), RemoteError>>>,
    pending_stream_id: Option<BoxFuture<'static, Result<VarInt, RemoteError>>>,
}

impl RemoteReadStream {
    /// Creates a new `RemoteReadStream` wrapping the given RTC client.
    pub fn new(client: RemoteReadClient) -> Self {
        Self {
            client,
            stream_id: None,
            pending_read: None,
            pending_stop: None,
            pending_stream_id: None,
        }
    }
}

impl GetStreamId for RemoteReadStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        let this = self.get_mut();

        if let Some(id) = this.stream_id {
            return Poll::Ready(Ok(id));
        }

        if this.pending_stream_id.is_none() {
            let client = this.client.clone();
            this.pending_stream_id = Some(Box::pin(async move { client.stream_id().await }));
        }

        let fut = this.pending_stream_id.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_stream_id = None;
                match result {
                    Ok(id) => {
                        this.stream_id = Some(id);
                        Poll::Ready(Ok(id))
                    }
                    Err(e) => Poll::Ready(Err(e.into_stream_error())),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl StopStream for RemoteReadStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();

        if this.pending_stop.is_none() {
            let client = this.client.clone();
            this.pending_stop = Some(Box::pin(async move { client.stop(code).await }));
        }

        let fut = this.pending_stop.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_stop = None;
                Poll::Ready(result.map_err(|e| e.into_stream_error()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for RemoteReadStream {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.pending_read.is_none() {
            let client = this.client.clone();
            this.pending_read = Some(Box::pin(async move { client.read().await }));
        }

        let fut = this.pending_read.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_read = None;
                match result {
                    Ok(Some(data)) => Poll::Ready(Some(Ok(Bytes::from(data)))),
                    Ok(None) => Poll::Ready(None),
                    Err(e) => Poll::Ready(Some(Err(e.into_stream_error()))),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Wraps a [`RemoteWriteClient`] to implement the poll-based [`WriteStream`](quic::WriteStream) traits.
///
/// All fields are owned or boxed, so this type is `Unpin` without pin projection.
pub struct RemoteWriteStream {
    client: RemoteWriteClient,
    stream_id: Option<VarInt>,
    buffer: Option<Vec<u8>>,
    pending_write: Option<BoxFuture<'static, Result<(), RemoteError>>>,
    pending_flush: Option<BoxFuture<'static, Result<(), RemoteError>>>,
    pending_shutdown: Option<BoxFuture<'static, Result<(), RemoteError>>>,
    pending_cancel: Option<BoxFuture<'static, Result<(), RemoteError>>>,
    pending_stream_id: Option<BoxFuture<'static, Result<VarInt, RemoteError>>>,
}

impl RemoteWriteStream {
    /// Creates a new `RemoteWriteStream` wrapping the given RTC client.
    pub fn new(client: RemoteWriteClient) -> Self {
        Self {
            client,
            stream_id: None,
            buffer: None,
            pending_write: None,
            pending_flush: None,
            pending_shutdown: None,
            pending_cancel: None,
            pending_stream_id: None,
        }
    }
}

impl GetStreamId for RemoteWriteStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        let this = self.get_mut();

        if let Some(id) = this.stream_id {
            return Poll::Ready(Ok(id));
        }

        if this.pending_stream_id.is_none() {
            let client = this.client.clone();
            this.pending_stream_id = Some(Box::pin(async move { client.stream_id().await }));
        }

        let fut = this.pending_stream_id.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_stream_id = None;
                match result {
                    Ok(id) => {
                        this.stream_id = Some(id);
                        Poll::Ready(Ok(id))
                    }
                    Err(e) => Poll::Ready(Err(e.into_stream_error())),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl CancelStream for RemoteWriteStream {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        let this = self.get_mut();

        if this.pending_cancel.is_none() {
            let client = this.client.clone();
            this.pending_cancel = Some(Box::pin(async move { client.cancel(code).await }));
        }

        let fut = this.pending_cancel.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_cancel = None;
                Poll::Ready(result.map_err(|e| e.into_stream_error()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for RemoteWriteStream {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        if let Some(fut) = this.pending_write.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    this.pending_write = None;
                    result.map_err(|e| e.into_stream_error())?;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.buffer = Some(item.to_vec());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        if let Some(data) = this.buffer.take() {
            let client = this.client.clone();
            this.pending_write = Some(Box::pin(async move { client.write(data).await }));
        }

        if let Some(fut) = this.pending_write.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(result) => {
                    this.pending_write = None;
                    result.map_err(|e| e.into_stream_error())?;
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if this.pending_flush.is_none() {
            let client = this.client.clone();
            this.pending_flush = Some(Box::pin(async move { client.flush().await }));
        }

        let fut = this.pending_flush.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_flush = None;
                Poll::Ready(result.map_err(|e| e.into_stream_error()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();

        if this.pending_shutdown.is_none() {
            let client = this.client.clone();
            this.pending_shutdown = Some(Box::pin(async move { client.shutdown().await }));
        }

        let fut = this.pending_shutdown.as_mut().expect("just set above");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                this.pending_shutdown = None;
                Poll::Ready(result.map_err(|e| e.into_stream_error()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
