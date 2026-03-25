use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::Either};
use tokio_util::sync::CancellationToken;

use crate::{
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    quic,
    util::try_future::TryFuture,
    varint::VarInt,
};

use super::super::bridge;

/// Remote trait for reading from a QUIC stream over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone` (remoc uses
/// internal channels for mutation).
#[remoc::rtc::remote]
pub trait ReadStream: Send + Sync {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError>;
    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

impl ReadStreamClient {
    pub async fn into_quic(mut self) -> Result<impl quic::ReadStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            stream_id,
            self,
            |mut client: ReadStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.read() => Either::Left((client, res.transpose())),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: ReadStreamClient, code| async move {
                let res = client.stop(code).await;
                (client, res)
            },
        ))
    }

    pub fn into_boxed_quic(self) -> BoxDynQuicStreamReader {
        Box::pin(TryFuture::from(self.into_quic())) as BoxDynQuicStreamReader
    }
}

/// Remote trait for writing to a QUIC stream over remoc RTC.
///
/// All methods take `&self` so the generated client is `Clone` (remoc uses
/// internal channels for mutation).
#[remoc::rtc::remote]
pub trait WriteStream: Send + Sync {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError>;
    async fn flush(&mut self) -> Result<(), quic::StreamError>;
    async fn shutdown(&mut self) -> Result<(), quic::StreamError>;
    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

impl WriteStreamClient {
    pub async fn into_quic(mut self) -> Result<impl quic::WriteStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
            stream_id,
            self,
            |mut client: WriteStreamClient, token: CancellationToken, bytes| async move {
                tokio::select! {
                    res = client.write(bytes) => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.flush() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.shutdown() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteStreamClient, code| async move {
                let res = client.cancel(code).await;
                (client, res)
            },
        ))
    }

    pub fn into_boxed_quic(self) -> BoxDynQuicStreamWriter {
        Box::pin(TryFuture::from(self.into_quic())) as BoxDynQuicStreamWriter
    }
}

impl<S> ReadStream for Pin<Box<S>>
where
    S: quic::ReadStream + Send + Sync,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_stream_id(cx)).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError> {
        self.as_mut().next().await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_stop(cx, code)).await
    }
}
impl<S> WriteStream for Pin<Box<S>>
where
    S: quic::WriteStream + Send + Sync,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_stream_id(cx)).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError> {
        self.as_mut().send(data).await
    }

    async fn flush(&mut self) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_flush(cx)).await
    }

    async fn shutdown(&mut self) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_close(cx)).await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.as_mut().poll_cancel(cx, code)).await
    }
}
