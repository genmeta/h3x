use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::Either};
use tokio_util::sync::CancellationToken;

use super::super::bridge;
use crate::{
    codec::BoxReadStream,
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    message::stream::guard,
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    util::try_future::TryFuture,
    varint::VarInt,
};

/// Remote trait for reading from a QUIC stream over remoc RTC.
#[remoc::rtc::remote]
pub trait ReadStream: Send {
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
        let raw: BoxReadStream = Box::pin(TryFuture::from(self.into_quic()));
        guard::GuardedQuicReader::new(raw)
    }
}

/// Remote trait for writing to a QUIC stream over remoc RTC.
#[remoc::rtc::remote]
pub trait WriteStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError>;
    async fn flush(&mut self) -> Result<(), quic::StreamError>;
    async fn shutdown(&mut self) -> Result<(), quic::StreamError>;
    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

impl WriteStreamClient {
    pub async fn into_quic(mut self) -> Result<impl quic::WriteStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::WriteBridge::<
            _,
            quic::StreamError,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        >::new(
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
        let raw: crate::codec::BoxWriteStream = Box::pin(TryFuture::from(self.into_quic()));
        guard::GuardedQuicWriter::new(raw)
    }
}

impl<S> ReadStream for S
where
    S: quic::ReadStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError> {
        StreamExt::next(self).await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        StopStreamExt::stop(self, code).await
    }
}

impl<S> WriteStream for S
where
    S: quic::WriteStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError> {
        SinkExt::send(self, data).await
    }

    async fn flush(&mut self) -> Result<(), quic::StreamError> {
        SinkExt::flush(self).await
    }

    async fn shutdown(&mut self) -> Result<(), quic::StreamError> {
        SinkExt::close(self).await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        CancelStreamExt::cancel(self, code).await
    }
}
