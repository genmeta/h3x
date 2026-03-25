use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::future::Either;
use tokio_util::sync::CancellationToken;

use crate::{
    message::stream::{
        MessageStreamError,
        unfold::{
            read::{BoxMessageStreamReader, ReadMessageStream},
            write::{BoxMessageStreamWriter, WriteMessageStream},
        },
    },
    quic,
    util::try_future::TryFuture,
    varint::VarInt,
};

use super::super::bridge;

// ---------------------------------------------------------------------------
// RTC traits
// ---------------------------------------------------------------------------

/// Remote trait for reading from a message-level stream over remoc RTC.
///
/// Data reads use [`MessageStreamError`]; QUIC control operations
/// (`stream_id`, `stop`) use [`quic::StreamError`].
#[remoc::rtc::remote]
pub trait MessageReadStream: Send + Sync {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn read(&mut self) -> Result<Option<Bytes>, MessageStreamError>;
    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

/// Remote trait for writing to a message-level stream over remoc RTC.
///
/// Data writes use [`MessageStreamError`]; QUIC control operations
/// (`stream_id`, `cancel`) use [`quic::StreamError`].
#[remoc::rtc::remote]
pub trait MessageWriteStream: Send + Sync {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), MessageStreamError>;
    async fn flush(&mut self) -> Result<(), MessageStreamError>;
    async fn shutdown(&mut self) -> Result<(), MessageStreamError>;
    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

// ---------------------------------------------------------------------------
// Read bridge (MessageReadStreamClient → impl ReadMessageStream)
// ---------------------------------------------------------------------------

impl MessageReadStreamClient {
    /// Convert into a poll-based [`ReadMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl ReadMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::ReadBridge::<_, MessageStreamError, _, _, _, _>::new(
            stream_id,
            self,
            |mut client: MessageReadStreamClient,
             token: CancellationToken| async move {
                tokio::select! {
                    res = client.read() => Either::Left((client, res.transpose())),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: MessageReadStreamClient, code| async move {
                let res = client.stop(code).await;
                (client, res)
            },
        ))
    }

    /// Convert into a boxed [`ReadMessageStream`] (lazy — resolves on first poll).
    pub fn into_boxed_message_stream(
        self,
    ) -> Pin<Box<dyn ReadMessageStream + Send + 'static>> {
        Box::pin(TryFuture::from(self.into_message_stream()))
    }

    /// Convert into a [`BoxMessageStreamReader`] (implements [`AsyncRead`](tokio::io::AsyncRead)).
    pub fn into_box_reader(self) -> BoxMessageStreamReader<'static> {
        crate::codec::StreamReader::new(self.into_boxed_message_stream())
    }
}

// ---------------------------------------------------------------------------
// Write bridge (MessageWriteStreamClient → impl WriteMessageStream)
// ---------------------------------------------------------------------------

impl MessageWriteStreamClient {
    /// Convert into a poll-based [`WriteMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl WriteMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::WriteBridge::<_, MessageStreamError, _, _, _, _, _, _, _, _>::new(
            stream_id,
            self,
            |mut client: MessageWriteStreamClient,
             token: CancellationToken,
             bytes| async move {
                tokio::select! {
                    res = client.write(bytes) => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: MessageWriteStreamClient,
             token: CancellationToken| async move {
                tokio::select! {
                    res = client.flush() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: MessageWriteStreamClient,
             token: CancellationToken| async move {
                tokio::select! {
                    res = client.shutdown() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: MessageWriteStreamClient, code| async move {
                let res = client.cancel(code).await;
                (client, res)
            },
        ))
    }

    /// Convert into a boxed [`WriteMessageStream`] (lazy — resolves on first poll).
    pub fn into_boxed_message_stream(
        self,
    ) -> Pin<Box<dyn WriteMessageStream + Send + 'static>> {
        Box::pin(TryFuture::from(self.into_message_stream()))
    }

    /// Convert into a [`BoxMessageStreamWriter`] (implements [`AsyncWrite`](tokio::io::AsyncWrite)).
    pub fn into_box_writer(self) -> BoxMessageStreamWriter<'static> {
        crate::codec::SinkWriter::new(self.into_boxed_message_stream())
    }
}
