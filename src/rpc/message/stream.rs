use std::pin::Pin;

use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::Either};
use tokio_util::sync::CancellationToken;

use super::super::bridge;
// Import original traits under aliases to avoid collision with the RTC traits
// defined in this module (which share the same names).
use crate::message::stream::{
    ReadMessageStream as OrigReadMessageStream, WriteMessageStream as OrigWriteMessageStream,
};
use crate::{
    message::stream::{BoxMessageStreamReader, BoxMessageStreamWriter, MessageStreamError},
    quic::{self, CancelStreamExt, GetStreamIdExt, StopStreamExt},
    util::deferred::Deferred,
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// RTC traits
// ---------------------------------------------------------------------------

/// Remote trait for reading from a message-level stream over remoc RTC.
///
/// Data reads use [`MessageStreamError`]; QUIC control operations
/// (`stream_id`, `stop`) use [`quic::StreamError`].
#[remoc::rtc::remote]
pub trait ReadMessageStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn read(&mut self) -> Result<Option<Bytes>, MessageStreamError>;
    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

/// Remote trait for writing to a message-level stream over remoc RTC.
///
/// Data writes use [`MessageStreamError`]; QUIC control operations
/// (`stream_id`, `cancel`) use [`quic::StreamError`].
#[remoc::rtc::remote]
pub trait WriteMessageStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), MessageStreamError>;
    async fn flush(&mut self) -> Result<(), MessageStreamError>;
    async fn shutdown(&mut self) -> Result<(), MessageStreamError>;
    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
}

// ---------------------------------------------------------------------------
// Server side: blanket impls for original message stream types
// ---------------------------------------------------------------------------

impl<S> ReadMessageStream for S
where
    S: OrigReadMessageStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, MessageStreamError> {
        StreamExt::next(self).await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        StopStreamExt::stop(self, code).await
    }
}

impl<S> WriteMessageStream for S
where
    S: OrigWriteMessageStream + Unpin + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        GetStreamIdExt::stream_id(self).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), MessageStreamError> {
        SinkExt::send(self, data).await
    }

    async fn flush(&mut self) -> Result<(), MessageStreamError> {
        SinkExt::flush(self).await
    }

    async fn shutdown(&mut self) -> Result<(), MessageStreamError> {
        SinkExt::close(self).await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        CancelStreamExt::cancel(self, code).await
    }
}

// ---------------------------------------------------------------------------
// Client side: ReadMessageStreamClient → impl OrigReadMessageStream
// ---------------------------------------------------------------------------

impl ReadMessageStreamClient {
    /// Convert into a poll-based [`OrigReadMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl OrigReadMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(
            bridge::ReadBridge::<_, MessageStreamError, _, _, _, _>::new(
                stream_id,
                self,
                |mut client: ReadMessageStreamClient, token: CancellationToken| async move {
                    tokio::select! {
                        res = client.read() => Either::Left((client, res.transpose())),
                        _ = token.cancelled() => Either::Right(client),
                    }
                },
                |mut client: ReadMessageStreamClient, code| async move {
                    let res = client.stop(code).await;
                    (client, res)
                },
            ),
        )
    }

    /// Convert into a boxed [`OrigReadMessageStream`] (lazy — resolves on first poll).
    pub fn into_boxed_message_stream(self) -> Pin<Box<dyn OrigReadMessageStream + Send + 'static>> {
        Box::pin(Deferred::from(self.into_message_stream()))
    }

    /// Convert into a [`BoxMessageStreamReader`] (implements [`AsyncRead`](tokio::io::AsyncRead)).
    pub fn into_box_reader(self) -> BoxMessageStreamReader<'static> {
        crate::codec::StreamReader::new(self.into_boxed_message_stream())
    }
}

// ---------------------------------------------------------------------------
// Client side: WriteMessageStreamClient → impl OrigWriteMessageStream
// ---------------------------------------------------------------------------

impl WriteMessageStreamClient {
    /// Convert into a poll-based [`OrigWriteMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl OrigWriteMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(bridge::WriteBridge::<
            _,
            MessageStreamError,
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
            |mut client: WriteMessageStreamClient, token: CancellationToken, bytes| async move {
                tokio::select! {
                    res = client.write(bytes) => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteMessageStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.flush() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteMessageStreamClient, token: CancellationToken| async move {
                tokio::select! {
                    res = client.shutdown() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            |mut client: WriteMessageStreamClient, code| async move {
                let res = client.cancel(code).await;
                (client, res)
            },
        ))
    }

    /// Convert into a boxed [`OrigWriteMessageStream`] (lazy — resolves on first poll).
    pub fn into_boxed_message_stream(
        self,
    ) -> Pin<Box<dyn OrigWriteMessageStream + Send + 'static>> {
        Box::pin(Deferred::from(self.into_message_stream()))
    }

    /// Convert into a [`BoxMessageStreamWriter`] (implements [`AsyncWrite`](tokio::io::AsyncWrite)).
    pub fn into_box_writer(self) -> BoxMessageStreamWriter<'static> {
        crate::codec::SinkWriter::new(self.into_boxed_message_stream())
    }
}
