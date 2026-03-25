use std::{
    future::poll_fn,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{SinkExt, StreamExt, future::Either};
use remoc::prelude::ServerSharedMut;
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
// Served wrappers (server side — wrap a real stream behind a Mutex)
// ---------------------------------------------------------------------------

struct ServedMessageReadStream<R> {
    inner: tokio::sync::Mutex<Pin<Box<R>>>,
}

impl<R> ServedMessageReadStream<R> {
    fn new(stream: R) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Box::pin(stream)),
        }
    }
}

impl<R> MessageReadStream for ServedMessageReadStream<R>
where
    R: ReadMessageStream + 'static,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        let mut stream = self.inner.lock().await;
        poll_fn(|cx| stream.as_mut().poll_stream_id(cx)).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, MessageStreamError> {
        let mut stream = self.inner.lock().await;
        stream.next().await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        poll_fn(|cx| stream.as_mut().poll_stop(cx, code)).await
    }
}

struct ServedMessageWriteStream<W> {
    inner: tokio::sync::Mutex<Pin<Box<W>>>,
}

impl<W> ServedMessageWriteStream<W> {
    fn new(stream: W) -> Self {
        Self {
            inner: tokio::sync::Mutex::new(Box::pin(stream)),
        }
    }
}

impl<W> MessageWriteStream for ServedMessageWriteStream<W>
where
    W: WriteMessageStream + 'static,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        let mut stream = self.inner.lock().await;
        poll_fn(|cx| stream.as_mut().poll_stream_id(cx)).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), MessageStreamError> {
        let mut stream = self.inner.lock().await;
        stream.send(data).await
    }

    async fn flush(&mut self) -> Result<(), MessageStreamError> {
        let mut stream = self.inner.lock().await;
        SinkExt::flush(&mut *stream).await
    }

    async fn shutdown(&mut self) -> Result<(), MessageStreamError> {
        let mut stream = self.inner.lock().await;
        stream.close().await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        let mut stream = self.inner.lock().await;
        poll_fn(|cx| stream.as_mut().poll_cancel(cx, code)).await
    }
}

// ---------------------------------------------------------------------------
// Serve functions (create server+client pair)
// ---------------------------------------------------------------------------

pub fn serve_message_read_stream(
    reader: impl ReadMessageStream + 'static,
) -> (
    MessageReadStreamClient,
    impl Future<Output = ()> + Send + 'static,
) {
    let (server, client) = MessageReadStreamServerSharedMut::new(
        Arc::new(tokio::sync::RwLock::new(
            ServedMessageReadStream::new(reader),
        )),
        1,
    );
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
}

pub fn serve_message_write_stream(
    writer: impl WriteMessageStream + 'static,
) -> (
    MessageWriteStreamClient,
    impl Future<Output = ()> + Send + 'static,
) {
    let (server, client) = MessageWriteStreamServerSharedMut::new(
        Arc::new(tokio::sync::RwLock::new(
            ServedMessageWriteStream::new(writer),
        )),
        1,
    );
    let fut = async move {
        let _ = server.serve(true).await;
    };
    (client, fut)
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
