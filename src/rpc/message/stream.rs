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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use futures::{Sink, Stream, stream::FusedStream};

    use super::*;

    struct TestReadMessageStream {
        stream_id: VarInt,
        chunks: VecDeque<Result<Bytes, MessageStreamError>>,
        stopped: Arc<Mutex<Option<VarInt>>>,
        terminated: bool,
    }

    impl quic::GetStreamId for TestReadMessageStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for TestReadMessageStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for TestReadMessageStream {
        type Item = Result<Bytes, MessageStreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            match this.chunks.pop_front() {
                Some(chunk) => Poll::Ready(Some(chunk)),
                None => {
                    this.terminated = true;
                    Poll::Ready(None)
                }
            }
        }
    }

    impl FusedStream for TestReadMessageStream {
        fn is_terminated(&self) -> bool {
            self.terminated
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Write(Bytes),
        Flush,
        Shutdown,
        Cancel(VarInt),
    }

    struct TestWriteMessageStream {
        stream_id: VarInt,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl quic::GetStreamId for TestWriteMessageStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::CancelStream for TestWriteMessageStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Cancel(code));
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for TestWriteMessageStream {
        type Error = MessageStreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Write(item));
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Flush);
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Shutdown);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn blanket_read_message_stream_delegates_to_original_stream() {
        let stopped = Arc::new(Mutex::new(None));
        let stream_id = VarInt::from_u32(17);
        let stop_code = VarInt::from_u32(19);
        let mut stream = TestReadMessageStream {
            stream_id,
            chunks: VecDeque::from([Ok(Bytes::from_static(b"message"))]),
            stopped: stopped.clone(),
            terminated: false,
        };

        let id = ReadMessageStream::stream_id(&mut stream)
            .await
            .expect("stream id resolves");
        assert_eq!(id, stream_id);

        let chunk = ReadMessageStream::read(&mut stream)
            .await
            .expect("read succeeds");
        assert_eq!(chunk, Some(Bytes::from_static(b"message")));

        let eof = ReadMessageStream::read(&mut stream)
            .await
            .expect("eof succeeds");
        assert!(eof.is_none());
        assert!(stream.is_terminated());

        ReadMessageStream::stop(&mut stream, stop_code)
            .await
            .expect("stop succeeds");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn blanket_write_message_stream_delegates_to_original_sink() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stream_id = VarInt::from_u32(23);
        let cancel_code = VarInt::from_u32(29);
        let mut stream = TestWriteMessageStream {
            stream_id,
            events: events.clone(),
        };

        let id = WriteMessageStream::stream_id(&mut stream)
            .await
            .expect("stream id resolves");
        assert_eq!(id, stream_id);

        WriteMessageStream::write(&mut stream, Bytes::from_static(b"payload"))
            .await
            .expect("write succeeds");
        WriteMessageStream::flush(&mut stream)
            .await
            .expect("flush succeeds");
        WriteMessageStream::shutdown(&mut stream)
            .await
            .expect("shutdown succeeds");
        WriteMessageStream::cancel(&mut stream, cancel_code)
            .await
            .expect("cancel succeeds");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![
                Event::Write(Bytes::from_static(b"payload")),
                Event::Flush,
                Event::Flush,
                Event::Shutdown,
                Event::Cancel(cancel_code),
            ]
        );
    }
}
