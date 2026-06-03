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
    quic::{self, GetStreamIdExt, ResetStreamExt, StopStreamExt},
    util::deferred::{DeferredStreamReader, DeferredStreamWriter},
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
/// (`stream_id`, `reset`) use [`quic::StreamError`].
#[remoc::rtc::remote]
pub trait WriteMessageStream: Send {
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError>;
    async fn write(&mut self, data: Bytes) -> Result<(), MessageStreamError>;
    async fn flush(&mut self) -> Result<(), MessageStreamError>;
    async fn shutdown(&mut self) -> Result<(), MessageStreamError>;
    async fn reset(&mut self, code: VarInt) -> Result<(), quic::StreamError>;
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

    async fn reset(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        ResetStreamExt::reset(self, code).await
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
        Box::pin(DeferredStreamReader::from(self.into_message_stream()))
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
                let res = client.reset(code).await;
                (client, res)
            },
        ))
    }

    /// Convert into a boxed [`OrigWriteMessageStream`] (lazy — resolves on first poll).
    pub fn into_boxed_message_stream(
        self,
    ) -> Pin<Box<dyn OrigWriteMessageStream + Send + 'static>> {
        Box::pin(DeferredStreamWriter::from(self.into_message_stream()))
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
        future::poll_fn,
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt, stream::FusedStream};
    use remoc::prelude::Server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::Instrument;

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
        Reset(VarInt),
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

    impl quic::ResetStream for TestWriteMessageStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Reset(code));
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

    struct BlockingReadMessageStream {
        stream_id: VarInt,
        read_started: Arc<AtomicBool>,
        stopped: Arc<Mutex<Option<VarInt>>>,
    }

    impl quic::GetStreamId for BlockingReadMessageStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for BlockingReadMessageStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for BlockingReadMessageStream {
        type Item = Result<Bytes, MessageStreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.read_started.store(true, Ordering::Relaxed);
            Poll::Pending
        }
    }

    impl FusedStream for BlockingReadMessageStream {
        fn is_terminated(&self) -> bool {
            false
        }
    }

    struct BlockingWriteMessageStream {
        stream_id: VarInt,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl quic::GetStreamId for BlockingWriteMessageStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::ResetStream for BlockingWriteMessageStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.events
                .lock()
                .expect("event log poisoned")
                .push(Event::Reset(code));
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for BlockingWriteMessageStream {
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
            Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn spawn_read_server(
        stream: impl ReadMessageStream + 'static,
    ) -> (ReadMessageStreamClient, tokio::task::JoinHandle<()>) {
        let (server, client) = ReadMessageStreamServer::new(stream, 1);
        let task = tokio::spawn(
            async move {
                let _ = server.serve().await;
            }
            .in_current_span(),
        );
        (client, task)
    }

    fn spawn_write_server(
        stream: impl WriteMessageStream + 'static,
    ) -> (WriteMessageStreamClient, tokio::task::JoinHandle<()>) {
        let (server, client) = WriteMessageStreamServer::new(stream, 1);
        let task = tokio::spawn(
            async move {
                let _ = server.serve().await;
            }
            .in_current_span(),
        );
        (client, task)
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
        let reset_code = VarInt::from_u32(29);
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
        WriteMessageStream::reset(&mut stream, reset_code)
            .await
            .expect("reset succeeds");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![
                Event::Write(Bytes::from_static(b"payload")),
                Event::Flush,
                Event::Flush,
                Event::Shutdown,
                Event::Reset(reset_code),
            ]
        );
    }

    #[tokio::test]
    async fn read_client_into_message_stream_delegates_and_propagates_errors() {
        let stopped = Arc::new(Mutex::new(None));
        let stop_code = VarInt::from_u32(41);
        let (client, task) = spawn_read_server(TestReadMessageStream {
            stream_id: VarInt::from_u32(31),
            chunks: VecDeque::from([
                Ok(Bytes::from_static(b"one")),
                Err(MessageStreamError::MalformedIncomingMessage),
            ]),
            stopped: stopped.clone(),
            terminated: false,
        });

        let mut stream = Box::pin(
            client
                .into_message_stream()
                .await
                .expect("stream conversion succeeds"),
        );
        assert_eq!(
            GetStreamIdExt::stream_id(&mut stream.as_mut())
                .await
                .expect("stream id resolves"),
            VarInt::from_u32(31)
        );
        assert_eq!(
            stream
                .as_mut()
                .next()
                .await
                .expect("chunk present")
                .expect("chunk read succeeds"),
            Bytes::from_static(b"one")
        );

        let error = stream
            .as_mut()
            .next()
            .await
            .expect("error item present")
            .expect_err("stream propagates remote message errors");
        assert!(matches!(
            error,
            MessageStreamError::MalformedIncomingMessage
        ));

        StopStreamExt::stop(&mut stream.as_mut(), stop_code)
            .await
            .expect("stop succeeds");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );

        drop(stream);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("read server exits")
            .expect("read server task joins");
    }

    #[tokio::test]
    async fn read_client_box_adapters_are_lazy_and_read_bytes() {
        let (boxed_client, boxed_task) = spawn_read_server(TestReadMessageStream {
            stream_id: VarInt::from_u32(33),
            chunks: VecDeque::from([
                Ok(Bytes::from_static(b"hel")),
                Ok(Bytes::from_static(b"lo")),
            ]),
            stopped: Arc::new(Mutex::new(None)),
            terminated: false,
        });
        let mut boxed_stream = boxed_client.into_boxed_message_stream();
        assert_eq!(
            boxed_stream
                .as_mut()
                .next()
                .await
                .expect("chunk present")
                .expect("boxed read succeeds"),
            Bytes::from_static(b"hel")
        );
        drop(boxed_stream);
        tokio::time::timeout(Duration::from_secs(1), boxed_task)
            .await
            .expect("boxed read server exits")
            .expect("boxed read server task joins");

        let (reader_client, reader_task) = spawn_read_server(TestReadMessageStream {
            stream_id: VarInt::from_u32(35),
            chunks: VecDeque::from([
                Ok(Bytes::from_static(b"wo")),
                Ok(Bytes::from_static(b"rld")),
            ]),
            stopped: Arc::new(Mutex::new(None)),
            terminated: false,
        });
        let mut reader = reader_client.into_box_reader();
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .await
            .expect("box reader reads all bytes");
        assert_eq!(buf, b"world");
        drop(reader);
        tokio::time::timeout(Duration::from_secs(1), reader_task)
            .await
            .expect("box reader server exits")
            .expect("box reader server task joins");
    }

    #[tokio::test]
    async fn read_client_stop_cancels_pending_remote_read() {
        let read_started = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(Mutex::new(None));
        let stop_code = VarInt::from_u32(43);
        let (client, task) = spawn_read_server(BlockingReadMessageStream {
            stream_id: VarInt::from_u32(37),
            read_started: read_started.clone(),
            stopped: stopped.clone(),
        });

        let mut stream = Box::pin(
            client
                .into_message_stream()
                .await
                .expect("stream conversion succeeds"),
        );
        let pending = poll_fn(|cx| stream.as_mut().poll_next(cx)).now_or_never();
        assert!(pending.is_none(), "blocking read should remain pending");
        let _ = read_started;

        StopStreamExt::stop(&mut stream.as_mut(), stop_code)
            .await
            .expect("stop succeeds");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn read_client_into_message_stream_maps_stream_id_call_errors() {
        let (server, client) = ReadMessageStreamServer::new(
            TestReadMessageStream {
                stream_id: VarInt::from_u32(39),
                chunks: VecDeque::new(),
                stopped: Arc::new(Mutex::new(None)),
                terminated: false,
            },
            1,
        );
        drop(server);

        let result = tokio::time::timeout(Duration::from_secs(1), client.into_message_stream())
            .await
            .expect("stream id failure returns promptly");
        let Err(error) = result else {
            panic!("dropped server should fail stream conversion");
        };
        let quic::StreamError::Connection { source } = error else {
            panic!("call errors should map to connection-scoped stream errors");
        };
        assert!(source.is_transport());
    }

    #[tokio::test]
    async fn write_client_into_message_stream_delegates_and_box_writer_writes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reset_code = VarInt::from_u32(47);
        let (client, task) = spawn_write_server(TestWriteMessageStream {
            stream_id: VarInt::from_u32(45),
            events: events.clone(),
        });

        let mut stream = Box::pin(
            client
                .into_message_stream()
                .await
                .expect("stream conversion succeeds"),
        );
        assert_eq!(
            GetStreamIdExt::stream_id(&mut stream.as_mut())
                .await
                .expect("stream id resolves"),
            VarInt::from_u32(45)
        );
        stream
            .as_mut()
            .feed(Bytes::from_static(b"payload"))
            .await
            .expect("write succeeds");
        SinkExt::flush(&mut stream.as_mut())
            .await
            .expect("flush succeeds");
        stream.as_mut().close().await.expect("shutdown succeeds");
        ResetStreamExt::reset(&mut stream.as_mut(), reset_code)
            .await
            .expect("reset succeeds");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![
                Event::Write(Bytes::from_static(b"payload")),
                Event::Flush,
                Event::Flush,
                Event::Shutdown,
                Event::Reset(reset_code),
            ]
        );
        drop(stream);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("write server exits")
            .expect("write server task joins");

        let writer_events = Arc::new(Mutex::new(Vec::new()));
        let (writer_client, writer_task) = spawn_write_server(TestWriteMessageStream {
            stream_id: VarInt::from_u32(49),
            events: writer_events.clone(),
        });
        let mut writer = writer_client.into_box_writer();
        writer
            .write_all(b"boxed")
            .await
            .expect("boxed writer writes");
        AsyncWriteExt::flush(&mut writer)
            .await
            .expect("boxed writer flushes");
        AsyncWriteExt::shutdown(&mut writer)
            .await
            .expect("boxed writer shuts down");

        assert_eq!(
            *writer_events.lock().expect("event log poisoned"),
            vec![
                Event::Write(Bytes::from_static(b"boxed")),
                Event::Flush,
                Event::Flush,
                Event::Shutdown,
            ]
        );
        drop(writer);
        tokio::time::timeout(Duration::from_secs(1), writer_task)
            .await
            .expect("box writer server exits")
            .expect("box writer server task joins");
    }

    #[tokio::test]
    async fn write_client_reset_interrupts_pending_remote_write() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reset_code = VarInt::from_u32(53);
        let (client, task) = spawn_write_server(BlockingWriteMessageStream {
            stream_id: VarInt::from_u32(51),
            events: events.clone(),
        });

        let mut stream = Box::pin(
            client
                .into_message_stream()
                .await
                .expect("stream conversion succeeds"),
        );
        poll_fn(|cx| stream.as_mut().poll_ready(cx))
            .await
            .expect("stream becomes ready");
        stream
            .as_mut()
            .start_send(Bytes::from_static(b"pending"))
            .expect("start send succeeds");

        ResetStreamExt::reset(&mut stream.as_mut(), reset_code)
            .await
            .expect("reset succeeds");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![Event::Reset(reset_code),]
        );

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn write_client_into_message_stream_maps_stream_id_call_errors() {
        let (server, client) = WriteMessageStreamServer::new(
            TestWriteMessageStream {
                stream_id: VarInt::from_u32(55),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            1,
        );
        drop(server);

        let result = tokio::time::timeout(Duration::from_secs(1), client.into_message_stream())
            .await
            .expect("stream id failure returns promptly");
        let Err(error) = result else {
            panic!("dropped server should fail stream conversion");
        };
        let quic::StreamError::Connection { source } = error else {
            panic!("call errors should map to connection-scoped stream errors");
        };
        assert!(source.is_transport());
    }
}
