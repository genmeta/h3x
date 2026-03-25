use std::{
    future::poll_fn,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{stream::FusedStream, Sink, SinkExt, Stream, StreamExt, future::Either};
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

pin_project_lite::pin_project! {
    #[project = ReadBridgeStateProj]
    #[project_replace = ReadBridgeStateReplace]
    enum ReadBridgeState<St, RF, SF> {
        Stream { stream: St },
        Read {
            token: CancellationToken,
            #[pin] future: RF,
        },
        Stop {
            code: VarInt,
            #[pin] future: SF,
        },
        Empty,
    }
}

impl<St, RF, SF> ReadBridgeState<St, RF, SF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(ReadBridgeState::Empty) {
            ReadBridgeStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream"),
        }
    }
}

pin_project_lite::pin_project! {
    struct MessageReadBridge<R, RF, S, SF> {
        stream_id: VarInt,
        terminated: bool,
        #[pin]
        state: ReadBridgeState<MessageReadStreamClient, RF, SF>,
        read: R,
        stop: S,
    }
}

impl<R, RF, S, SF> quic::GetStreamId for MessageReadBridge<R, RF, S, SF> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<R, RF, S, SF> Stream for MessageReadBridge<R, RF, S, SF>
where
    R: Fn(MessageReadStreamClient, CancellationToken) -> RF,
    RF: Future<
        Output = Either<
            (
                MessageReadStreamClient,
                Option<Result<Bytes, MessageStreamError>>,
            ),
            MessageReadStreamClient,
        >,
    >,
    S: Fn(MessageReadStreamClient, VarInt) -> SF,
    SF: Future<Output = (MessageReadStreamClient, Result<(), quic::StreamError>)>,
{
    type Item = Result<Bytes, MessageStreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                ReadBridgeStateProj::Stream { .. } => {
                    if *project.terminated {
                        return Poll::Ready(None);
                    }
                    let stream = state.as_mut().take_stream();
                    let cancellation_token = CancellationToken::new();
                    state.set(ReadBridgeState::Read {
                        token: cancellation_token.clone(),
                        future: (project.read)(stream, cancellation_token),
                    });
                }
                ReadBridgeStateProj::Read { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            if result.is_none() {
                                *project.terminated = true;
                            }
                            state.set(ReadBridgeState::Stream { stream });
                            return Poll::Ready(result);
                        }
                        Either::Right(stream) => {
                            state.set(ReadBridgeState::Stream { stream });
                        }
                    };
                }
                ReadBridgeStateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(ReadBridgeState::Stream { stream });
                    // quic::StreamError → MessageStreamError via From
                    result?;
                }
                ReadBridgeStateProj::Empty => unreachable!("invalid state for poll_next"),
            };
        }
    }
}

impl<R, RF, S, SF> FusedStream for MessageReadBridge<R, RF, S, SF>
where
    R: Fn(MessageReadStreamClient, CancellationToken) -> RF,
    RF: Future<
        Output = Either<
            (
                MessageReadStreamClient,
                Option<Result<Bytes, MessageStreamError>>,
            ),
            MessageReadStreamClient,
        >,
    >,
    S: Fn(MessageReadStreamClient, VarInt) -> SF,
    SF: Future<Output = (MessageReadStreamClient, Result<(), quic::StreamError>)>,
{
    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

impl<R, RF, S, SF> quic::StopStream for MessageReadBridge<R, RF, S, SF>
where
    R: Fn(MessageReadStreamClient, CancellationToken) -> RF,
    RF: Future<
        Output = Either<
            (
                MessageReadStreamClient,
                Option<Result<Bytes, MessageStreamError>>,
            ),
            MessageReadStreamClient,
        >,
    >,
    S: Fn(MessageReadStreamClient, VarInt) -> SF,
    SF: Future<Output = (MessageReadStreamClient, Result<(), quic::StreamError>)>,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            let stream = match state.as_mut().project() {
                ReadBridgeStateProj::Stream { .. } => state.as_mut().take_stream(),
                ReadBridgeStateProj::Read { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                ReadBridgeStateProj::Stop { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(ReadBridgeState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                ReadBridgeStateProj::Empty => unreachable!("invalid state for poll_stop"),
            };
            state.set(ReadBridgeState::Stop {
                code,
                future: (project.stop)(stream, code),
            })
        }
    }
}

impl MessageReadStreamClient {
    /// Convert into a poll-based [`ReadMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl ReadMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(MessageReadBridge {
            stream_id,
            terminated: false,
            state: ReadBridgeState::Stream { stream: self },
            read: |mut client: MessageReadStreamClient,
                   token: CancellationToken|
                  async move {
                tokio::select! {
                    res = client.read() => Either::Left((client, res.transpose())),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            stop: |mut client: MessageReadStreamClient, code| async move {
                let res = client.stop(code).await;
                (client, res)
            },
        })
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

pin_project_lite::pin_project! {
    #[project = WriteBridgeStateProj]
    #[project_replace = WriteBridgeStateReplace]
    enum WriteBridgeState<St, WF, FF, SF, CF> {
        Stream { stream: St },
        Write {
            token: CancellationToken,
            #[pin] future: WF,
        },
        Flush {
            token: CancellationToken,
            #[pin] future: FF,
        },
        Shutdown {
            token: CancellationToken,
            #[pin] future: SF,
        },
        Cancel {
            code: VarInt,
            #[pin] future: CF,
        },
        Empty,
    }
}

impl<St, WF, FF, SF, CF> WriteBridgeState<St, WF, FF, SF, CF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(WriteBridgeState::Empty) {
            WriteBridgeStateReplace::Stream { stream } => stream,
            _ => unreachable!(
                "invalid state for take_stream, maybe poll_send before poll_ready"
            ),
        }
    }
}

pin_project_lite::pin_project! {
    struct MessageWriteBridge<W, WF, F, FF, S, SF, C, CF> {
        stream_id: VarInt,
        #[pin]
        state: WriteBridgeState<MessageWriteStreamClient, WF, FF, SF, CF>,
        write: W,
        flush: F,
        shutdown: S,
        cancel: C,
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::GetStreamId
    for MessageWriteBridge<W, WF, F, FF, S, SF, C, CF>
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<W, WF, F, FF, S, SF, C, CF> Sink<Bytes>
    for MessageWriteBridge<W, WF, F, FF, S, SF, C, CF>
where
    W: Fn(MessageWriteStreamClient, CancellationToken, Bytes) -> WF,
    WF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    F: Fn(MessageWriteStreamClient, CancellationToken) -> FF,
    FF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    S: Fn(MessageWriteStreamClient, CancellationToken) -> SF,
    SF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    C: Fn(MessageWriteStreamClient, VarInt) -> CF,
    CF: Future<Output = (MessageWriteStreamClient, Result<(), quic::StreamError>)>,
{
    type Error = MessageStreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                WriteBridgeStateProj::Stream { .. } => return Poll::Ready(Ok(())),
                WriteBridgeStateProj::Write { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteBridgeState::Stream { stream });
                        }
                    };
                }
                WriteBridgeStateProj::Flush { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteBridgeState::Stream { stream });
                        }
                    };
                }
                WriteBridgeStateProj::Shutdown { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteBridgeState::Stream { stream });
                        }
                    };
                }
                WriteBridgeStateProj::Cancel { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(WriteBridgeState::Stream { stream });
                    // quic::StreamError → MessageStreamError via From
                    result?;
                }
                WriteBridgeStateProj::Empty => unreachable!("invalid state for poll_ready"),
            };
        }
    }

    fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        let mut state = project.state;

        let stream = state.as_mut().take_stream();
        let cancellation_token = CancellationToken::new();
        state.set(WriteBridgeState::Write {
            token: cancellation_token.clone(),
            future: (project.write)(stream, cancellation_token, bytes),
        });
        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_flush = matches!(self.state, WriteBridgeState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_flush {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteBridgeState::Flush {
                token: cancellation_token.clone(),
                future: (project.flush)(stream, cancellation_token),
            });
        }
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_shutdown = matches!(self.state, WriteBridgeState::Shutdown { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_shutdown {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteBridgeState::Shutdown {
                token: cancellation_token.clone(),
                future: (project.shutdown)(stream, cancellation_token),
            });
        }
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::CancelStream
    for MessageWriteBridge<W, WF, F, FF, S, SF, C, CF>
where
    W: Fn(MessageWriteStreamClient, CancellationToken, Bytes) -> WF,
    WF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    F: Fn(MessageWriteStreamClient, CancellationToken) -> FF,
    FF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    S: Fn(MessageWriteStreamClient, CancellationToken) -> SF,
    SF: Future<
        Output = Either<
            (MessageWriteStreamClient, Result<(), MessageStreamError>),
            MessageWriteStreamClient,
        >,
    >,
    C: Fn(MessageWriteStreamClient, VarInt) -> CF,
    CF: Future<Output = (MessageWriteStreamClient, Result<(), quic::StreamError>)>,
{
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            let stream = match state.as_mut().project() {
                WriteBridgeStateProj::Stream { .. } => state.as_mut().take_stream(),
                WriteBridgeStateProj::Write { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteBridgeStateProj::Flush { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteBridgeStateProj::Shutdown { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteBridgeStateProj::Cancel { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(WriteBridgeState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                WriteBridgeStateProj::Empty => unreachable!("invalid state for poll_cancel"),
            };
            state.set(WriteBridgeState::Cancel {
                code,
                future: (project.cancel)(stream, code),
            })
        }
    }
}

impl MessageWriteStreamClient {
    /// Convert into a poll-based [`WriteMessageStream`].
    pub async fn into_message_stream(
        mut self,
    ) -> Result<impl WriteMessageStream, quic::StreamError> {
        let stream_id = self.stream_id().await?;
        Ok(MessageWriteBridge {
            stream_id,
            state: WriteBridgeState::Stream { stream: self },
            write: |mut client: MessageWriteStreamClient,
                    token: CancellationToken,
                    bytes| async move {
                tokio::select! {
                    res = client.write(bytes) => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            flush: |mut client: MessageWriteStreamClient,
                    token: CancellationToken| async move {
                tokio::select! {
                    res = client.flush() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            shutdown: |mut client: MessageWriteStreamClient,
                       token: CancellationToken| async move {
                tokio::select! {
                    res = client.shutdown() => Either::Left((client, res)),
                    _ = token.cancelled() => Either::Right(client),
                }
            },
            cancel: |mut client: MessageWriteStreamClient, code| async move {
                let res = client.cancel(code).await;
                (client, res)
            },
        })
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
