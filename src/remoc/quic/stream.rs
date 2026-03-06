use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, future::Either};
use remoc::prelude::ServerSharedMut;
use tokio_util::sync::CancellationToken;

use crate::{quic, varint::VarInt};

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

pin_project_lite::pin_project! {
    #[project = RemoteReadStreamStateProj]
    #[project_replace = RemoteReadStreamStateReplace]
    enum RemoteReadStreamState<St, RF, SF> {
        Stream {
            stream: St
        },
        Read {
            token: CancellationToken,
            #[pin] future: RF
        },
        Stop {
            code: VarInt,
            #[pin] future: SF
        },
        Empty,
    }
}

impl<St, RF, SF> RemoteReadStreamState<St, RF, SF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(RemoteReadStreamState::Empty) {
            RemoteReadStreamStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream"),
        }
    }
}

pin_project_lite::pin_project! {
    struct RemoteReadStreamInner<R, RF, S, SF> {
        stream_id: VarInt,
        #[pin]
        state: RemoteReadStreamState<ReadStreamClient, RF, SF>,

        read: R,
        stop: S,
    }
}

impl<R, RF, S, SF> quic::GetStreamId for RemoteReadStreamInner<R, RF, S, SF> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        _ = cx;
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<R, RF, S, SF> Stream for RemoteReadStreamInner<R, RF, S, SF>
where
    R: Fn(ReadStreamClient, CancellationToken) -> RF,
    RF: Future<
        Output = Either<
            (ReadStreamClient, Option<Result<Bytes, quic::StreamError>>),
            ReadStreamClient,
        >,
    >,
    S: Fn(ReadStreamClient, VarInt) -> SF,
    SF: Future<Output = (ReadStreamClient, Result<(), quic::StreamError>)>,
{
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                RemoteReadStreamStateProj::Stream { .. } => {
                    let stream = state.as_mut().take_stream();
                    let cancellation_token = CancellationToken::new();
                    state.set(RemoteReadStreamState::Read {
                        token: cancellation_token.clone(),
                        future: (project.read)(stream, cancellation_token),
                    });
                }
                RemoteReadStreamStateProj::Read { future, .. } => {
                    match ready!(future.poll(cx)) {
                        // completed without cancellation
                        Either::Left((stream, result)) => {
                            state.set(RemoteReadStreamState::Stream { stream });
                            return Poll::Ready(result);
                        }
                        Either::Right(stream) => {
                            state.set(RemoteReadStreamState::Stream { stream });
                        }
                    };
                }
                RemoteReadStreamStateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(RemoteReadStreamState::Stream { stream });
                    result?;
                }
                RemoteReadStreamStateProj::Empty => unreachable!("invalid state for poll_next"),
            };
        }
    }
}

impl<R, RF, S, SF> quic::StopStream for RemoteReadStreamInner<R, RF, S, SF>
where
    R: Fn(ReadStreamClient, CancellationToken) -> RF,
    RF: Future<
        Output = Either<
            (ReadStreamClient, Option<Result<Bytes, quic::StreamError>>),
            ReadStreamClient,
        >,
    >,
    S: Fn(ReadStreamClient, VarInt) -> SF,
    SF: Future<Output = (ReadStreamClient, Result<(), quic::StreamError>)>,
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
                RemoteReadStreamStateProj::Stream { .. } => state.as_mut().take_stream(),
                RemoteReadStreamStateProj::Read { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                RemoteReadStreamStateProj::Stop { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(RemoteReadStreamState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                RemoteReadStreamStateProj::Empty => unreachable!("invalid state for poll_stop"),
            };
            state.set(RemoteReadStreamState::Stop {
                code,
                future: (project.stop)(stream, code),
            })
        }
    }
}

pub async fn new_remote_read_stream(
    mut client: ReadStreamClient,
) -> Result<impl quic::ReadStream, quic::StreamError> {
    Ok(RemoteReadStreamInner {
        stream_id: client.stream_id().await?,
        state: RemoteReadStreamState::Stream { stream: client },
        read: |mut client: ReadStreamClient, token: CancellationToken| async move {
            tokio::select! {
                res = client.read() => Either::Left((client, res.transpose())),
                _ = token.cancelled() => Either::Right(client),
            }
        },
        stop: |mut client: ReadStreamClient, code| async move {
            let res = client.stop(code).await;
            (client, res)
        },
    })
}

/// Serializable wrapper around a remoc-generated [`ReadStreamClient`].
///
/// Unlike [`RemoteQuicConnection`](super::RemoteQuicConnection) which directly
/// implements the `quic::Connection` trait, `RemoteReadStream` requires an
/// explicit [`into_quic`](Self::into_quic) conversion step because the standard
/// `quic::ReadStream` trait uses poll-based methods (`Stream`, `StopStream`)
/// that cannot directly bridge to the async RTC client methods.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RemoteReadStream {
    client: ReadStreamClient,
}

impl RemoteReadStream {
    /// Create a new wrapper from a remoc-generated read stream client.
    pub fn new(client: ReadStreamClient) -> Self {
        Self { client }
    }

    /// Convert into a type implementing [`quic::ReadStream`].
    ///
    /// This async step is necessary because the poll-based `quic::ReadStream`
    /// trait requires an initial `stream_id` query from the remote side.
    pub async fn into_quic(self) -> Result<impl quic::ReadStream, quic::StreamError> {
        new_remote_read_stream(self.client).await
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

pin_project_lite::pin_project! {
    #[project = RemoteWriteStreamStateProj]
    #[project_replace = RemoteWriteStreamStateReplace]
    enum RemoteWriteStreamState<St, WF, FF, SF, CF> {
        Stream {
            stream: St
        },
        Write {
            token: CancellationToken,
            #[pin] future: WF
        },
        Flush {
            token: CancellationToken,
            #[pin] future: FF
        },
        Shutdown {
            token: CancellationToken,
            #[pin] future: SF
        },
        Cancel {
            code: VarInt,
            #[pin] future: CF
        },
        Empty,
    }
}

impl<St, WF, FF, SF, CF> RemoteWriteStreamState<St, WF, FF, SF, CF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(RemoteWriteStreamState::Empty) {
            RemoteWriteStreamStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream, maybe poll_send before poll_ready"),
        }
    }
}

pin_project_lite::pin_project! {
    struct RemoteWriteStreamInner<W, WF, F, FF, S, SF, C, CF> {
        stream_id: VarInt,
        #[pin]
        state: RemoteWriteStreamState<WriteStreamClient, WF, FF, SF, CF>,

        write: W,
        flush: F,
        shutdown: S,
        cancel: C,
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::GetStreamId
    for RemoteWriteStreamInner<W, WF, F, FF, S, SF, C, CF>
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        _ = cx;
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<W, WF, F, FF, S, SF, C, CF> Sink<Bytes> for RemoteWriteStreamInner<W, WF, F, FF, S, SF, C, CF>
where
    W: Fn(WriteStreamClient, CancellationToken, Bytes) -> WF,
    WF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    F: Fn(WriteStreamClient, CancellationToken) -> FF,
    FF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    S: Fn(WriteStreamClient, CancellationToken) -> SF,
    SF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    C: Fn(WriteStreamClient, VarInt) -> CF,
    CF: Future<Output = (WriteStreamClient, Result<(), quic::StreamError>)>,
{
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                RemoteWriteStreamStateProj::Stream { .. } => return Poll::Ready(Ok(())),
                RemoteWriteStreamStateProj::Write { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                        }
                    };
                }
                RemoteWriteStreamStateProj::Flush { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                        }
                    };
                }
                RemoteWriteStreamStateProj::Shutdown { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(RemoteWriteStreamState::Stream { stream });
                        }
                    };
                }
                RemoteWriteStreamStateProj::Cancel { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(RemoteWriteStreamState::Stream { stream });
                    result?;
                }
                RemoteWriteStreamStateProj::Empty => unreachable!("invalid state for poll_ready"),
            };
        }
    }

    fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        let mut state = project.state;

        let stream = state.as_mut().take_stream();
        let cancellation_token = CancellationToken::new();
        state.set(RemoteWriteStreamState::Write {
            token: cancellation_token.clone(),
            future: (project.write)(stream, cancellation_token, bytes),
        });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_flush = matches!(self.state, RemoteWriteStreamState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_flush {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(RemoteWriteStreamState::Flush {
                token: cancellation_token.clone(),
                future: (project.flush)(stream, cancellation_token),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_shutdown = matches!(self.state, RemoteWriteStreamState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_shutdown {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(RemoteWriteStreamState::Shutdown {
                token: cancellation_token.clone(),
                future: (project.shutdown)(stream, cancellation_token),
            });
        }
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::CancelStream
    for RemoteWriteStreamInner<W, WF, F, FF, S, SF, C, CF>
where
    W: Fn(WriteStreamClient, CancellationToken, Bytes) -> WF,
    WF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    F: Fn(WriteStreamClient, CancellationToken) -> FF,
    FF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    S: Fn(WriteStreamClient, CancellationToken) -> SF,
    SF: Future<
        Output = Either<(WriteStreamClient, Result<(), quic::StreamError>), WriteStreamClient>,
    >,
    C: Fn(WriteStreamClient, VarInt) -> CF,
    CF: Future<Output = (WriteStreamClient, Result<(), quic::StreamError>)>,
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
                RemoteWriteStreamStateProj::Stream { .. } => state.as_mut().take_stream(),
                RemoteWriteStreamStateProj::Write { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                RemoteWriteStreamStateProj::Flush { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                RemoteWriteStreamStateProj::Shutdown { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                RemoteWriteStreamStateProj::Cancel { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(RemoteWriteStreamState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                RemoteWriteStreamStateProj::Empty => unreachable!("invalid state for poll_cancel"),
            };
            state.set(RemoteWriteStreamState::Cancel {
                code,
                future: (project.cancel)(stream, code),
            })
        }
    }
}

pub async fn new_remote_write_stream(
    mut client: WriteStreamClient,
) -> Result<impl quic::WriteStream, quic::StreamError> {
    Ok(RemoteWriteStreamInner {
        stream_id: client.stream_id().await?,
        state: RemoteWriteStreamState::Stream { stream: client },
        write: |mut client: WriteStreamClient, token: CancellationToken, bytes| async move {
            tokio::select! {
                res = client.write(bytes) => Either::Left((client, res)),
                _ = token.cancelled() => Either::Right(client),
            }
        },
        flush: |mut client: WriteStreamClient, token: CancellationToken| async move {
            tokio::select! {
                res = client.flush() => Either::Left((client, res)),
                _ = token.cancelled() => Either::Right(client),
            }
        },
        shutdown: |mut client: WriteStreamClient, token: CancellationToken| async move {
            tokio::select! {
                res = client.shutdown() => Either::Left((client, res)),
                _ = token.cancelled() => Either::Right(client),
            }
        },
        cancel: |mut client: WriteStreamClient, code| async move {
            let res = client.cancel(code).await;
            (client, res)
        },
    })
}

/// Serializable wrapper around a remoc-generated [`WriteStreamClient`].
///
/// Unlike [`RemoteQuicConnection`](super::RemoteQuicConnection) which directly
/// implements the `quic::Connection` trait, `RemoteWriteStream` requires an
/// explicit [`into_quic`](Self::into_quic) conversion step because the standard
/// `quic::WriteStream` trait uses poll-based methods (`Sink`, `CancelStream`)
/// that cannot directly bridge to the async RTC client methods.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RemoteWriteStream {
    client: WriteStreamClient,
}

impl RemoteWriteStream {
    /// Create a new wrapper from a remoc-generated write stream client.
    pub fn new(client: WriteStreamClient) -> Self {
        Self { client }
    }

    /// Convert into a type implementing [`quic::WriteStream`].
    ///
    /// This async step is necessary because the poll-based `quic::WriteStream`
    /// trait requires an initial `stream_id` query from the remote side.
    pub async fn into_quic(self) -> Result<impl quic::WriteStream, quic::StreamError> {
        new_remote_write_stream(self.client).await
    }
}

/// Server-side wrapper that implements the remoc [`ReadStream`] RTC trait
/// for any local [`quic::ReadStream`] implementation.
///
/// Uses generics instead of dynamic dispatch. The inner stream is stored as
/// `Pin<Box<S>>` to handle poll-based methods that require pinning.
/// Since the RTC trait provides `&mut self`, exclusive access is guaranteed
/// and no mutex is needed.
pub struct LocalReadStream<S> {
    inner: Pin<Box<S>>,
}

// SAFETY: `LocalReadStream` is only accessed through `&mut self` methods.
// The RTC server wraps it in `RwLock` which provides synchronization.
// The inner `Pin<Box<S>>` is never shared across threads without the lock.
unsafe impl<S: Send> Sync for LocalReadStream<S> {}

impl<S> LocalReadStream<S>
where
    S: quic::ReadStream + 'static,
{
    /// Wrap a local read stream so it can be served over remoc RTC.
    pub fn new(stream: S) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }

    /// Convert this local read stream into a serializable [`RemoteReadStream`]
    /// and a future that serves the RTC connection.
    ///
    /// The returned future must be polled (e.g. spawned) for the remote stream
    /// to function. When the future completes, the RTC serving session has ended.
    pub fn into_remote(self) -> (RemoteReadStream, impl Future<Output = ()> + Send + 'static) {
        let (server, client) =
            ReadStreamServerSharedMut::new(Arc::new(tokio::sync::RwLock::new(self)), 1);
        let remote = RemoteReadStream::new(client);
        let fut = async move {
            let _ = server.serve(true).await;
        };
        (remote, fut)
    }
}

impl<S> ReadStream for LocalReadStream<S>
where
    S: quic::ReadStream + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_stream_id(cx)).await
    }

    async fn read(&mut self) -> Result<Option<Bytes>, quic::StreamError> {
        self.inner.as_mut().next().await.transpose()
    }

    async fn stop(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_stop(cx, code)).await
    }
}

/// Server-side wrapper that implements the remoc [`WriteStream`] RTC trait
/// for any local [`quic::WriteStream`] implementation.
///
/// Uses generics instead of dynamic dispatch. The inner stream is stored as
/// `Pin<Box<S>>` to handle poll-based methods that require pinning.
/// Since the RTC trait provides `&mut self`, exclusive access is guaranteed
/// and no mutex is needed.
pub struct LocalWriteStream<S> {
    inner: Pin<Box<S>>,
}

// SAFETY: `LocalWriteStream` is only accessed through `&mut self` methods.
// The RTC server wraps it in `RwLock` which provides synchronization.
// The inner `Pin<Box<S>>` is never shared across threads without the lock.
unsafe impl<S: Send> Sync for LocalWriteStream<S> {}

impl<S> LocalWriteStream<S>
where
    S: quic::WriteStream + 'static,
{
    /// Wrap a local write stream so it can be served over remoc RTC.
    pub fn new(stream: S) -> Self {
        Self {
            inner: Box::pin(stream),
        }
    }

    /// Convert this local write stream into a serializable [`RemoteWriteStream`]
    /// and a future that serves the RTC connection.
    ///
    /// The returned future must be polled (e.g. spawned) for the remote stream
    /// to function. When the future completes, the RTC serving session has ended.
    pub fn into_remote(self) -> (RemoteWriteStream, impl Future<Output = ()> + Send + 'static) {
        let (server, client) =
            WriteStreamServerSharedMut::new(Arc::new(tokio::sync::RwLock::new(self)), 1);
        let remote = RemoteWriteStream::new(client);
        let fut = async move {
            let _ = server.serve(true).await;
        };
        (remote, fut)
    }
}

impl<S> WriteStream for LocalWriteStream<S>
where
    S: quic::WriteStream + Send,
{
    async fn stream_id(&mut self) -> Result<VarInt, quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_stream_id(cx)).await
    }

    async fn write(&mut self, data: Bytes) -> Result<(), quic::StreamError> {
        self.inner.as_mut().send(data).await
    }

    async fn flush(&mut self) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_flush(cx)).await
    }

    async fn shutdown(&mut self) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_close(cx)).await
    }

    async fn cancel(&mut self, code: VarInt) -> Result<(), quic::StreamError> {
        poll_fn(|cx| self.inner.as_mut().poll_cancel(cx, code)).await
    }
}
