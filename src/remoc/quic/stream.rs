use std::{
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt, future::Either};
use tokio_util::sync::CancellationToken;

use crate::{
    dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
    quic,
    util::try_future::TryFuture,
    varint::VarInt,
};

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
    #[project = ReadStreamBridgeStateProj]
    #[project_replace = ReadStreamBridgeStateReplace]
    enum ReadStreamBridgeState<St, RF, SF> {
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

impl<St, RF, SF> ReadStreamBridgeState<St, RF, SF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(ReadStreamBridgeState::Empty) {
            ReadStreamBridgeStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream"),
        }
    }
}

pin_project_lite::pin_project! {
    struct ReadStreamBridge<R, RF, S, SF> {
        stream_id: VarInt,
        #[pin]
        state: ReadStreamBridgeState<ReadStreamClient, RF, SF>,

        read: R,
        stop: S,
    }
}

impl<R, RF, S, SF> quic::GetStreamId for ReadStreamBridge<R, RF, S, SF> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        _ = cx;
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<R, RF, S, SF> Stream for ReadStreamBridge<R, RF, S, SF>
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
                ReadStreamBridgeStateProj::Stream { .. } => {
                    let stream = state.as_mut().take_stream();
                    let cancellation_token = CancellationToken::new();
                    state.set(ReadStreamBridgeState::Read {
                        token: cancellation_token.clone(),
                        future: (project.read)(stream, cancellation_token),
                    });
                }
                ReadStreamBridgeStateProj::Read { future, .. } => {
                    match ready!(future.poll(cx)) {
                        // completed without cancellation
                        Either::Left((stream, result)) => {
                            state.set(ReadStreamBridgeState::Stream { stream });
                            return Poll::Ready(result);
                        }
                        Either::Right(stream) => {
                            state.set(ReadStreamBridgeState::Stream { stream });
                        }
                    };
                }
                ReadStreamBridgeStateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(ReadStreamBridgeState::Stream { stream });
                    result?;
                }
                ReadStreamBridgeStateProj::Empty => unreachable!("invalid state for poll_next"),
            };
        }
    }
}

impl<R, RF, S, SF> quic::StopStream for ReadStreamBridge<R, RF, S, SF>
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
                ReadStreamBridgeStateProj::Stream { .. } => state.as_mut().take_stream(),
                ReadStreamBridgeStateProj::Read { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                ReadStreamBridgeStateProj::Stop { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(ReadStreamBridgeState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                ReadStreamBridgeStateProj::Empty => unreachable!("invalid state for poll_stop"),
            };
            state.set(ReadStreamBridgeState::Stop {
                code,
                future: (project.stop)(stream, code),
            })
        }
    }
}

pub async fn new_remote_read_stream(
    mut client: ReadStreamClient,
) -> Result<impl quic::ReadStream, quic::StreamError> {
    Ok(ReadStreamBridge {
        stream_id: client.stream_id().await?,
        state: ReadStreamBridgeState::Stream { stream: client },
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

pub fn read_stream_client_into_quic(client: ReadStreamClient) -> BoxDynQuicStreamReader {
    Box::pin(TryFuture::from(new_remote_read_stream(client))) as BoxDynQuicStreamReader
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
    #[project = WriteStreamBridgeStateProj]
    #[project_replace = WriteStreamBridgeStateReplace]
    enum WriteStreamBridgeState<St, WF, FF, SF, CF> {
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

impl<St, WF, FF, SF, CF> WriteStreamBridgeState<St, WF, FF, SF, CF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(WriteStreamBridgeState::Empty) {
            WriteStreamBridgeStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream, maybe poll_send before poll_ready"),
        }
    }
}

pin_project_lite::pin_project! {
    struct WriteStreamBridge<W, WF, F, FF, S, SF, C, CF> {
        stream_id: VarInt,
        #[pin]
        state: WriteStreamBridgeState<WriteStreamClient, WF, FF, SF, CF>,

        write: W,
        flush: F,
        shutdown: S,
        cancel: C,
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::GetStreamId
    for WriteStreamBridge<W, WF, F, FF, S, SF, C, CF>
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        _ = cx;
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<W, WF, F, FF, S, SF, C, CF> Sink<Bytes> for WriteStreamBridge<W, WF, F, FF, S, SF, C, CF>
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
                WriteStreamBridgeStateProj::Stream { .. } => return Poll::Ready(Ok(())),
                WriteStreamBridgeStateProj::Write { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                        }
                    };
                }
                WriteStreamBridgeStateProj::Flush { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                        }
                    };
                }
                WriteStreamBridgeStateProj::Shutdown { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteStreamBridgeState::Stream { stream });
                        }
                    };
                }
                WriteStreamBridgeStateProj::Cancel { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(WriteStreamBridgeState::Stream { stream });
                    result?;
                }
                WriteStreamBridgeStateProj::Empty => unreachable!("invalid state for poll_ready"),
            };
        }
    }

    fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        let mut state = project.state;

        let stream = state.as_mut().take_stream();
        let cancellation_token = CancellationToken::new();
        state.set(WriteStreamBridgeState::Write {
            token: cancellation_token.clone(),
            future: (project.write)(stream, cancellation_token, bytes),
        });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_flush = matches!(self.state, WriteStreamBridgeState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_flush {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteStreamBridgeState::Flush {
                token: cancellation_token.clone(),
                future: (project.flush)(stream, cancellation_token),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_shutdown = matches!(self.state, WriteStreamBridgeState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_shutdown {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteStreamBridgeState::Shutdown {
                token: cancellation_token.clone(),
                future: (project.shutdown)(stream, cancellation_token),
            });
        }
    }
}

impl<W, WF, F, FF, S, SF, C, CF> quic::CancelStream
    for WriteStreamBridge<W, WF, F, FF, S, SF, C, CF>
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
                WriteStreamBridgeStateProj::Stream { .. } => state.as_mut().take_stream(),
                WriteStreamBridgeStateProj::Write { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStreamBridgeStateProj::Flush { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStreamBridgeStateProj::Shutdown { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStreamBridgeStateProj::Cancel { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(WriteStreamBridgeState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                WriteStreamBridgeStateProj::Empty => unreachable!("invalid state for poll_cancel"),
            };
            state.set(WriteStreamBridgeState::Cancel {
                code,
                future: (project.cancel)(stream, code),
            })
        }
    }
}

pub async fn new_remote_write_stream(
    mut client: WriteStreamClient,
) -> Result<impl quic::WriteStream, quic::StreamError> {
    Ok(WriteStreamBridge {
        stream_id: client.stream_id().await?,
        state: WriteStreamBridgeState::Stream { stream: client },
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

pub fn write_stream_client_into_quic(client: WriteStreamClient) -> BoxDynQuicStreamWriter {
    Box::pin(TryFuture::from(new_remote_write_stream(client))) as BoxDynQuicStreamWriter
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
