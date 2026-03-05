use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::Either};
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
