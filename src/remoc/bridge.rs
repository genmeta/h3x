//! Generic bridge state machines for converting remoc RTC clients back into
//! poll-based streams (`Stream`, `Sink`, `GetStreamId`, `StopStream`, `CancelStream`).
//!
//! Both QUIC-level and message-level stream clients share the same state machine
//! logic; only the client type and data error type differ. This module provides
//! [`ReadBridge`] and [`WriteBridge`] parameterised over those axes.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::Either, stream::FusedStream};
use tokio_util::sync::CancellationToken;

use crate::{quic, varint::VarInt};

// ---------------------------------------------------------------------------
// ReadBridge
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = ReadStateProj]
    #[project_replace = ReadStateReplace]
    enum ReadState<St, RF, SF> {
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

impl<St, RF, SF> ReadState<St, RF, SF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(ReadState::Empty) {
            ReadStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream"),
        }
    }
}

pin_project_lite::pin_project! {
    /// Generic read bridge: converts an RTC client into a poll-based
    /// `Stream + StopStream + GetStreamId`.
    ///
    /// - `St`: client type stored in the state machine
    /// - `E`: data error type (`Stream::Item = Result<Bytes, E>`)
    /// - `R / RF`: read closure and its future
    /// - `S / SF`: stop closure and its future
    pub(super) struct ReadBridge<St, E, R, RF, S, SF> {
        stream_id: VarInt,
        terminated: bool,
        #[pin]
        state: ReadState<St, RF, SF>,

        read: R,
        stop: S,

        // PhantomData to carry `E` without storing it.
        _error: std::marker::PhantomData<fn() -> E>,
    }
}

impl<St, E, R, RF, S, SF> ReadBridge<St, E, R, RF, S, SF> {
    pub(super) fn new(stream_id: VarInt, client: St, read: R, stop: S) -> Self {
        Self {
            stream_id,
            terminated: false,
            state: ReadState::Stream { stream: client },
            read,
            stop,
            _error: std::marker::PhantomData,
        }
    }
}

impl<St, E, R, RF, S, SF> quic::GetStreamId for ReadBridge<St, E, R, RF, S, SF> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<St, E, R, RF, S, SF> Stream for ReadBridge<St, E, R, RF, S, SF>
where
    E: From<quic::StreamError>,
    R: Fn(St, CancellationToken) -> RF,
    RF: Future<Output = Either<(St, Option<Result<Bytes, E>>), St>>,
    S: Fn(St, VarInt) -> SF,
    SF: Future<Output = (St, Result<(), quic::StreamError>)>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                ReadStateProj::Stream { .. } => {
                    if *project.terminated {
                        return Poll::Ready(None);
                    }
                    let stream = state.as_mut().take_stream();
                    let cancellation_token = CancellationToken::new();
                    state.set(ReadState::Read {
                        token: cancellation_token.clone(),
                        future: (project.read)(stream, cancellation_token),
                    });
                }
                ReadStateProj::Read { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            if result.is_none() {
                                *project.terminated = true;
                            }
                            state.set(ReadState::Stream { stream });
                            return Poll::Ready(result);
                        }
                        Either::Right(stream) => {
                            state.set(ReadState::Stream { stream });
                        }
                    };
                }
                ReadStateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(ReadState::Stream { stream });
                    result?;
                }
                ReadStateProj::Empty => unreachable!("invalid state for poll_next"),
            };
        }
    }
}

impl<St, E, R, RF, S, SF> FusedStream for ReadBridge<St, E, R, RF, S, SF>
where
    E: From<quic::StreamError>,
    R: Fn(St, CancellationToken) -> RF,
    RF: Future<Output = Either<(St, Option<Result<Bytes, E>>), St>>,
    S: Fn(St, VarInt) -> SF,
    SF: Future<Output = (St, Result<(), quic::StreamError>)>,
{
    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

impl<St, E, R, RF, S, SF> quic::StopStream for ReadBridge<St, E, R, RF, S, SF>
where
    E: From<quic::StreamError>,
    R: Fn(St, CancellationToken) -> RF,
    RF: Future<Output = Either<(St, Option<Result<Bytes, E>>), St>>,
    S: Fn(St, VarInt) -> SF,
    SF: Future<Output = (St, Result<(), quic::StreamError>)>,
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
                ReadStateProj::Stream { .. } => state.as_mut().take_stream(),
                ReadStateProj::Read { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                ReadStateProj::Stop { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(ReadState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                ReadStateProj::Empty => unreachable!("invalid state for poll_stop"),
            };
            state.set(ReadState::Stop {
                code,
                future: (project.stop)(stream, code),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// WriteBridge
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = WriteStateProj]
    #[project_replace = WriteStateReplace]
    enum WriteState<St, WF, FF, SF, CF> {
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

impl<St, WF, FF, SF, CF> WriteState<St, WF, FF, SF, CF> {
    fn take_stream(self: Pin<&mut Self>) -> St {
        match self.project_replace(WriteState::Empty) {
            WriteStateReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream, maybe poll_send before poll_ready"),
        }
    }
}

pin_project_lite::pin_project! {
    /// Generic write bridge: converts an RTC client into a poll-based
    /// `Sink<Bytes> + CancelStream + GetStreamId`.
    ///
    /// - `St`: client type
    /// - `E`: data error type (`Sink::Error`)
    /// - `W / WF`: write closure / future
    /// - `F / FF`: flush closure / future
    /// - `S / SF`: shutdown closure / future
    /// - `C / CF`: cancel closure / future
    pub(super) struct WriteBridge<St, E, W, WF, F, FF, S, SF, C, CF> {
        stream_id: VarInt,
        #[pin]
        state: WriteState<St, WF, FF, SF, CF>,

        write: W,
        flush: F,
        shutdown: S,
        cancel: C,

        _error: std::marker::PhantomData<fn() -> E>,
    }
}

impl<St, E, W, WF, F, FF, S, SF, C, CF> WriteBridge<St, E, W, WF, F, FF, S, SF, C, CF> {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        stream_id: VarInt,
        client: St,
        write: W,
        flush: F,
        shutdown: S,
        cancel: C,
    ) -> Self {
        Self {
            stream_id,
            state: WriteState::Stream { stream: client },
            write,
            flush,
            shutdown,
            cancel,
            _error: std::marker::PhantomData,
        }
    }
}

impl<St, E, W, WF, F, FF, S, SF, C, CF> quic::GetStreamId
    for WriteBridge<St, E, W, WF, F, FF, S, SF, C, CF>
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl<St, E, W, WF, F, FF, S, SF, C, CF> Sink<Bytes>
    for WriteBridge<St, E, W, WF, F, FF, S, SF, C, CF>
where
    E: From<quic::StreamError>,
    W: Fn(St, CancellationToken, Bytes) -> WF,
    WF: Future<Output = Either<(St, Result<(), E>), St>>,
    F: Fn(St, CancellationToken) -> FF,
    FF: Future<Output = Either<(St, Result<(), E>), St>>,
    S: Fn(St, CancellationToken) -> SF,
    SF: Future<Output = Either<(St, Result<(), E>), St>>,
    C: Fn(St, VarInt) -> CF,
    CF: Future<Output = (St, Result<(), quic::StreamError>)>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        let mut state = project.state;

        loop {
            match state.as_mut().project() {
                WriteStateProj::Stream { .. } => return Poll::Ready(Ok(())),
                WriteStateProj::Write { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteState::Stream { stream });
                        }
                    };
                }
                WriteStateProj::Flush { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteState::Stream { stream });
                        }
                    };
                }
                WriteStateProj::Shutdown { future, .. } => {
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, result)) => {
                            state.set(WriteState::Stream { stream });
                            result?;
                        }
                        Either::Right(stream) => {
                            state.set(WriteState::Stream { stream });
                        }
                    };
                }
                WriteStateProj::Cancel { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    state.set(WriteState::Stream { stream });
                    result?;
                }
                WriteStateProj::Empty => unreachable!("invalid state for poll_ready"),
            };
        }
    }

    fn start_send(self: Pin<&mut Self>, bytes: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        let mut state = project.state;

        let stream = state.as_mut().take_stream();
        let cancellation_token = CancellationToken::new();
        state.set(WriteState::Write {
            token: cancellation_token.clone(),
            future: (project.write)(stream, cancellation_token, bytes),
        });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_flush = matches!(self.state, WriteState::Flush { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_flush {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteState::Flush {
                token: cancellation_token.clone(),
                future: (project.flush)(stream, cancellation_token),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            let is_shutdown = matches!(self.state, WriteState::Shutdown { .. });

            ready!(self.as_mut().poll_ready(cx)?);
            if is_shutdown {
                return Poll::Ready(Ok(()));
            }

            let project = self.as_mut().project();
            let mut state = project.state;

            let stream = state.as_mut().take_stream();
            let cancellation_token = CancellationToken::new();
            state.set(WriteState::Shutdown {
                token: cancellation_token.clone(),
                future: (project.shutdown)(stream, cancellation_token),
            });
        }
    }
}

impl<St, E, W, WF, F, FF, S, SF, C, CF> quic::CancelStream
    for WriteBridge<St, E, W, WF, F, FF, S, SF, C, CF>
where
    E: From<quic::StreamError>,
    W: Fn(St, CancellationToken, Bytes) -> WF,
    WF: Future<Output = Either<(St, Result<(), E>), St>>,
    F: Fn(St, CancellationToken) -> FF,
    FF: Future<Output = Either<(St, Result<(), E>), St>>,
    S: Fn(St, CancellationToken) -> SF,
    SF: Future<Output = Either<(St, Result<(), E>), St>>,
    C: Fn(St, VarInt) -> CF,
    CF: Future<Output = (St, Result<(), quic::StreamError>)>,
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
                WriteStateProj::Stream { .. } => state.as_mut().take_stream(),
                WriteStateProj::Write { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStateProj::Flush { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStateProj::Shutdown { future, token } => {
                    token.cancel();
                    let (Either::Left((stream, ..)) | Either::Right(stream)) =
                        ready!(future.poll(cx));
                    stream
                }
                WriteStateProj::Cancel { future, code: sent } => {
                    let (stream, result) = ready!(future.poll(cx));
                    if *sent == code {
                        state.set(WriteState::Stream { stream });
                        return Poll::Ready(result);
                    } else {
                        stream
                    }
                }
                WriteStateProj::Empty => unreachable!("invalid state for poll_cancel"),
            };
            state.set(WriteState::Cancel {
                code,
                future: (project.cancel)(stream, code),
            })
        }
    }
}
