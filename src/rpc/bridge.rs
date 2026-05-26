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

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use futures::{FutureExt, SinkExt, StreamExt, future::poll_fn};

    use super::*;
    use crate::quic::{CancelStreamExt, GetStreamIdExt, StopStreamExt};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        ReadStarted,
        ReadCancelled,
        Stop(u64),
        Write(Bytes),
        WriteStarted(Bytes),
        WriteCancelled,
        Flush,
        Shutdown,
        Cancel(u64),
    }

    #[derive(Debug)]
    struct TestReadClient {
        chunks: VecDeque<Option<Result<Bytes, quic::StreamError>>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl TestReadClient {
        fn new(chunks: impl IntoIterator<Item = Option<Result<Bytes, quic::StreamError>>>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record(&self, event: Event) {
            self.events
                .lock()
                .expect("events mutex should not be poisoned")
                .push(event);
        }
    }

    #[derive(Debug)]
    struct TestWriteClient {
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl TestWriteClient {
        fn new() -> Self {
            Self {
                events: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn record(&self, event: Event) {
            self.events
                .lock()
                .expect("events mutex should not be poisoned")
                .push(event);
        }
    }

    fn events(events: &Mutex<Vec<Event>>) -> Vec<Event> {
        events
            .lock()
            .expect("events mutex should not be poisoned")
            .clone()
    }

    #[tokio::test]
    async fn read_bridge_reads_until_eof_and_reports_stream_id() {
        let stream_id = VarInt::from_u32(7);
        let client = TestReadClient::new([
            Some(Ok(Bytes::from_static(b"one"))),
            Some(Ok(Bytes::from_static(b"two"))),
            None,
        ]);

        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            stream_id,
            client,
            |mut client: TestReadClient, _token: CancellationToken| async move {
                let result = client.chunks.pop_front().expect("scripted read result");
                Either::Left((client, result))
            },
            |client: TestReadClient, code: VarInt| async move {
                client.record(Event::Stop(code.into_inner()));
                (client, Ok(()))
            },
        ));

        assert_eq!(bridge.stream_id().await.expect("stream id"), stream_id);
        assert!(!bridge.is_terminated());
        assert_eq!(
            bridge.next().await.expect("first chunk").expect("read ok"),
            Bytes::from_static(b"one"),
        );
        assert_eq!(
            bridge.next().await.expect("second chunk").expect("read ok"),
            Bytes::from_static(b"two"),
        );
        assert!(bridge.next().await.is_none());
        assert!(bridge.is_terminated());
        assert!(bridge.next().await.is_none());
    }

    #[tokio::test]
    async fn read_bridge_stop_cancels_pending_read_before_stopping() {
        let stream_id = VarInt::from_u32(11);
        let client = TestReadClient::new([]);
        let events_handle = client.events.clone();
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            stream_id,
            client,
            |client: TestReadClient, token: CancellationToken| async move {
                client.record(Event::ReadStarted);
                token.cancelled().await;
                client.record(Event::ReadCancelled);
                Either::Right(client)
            },
            |client: TestReadClient, code: VarInt| async move {
                client.record(Event::Stop(code.into_inner()));
                (client, Ok(()))
            },
        ));

        let pending = poll_fn(|cx| bridge.as_mut().poll_next(cx)).now_or_never();
        assert!(pending.is_none(), "scripted read should remain pending");

        bridge
            .stop(VarInt::from_u32(99))
            .await
            .expect("stop should complete after cancelling pending read");

        assert_eq!(
            events(events_handle.as_ref()),
            vec![Event::ReadStarted, Event::ReadCancelled, Event::Stop(99),],
        );
    }

    #[tokio::test]
    async fn write_bridge_writes_flushes_shutdown_and_cancels() {
        let stream_id = VarInt::from_u32(13);
        let client = TestWriteClient::new();
        let events_handle = client.events.clone();
        let mut bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                stream_id,
                client,
                |client: TestWriteClient, _token: CancellationToken, bytes: Bytes| async move {
                    client.record(Event::Write(bytes));
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    client.record(Event::Flush);
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    client.record(Event::Shutdown);
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, code: VarInt| async move {
                    client.record(Event::Cancel(code.into_inner()));
                    (client, Ok(()))
                },
            ),
        );

        assert_eq!(bridge.stream_id().await.expect("stream id"), stream_id);
        bridge
            .feed(Bytes::from_static(b"payload"))
            .await
            .expect("write");
        bridge.flush().await.expect("flush");
        bridge.close().await.expect("shutdown");
        bridge.cancel(VarInt::from_u32(17)).await.expect("cancel");

        assert_eq!(
            events(events_handle.as_ref()),
            vec![
                Event::Write(Bytes::from_static(b"payload")),
                Event::Flush,
                Event::Shutdown,
                Event::Cancel(17),
            ],
        );
    }

    #[tokio::test]
    async fn write_bridge_cancel_cancels_pending_write() {
        let stream_id = VarInt::from_u32(19);
        let client = TestWriteClient::new();
        let events_handle = client.events.clone();
        let mut bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                stream_id,
                client,
                |client: TestWriteClient, token: CancellationToken, bytes: Bytes| async move {
                    client.record(Event::WriteStarted(bytes));
                    token.cancelled().await;
                    client.record(Event::WriteCancelled);
                    Either::Right(client)
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    client.record(Event::Flush);
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    client.record(Event::Shutdown);
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, code: VarInt| async move {
                    client.record(Event::Cancel(code.into_inner()));
                    (client, Ok(()))
                },
            ),
        );

        poll_fn(|cx| bridge.as_mut().poll_ready(cx))
            .await
            .expect("ready");
        bridge
            .as_mut()
            .start_send(Bytes::from_static(b"pending"))
            .expect("start send");

        bridge
            .cancel(VarInt::from_u32(23))
            .await
            .expect("cancel pending write");

        assert_eq!(
            events(events_handle.as_ref()),
            vec![
                Event::WriteStarted(Bytes::from_static(b"pending")),
                Event::WriteCancelled,
                Event::Cancel(23),
            ],
        );
    }
}
