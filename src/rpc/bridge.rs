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
    use crate::quic::{CancelStream, CancelStreamExt, GetStreamIdExt, StopStream, StopStreamExt};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        ReadStarted,
        ReadCancelled,
        Stop(u64),
        Write(Bytes),
        WriteStarted(Bytes),
        WriteCancelled,
        Flush,
        FlushStarted,
        FlushCancelled,
        Shutdown,
        ShutdownStarted,
        ShutdownCancelled,
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

    /// Take the value out of `Arc<Mutex<Option<T>>>` without holding the
    /// guard across an await point (clippy: `await_holding_lock`).
    fn take_locked<T>(slot: &Mutex<Option<T>>) -> Option<T> {
        slot.lock()
            .expect("slot mutex should not be poisoned")
            .take()
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
    async fn read_bridge_propagates_read_and_stop_errors() {
        let read_code = VarInt::from_u32(31);
        let stop_code = VarInt::from_u32(32);
        let client = TestReadClient::new([Some(Err(quic::StreamError::Reset { code: read_code }))]);
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            VarInt::from_u32(12),
            client,
            |mut client: TestReadClient, _token: CancellationToken| async move {
                let result = client.chunks.pop_front().expect("scripted read result");
                Either::Left((client, result))
            },
            move |client: TestReadClient, _code: VarInt| async move {
                (client, Err(quic::StreamError::Reset { code: stop_code }))
            },
        ));

        assert!(matches!(
            bridge.next().await,
            Some(Err(quic::StreamError::Reset { code })) if code == read_code
        ));
        assert!(matches!(
            bridge.stop(VarInt::from_u32(99)).await,
            Err(quic::StreamError::Reset { code }) if code == stop_code
        ));
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

    #[tokio::test]
    async fn write_bridge_reports_operation_errors() {
        let write_code = VarInt::from_u32(41);
        let flush_code = VarInt::from_u32(42);
        let shutdown_code = VarInt::from_u32(43);
        let cancel_code = VarInt::from_u32(44);
        let mut bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                VarInt::from_u32(25),
                TestWriteClient::new(),
                move |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| async move {
                    Either::Left((client, Err(quic::StreamError::Reset { code: write_code })))
                },
                move |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Err(quic::StreamError::Reset { code: flush_code })))
                },
                move |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((
                        client,
                        Err(quic::StreamError::Reset {
                            code: shutdown_code,
                        }),
                    ))
                },
                move |client: TestWriteClient, _code: VarInt| async move {
                    (client, Err(quic::StreamError::Reset { code: cancel_code }))
                },
            ),
        );

        assert!(matches!(
            bridge.send(Bytes::from_static(b"write")).await,
            Err(quic::StreamError::Reset { code }) if code == write_code
        ));
        assert!(matches!(
            bridge.flush().await,
            Err(quic::StreamError::Reset { code }) if code == flush_code
        ));
        assert!(matches!(
            bridge.close().await,
            Err(quic::StreamError::Reset { code }) if code == shutdown_code
        ));
        assert!(matches!(
            bridge.cancel(VarInt::from_u32(55)).await,
            Err(quic::StreamError::Reset { code }) if code == cancel_code
        ));
    }

    #[tokio::test]
    async fn write_bridge_cancel_cancels_pending_flush_and_shutdown() {
        let flush_client = TestWriteClient::new();
        let flush_events = flush_client.events.clone();
        let mut flush_bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                VarInt::from_u32(27),
                flush_client,
                |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, token: CancellationToken| async move {
                    client.record(Event::FlushStarted);
                    token.cancelled().await;
                    client.record(Event::FlushCancelled);
                    Either::Right(client)
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, code: VarInt| async move {
                    client.record(Event::Cancel(code.into_inner()));
                    (client, Ok(()))
                },
            ),
        );

        assert!(
            poll_fn(|cx| flush_bridge.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush should remain pending until cancellation"
        );
        flush_bridge
            .cancel(VarInt::from_u32(57))
            .await
            .expect("cancel pending flush");
        assert_eq!(
            events(flush_events.as_ref()),
            vec![
                Event::FlushStarted,
                Event::FlushCancelled,
                Event::Cancel(57),
            ],
        );

        let shutdown_client = TestWriteClient::new();
        let shutdown_events = shutdown_client.events.clone();
        let mut shutdown_bridge =
            Box::pin(
                WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                    VarInt::from_u32(29),
                    shutdown_client,
                    |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| async move {
                        Either::Left((client, Ok(())))
                    },
                    |client: TestWriteClient, _token: CancellationToken| async move {
                        Either::Left((client, Ok(())))
                    },
                    |client: TestWriteClient, token: CancellationToken| async move {
                        client.record(Event::ShutdownStarted);
                        token.cancelled().await;
                        client.record(Event::ShutdownCancelled);
                        Either::Right(client)
                    },
                    |client: TestWriteClient, code: VarInt| async move {
                        client.record(Event::Cancel(code.into_inner()));
                        (client, Ok(()))
                    },
                ),
            );

        assert!(
            poll_fn(|cx| shutdown_bridge.as_mut().poll_close(cx))
                .now_or_never()
                .is_none(),
            "shutdown should remain pending until cancellation"
        );
        shutdown_bridge
            .cancel(VarInt::from_u32(59))
            .await
            .expect("cancel pending shutdown");
        assert_eq!(
            events(shutdown_events.as_ref()),
            vec![
                Event::ShutdownStarted,
                Event::ShutdownCancelled,
                Event::Cancel(59),
            ],
        );
    }

    #[tokio::test]
    async fn read_bridge_poll_next_observes_read_right_and_retries() {
        // Drive poll_next through the `Either::Right` branch (lines 129-132):
        // the read closure returns `Right(stream)` once, which forces the
        // state machine back to `Stream` and re-invokes the read closure.
        let stream_id = VarInt::from_u32(101);
        let attempts = Arc::new(Mutex::new(0_u32));
        let client = TestReadClient::new([Some(Ok(Bytes::from_static(b"second")))]);
        let attempts_for_closure = attempts.clone();
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            stream_id,
            client,
            move |mut client: TestReadClient, _token: CancellationToken| {
                let attempts = attempts_for_closure.clone();
                async move {
                    let mut guard = attempts.lock().expect("attempts");
                    *guard += 1;
                    if *guard == 1 {
                        Either::Right(client)
                    } else {
                        let result = client.chunks.pop_front().expect("scripted read result");
                        Either::Left((client, result))
                    }
                }
            },
            |client: TestReadClient, _code: VarInt| async move { (client, Ok(())) },
        ));

        let chunk = bridge.next().await.expect("chunk").expect("read ok");
        assert_eq!(chunk, Bytes::from_static(b"second"));
        assert_eq!(*attempts.lock().expect("attempts"), 2);
    }

    #[tokio::test]
    async fn read_bridge_poll_next_drains_pending_stop_future() {
        // Drive poll_next through the `Stop` arm (lines 134-137): we leave the
        // bridge in `Stop` state by issuing poll_stop while the stop future is
        // pending, then call poll_next which must drain the same future.
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stop_rx = Arc::new(Mutex::new(Some(stop_rx)));
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            VarInt::from_u32(102),
            TestReadClient::new([Some(Ok(Bytes::from_static(b"data")))]),
            |mut client: TestReadClient, _token: CancellationToken| async move {
                let result = client.chunks.pop_front().expect("scripted read result");
                Either::Left((client, result))
            },
            move |client: TestReadClient, _code: VarInt| {
                let stop_rx = stop_rx.clone();
                async move {
                    let rx = stop_rx
                        .lock()
                        .expect("stop_rx mutex")
                        .take()
                        .expect("stop_rx taken once");
                    let _ = rx.await;
                    (client, Ok(()))
                }
            },
        ));

        // First poll_stop call: stop future is pending (waiting on stop_rx).
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_stop(cx, VarInt::from_u32(7)))
                .now_or_never()
                .is_none(),
            "stop should remain pending until released"
        );

        // Now poll_next: bridge is in Stop state, hits lines 134-137.
        // Spawn poll_next on a separate task and release the stop after.
        let next_pending = poll_fn(|cx| bridge.as_mut().poll_next(cx)).now_or_never();
        assert!(next_pending.is_none(), "poll_next observes pending Stop");

        // Release the stop future and let poll_next loop back into Stream.
        stop_tx.send(()).expect("send stop release");
        let chunk = bridge.next().await.expect("chunk").expect("read ok");
        assert_eq!(chunk, Bytes::from_static(b"data"));
    }

    #[tokio::test]
    async fn read_bridge_poll_stop_propagates_completed_read_data() {
        // Drive poll_stop through the `Read` arm's `Either::Left` pattern
        // (lines 179-181 Left): poll_next leaves a Read future in flight, but
        // the future completes with data (Left) when stop polls it.
        let (read_tx, read_rx) = tokio::sync::oneshot::channel::<()>();
        let read_rx = Arc::new(Mutex::new(Some(read_rx)));
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            VarInt::from_u32(103),
            TestReadClient::new([Some(Ok(Bytes::from_static(b"raced")))]),
            move |mut client: TestReadClient, _token: CancellationToken| {
                let read_rx = read_rx.clone();
                async move {
                    // Wait on an external signal that is independent of the
                    // cancellation token; once released, return Left with data.
                    let rx = read_rx
                        .lock()
                        .expect("read_rx mutex")
                        .take()
                        .expect("read_rx taken once");
                    let _ = rx.await;
                    let result = client.chunks.pop_front().expect("scripted read");
                    Either::Left((client, result))
                }
            },
            |client: TestReadClient, _code: VarInt| async move { (client, Ok(())) },
        ));

        // Start a read: it parks waiting on read_rx.
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_next(cx))
                .now_or_never()
                .is_none(),
            "read should remain pending"
        );

        // Release the read future; it will resolve to Left when polled next.
        read_tx.send(()).expect("send read release");

        // poll_stop sees Read state, polls future which returns Left(stream, data).
        bridge
            .stop(VarInt::from_u32(11))
            .await
            .expect("stop after completed read");
    }

    #[tokio::test]
    async fn read_bridge_poll_stop_replaces_future_when_code_differs() {
        // Drive poll_stop through the `Stop` arm where the in-flight stop's
        // code differs from the new code (lines 189-191): poll_stop must
        // resolve the pending stop and immediately issue a new one.
        let calls = Arc::new(Mutex::new(Vec::<u64>::new()));
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let gate_rx = Arc::new(Mutex::new(Some(gate_rx)));
        let calls_for_closure = calls.clone();
        let mut bridge = Box::pin(ReadBridge::<_, quic::StreamError, _, _, _, _>::new(
            VarInt::from_u32(104),
            TestReadClient::new([]),
            |client: TestReadClient, _token: CancellationToken| async move {
                std::future::pending::<()>().await;
                Either::Right(client)
            },
            move |client: TestReadClient, code: VarInt| {
                let calls = calls_for_closure.clone();
                let gate_rx = gate_rx.clone();
                async move {
                    calls.lock().expect("calls").push(code.into_inner());
                    if let Some(rx) = take_locked(&gate_rx) {
                        let _ = rx.await;
                    }
                    (client, Ok(()))
                }
            },
        ));

        // First stop: pending because gate is closed.
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_stop(cx, VarInt::from_u32(21)))
                .now_or_never()
                .is_none(),
            "first stop pending"
        );
        // Second stop with a different code: poll the future once to consume
        // the in-flight (different-code) stop, then it must issue a new stop.
        let pending =
            poll_fn(|cx| bridge.as_mut().poll_stop(cx, VarInt::from_u32(22))).now_or_never();
        assert!(pending.is_none(), "second stop polled while gate closed");
        // Release the gate; the first stop completes; the loop schedules a
        // second stop call with code 22 (now uses the released stop closure).
        gate_tx.send(()).expect("release gate");
        bridge
            .stop(VarInt::from_u32(22))
            .await
            .expect("stop completes with new code");

        let recorded = calls.lock().expect("calls").clone();
        assert_eq!(recorded.first().copied(), Some(21));
        assert!(recorded.contains(&22), "second stop must be issued");
    }

    #[tokio::test]
    async fn write_bridge_poll_ready_drains_pending_cancel_future() {
        // Drive poll_ready through the `Cancel` arm (lines 352-355): if a
        // cancel future is in flight, poll_ready must drain it.
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let cancel_rx = Arc::new(Mutex::new(Some(cancel_rx)));
        let mut bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                VarInt::from_u32(204),
                TestWriteClient::new(),
                |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Ok(())))
                },
                move |client: TestWriteClient, _code: VarInt| {
                    let cancel_rx = cancel_rx.clone();
                    async move {
                        if let Some(rx) = take_locked(&cancel_rx) {
                            let _ = rx.await;
                        }
                        (client, Ok(()))
                    }
                },
            ),
        );

        // Drive bridge into Cancel state with a pending cancel future.
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_cancel(cx, VarInt::from_u32(31)))
                .now_or_never()
                .is_none(),
            "cancel should be pending until released"
        );

        // poll_ready now sees Cancel state and must drain it (lines 352-355).
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_ready(cx))
                .now_or_never()
                .is_none(),
            "poll_ready observes pending Cancel"
        );

        // Release the cancel; the drained Cancel result loops to Stream, then
        // poll_ready returns Ready.
        cancel_tx.send(()).expect("release cancel");
        poll_fn(|cx| bridge.as_mut().poll_ready(cx))
            .await
            .expect("poll_ready completes once cancel drains");
    }

    #[tokio::test]
    async fn write_bridge_poll_cancel_propagates_completed_operation() {
        // Drive poll_cancel through the in-flight Write/Flush/Shutdown
        // `Either::Left` patterns (lines 444 / 450 / 456 Left): the in-flight
        // operation completes with a result before being cancelled.
        for operation in ["write", "flush", "shutdown"] {
            let (op_tx, op_rx) = tokio::sync::oneshot::channel::<()>();
            let op_rx = Arc::new(Mutex::new(Some(op_rx)));
            let write_release = if operation == "write" {
                Some(op_rx.clone())
            } else {
                None
            };
            let flush_release = if operation == "flush" {
                Some(op_rx.clone())
            } else {
                None
            };
            let shutdown_release = if operation == "shutdown" {
                Some(op_rx.clone())
            } else {
                None
            };
            let mut bridge = Box::pin(
                WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                    VarInt::from_u32(205),
                    TestWriteClient::new(),
                    move |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| {
                        let release = write_release.clone();
                        async move {
                            if let Some(release) = release
                                && let Some(rx) = take_locked(&release)
                            {
                                let _ = rx.await;
                            }
                            Either::Left((client, Ok(())))
                        }
                    },
                    move |client: TestWriteClient, _token: CancellationToken| {
                        let release = flush_release.clone();
                        async move {
                            if let Some(release) = release
                                && let Some(rx) = take_locked(&release)
                            {
                                let _ = rx.await;
                            }
                            Either::Left((client, Ok(())))
                        }
                    },
                    move |client: TestWriteClient, _token: CancellationToken| {
                        let release = shutdown_release.clone();
                        async move {
                            if let Some(release) = release
                                && let Some(rx) = take_locked(&release)
                            {
                                let _ = rx.await;
                            }
                            Either::Left((client, Ok(())))
                        }
                    },
                    |client: TestWriteClient, _code: VarInt| async move { (client, Ok(())) },
                ),
            );

            // Park the targeted operation.
            match operation {
                "write" => {
                    poll_fn(|cx| bridge.as_mut().poll_ready(cx))
                        .await
                        .expect("ready");
                    bridge
                        .as_mut()
                        .start_send(Bytes::from_static(b"x"))
                        .expect("start send");
                    assert!(
                        poll_fn(|cx| bridge.as_mut().poll_flush(cx))
                            .now_or_never()
                            .is_none(),
                        "flush observes pending write"
                    );
                }
                "flush" => {
                    assert!(
                        poll_fn(|cx| bridge.as_mut().poll_flush(cx))
                            .now_or_never()
                            .is_none(),
                        "flush pending"
                    );
                }
                "shutdown" => {
                    assert!(
                        poll_fn(|cx| bridge.as_mut().poll_close(cx))
                            .now_or_never()
                            .is_none(),
                        "shutdown pending"
                    );
                }
                _ => unreachable!(),
            }

            // Release the operation so its future resolves to Left when
            // poll_cancel polls it.
            op_tx.send(()).expect("release op");

            bridge
                .cancel(VarInt::from_u32(41))
                .await
                .expect("cancel after completed op");
        }
    }

    #[tokio::test]
    async fn write_bridge_poll_cancel_replaces_future_when_code_differs() {
        // Drive poll_cancel through the `Cancel` arm where the in-flight
        // cancel's code differs from the new code (lines 466-469).
        let calls = Arc::new(Mutex::new(Vec::<u64>::new()));
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let gate_rx = Arc::new(Mutex::new(Some(gate_rx)));
        let calls_for_closure = calls.clone();
        let mut bridge = Box::pin(
            WriteBridge::<_, quic::StreamError, _, _, _, _, _, _, _, _>::new(
                VarInt::from_u32(206),
                TestWriteClient::new(),
                |client: TestWriteClient, _token: CancellationToken, _bytes: Bytes| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Ok(())))
                },
                |client: TestWriteClient, _token: CancellationToken| async move {
                    Either::Left((client, Ok(())))
                },
                move |client: TestWriteClient, code: VarInt| {
                    let calls = calls_for_closure.clone();
                    let gate_rx = gate_rx.clone();
                    async move {
                        calls.lock().expect("calls").push(code.into_inner());
                        if let Some(rx) = take_locked(&gate_rx) {
                            let _ = rx.await;
                        }
                        (client, Ok(()))
                    }
                },
            ),
        );

        // First cancel: pending because gate is closed.
        assert!(
            poll_fn(|cx| bridge.as_mut().poll_cancel(cx, VarInt::from_u32(51)))
                .now_or_never()
                .is_none(),
            "first cancel pending"
        );
        // Second cancel with a different code: poll once to consume the
        // in-flight cancel, then a new one with code 52 must be issued.
        let pending =
            poll_fn(|cx| bridge.as_mut().poll_cancel(cx, VarInt::from_u32(52))).now_or_never();
        assert!(pending.is_none(), "second cancel polled while gate closed");
        gate_tx.send(()).expect("release gate");
        bridge
            .cancel(VarInt::from_u32(52))
            .await
            .expect("cancel completes with new code");

        let recorded = calls.lock().expect("calls").clone();
        assert_eq!(recorded.first().copied(), Some(51));
        assert!(recorded.contains(&52), "second cancel must be issued");
    }
}
