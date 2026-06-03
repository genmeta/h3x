//! since futures::sink::unfold only works for send, we implement our own version here to support flush and close as well.

use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, future::Either};
use tokio_util::sync::CancellationToken;

use super::super::{MessageStreamError, WriteStream};
use crate::{
    codec::SinkWriter,
    quic::{self, GetStreamId, ResetStream},
    varint::VarInt,
};

/// A message-level byte sink that also supports QUIC stream control operations.
///
/// This is the message-layer analog of [`quic::WriteStream`], combining DATA-frame
/// byte sinking with the underlying QUIC stream's [`ResetStream`] and
/// [`GetStreamId`] capabilities.
pub trait WriteMessageStream:
    ResetStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send
{
}

impl<T: ResetStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send + ?Sized>
    WriteMessageStream for T
{
}

/// Boxed stream writer with QUIC stream control traits preserved.
pub type BoxMessageStreamWriter<'s> = SinkWriter<Pin<Box<dyn WriteMessageStream + 's>>>;

impl From<WriteStream> for BoxMessageStreamWriter<'static> {
    fn from(value: WriteStream) -> Self {
        value.into_box_writer()
    }
}

// ---------------------------------------------------------------------------
// Unfold – custom sink unfold that preserves QUIC traits
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = StateProj]
    #[project_replace = StateProjReplace]
    #[derive(Debug)]
    enum State<StreamState, SendFuture, FlushFuture, CloseFuture, ResetFuture> {
        Value { value: StreamState },
        Send {
            token: CancellationToken,
            #[pin]
            future: SendFuture,
        },
        Flush {
            token: CancellationToken,
            #[pin]
            future: FlushFuture,
        },
        Close {
            token: CancellationToken,
            #[pin]
            future: CloseFuture,
        },
        Reset {
            #[pin]
            future: ResetFuture,
        },
        Empty,
    }
}

impl<StreamState, SendFuture, FlushFuture, CloseFuture, ResetFuture>
    State<StreamState, SendFuture, FlushFuture, CloseFuture, ResetFuture>
{
    fn take_value(self: Pin<&mut Self>) -> Option<StreamState> {
        match &*self {
            Self::Value { .. } => match self.project_replace(Self::Empty) {
                StateProjReplace::Value { value } => Some(value),
                _ => unreachable!(),
            },
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PendingWriteOp {
    Reset(VarInt),
    Flush,
    Close,
}

#[derive(Debug, Default)]
struct PendingWriteQueue {
    ops: std::collections::VecDeque<PendingWriteOp>,
}

impl PendingWriteQueue {
    fn contains_reset(&self) -> bool {
        matches!(self.ops.front(), Some(PendingWriteOp::Reset(_)))
    }

    fn contains_flush(&self) -> bool {
        self.ops.contains(&PendingWriteOp::Flush)
    }

    fn contains_close(&self) -> bool {
        self.ops.contains(&PendingWriteOp::Close)
    }

    fn contains_kind(&self, op: PendingWriteOp) -> bool {
        match op {
            PendingWriteOp::Reset(_) => self.contains_reset(),
            PendingWriteOp::Flush => self.contains_flush(),
            PendingWriteOp::Close => self.contains_close(),
        }
    }

    fn enqueue_reset(&mut self, code: VarInt) {
        if !self.contains_reset() {
            self.ops.clear();
            self.ops.push_back(PendingWriteOp::Reset(code));
        }
    }

    fn enqueue_flush(&mut self) {
        if !self.contains_reset() && !self.contains_flush() {
            self.ops.push_back(PendingWriteOp::Flush);
        }
    }

    fn enqueue_close(&mut self) {
        if !self.contains_reset() && !self.contains_close() {
            self.ops.push_back(PendingWriteOp::Close);
        }
    }

    fn front(&self) -> Option<PendingWriteOp> {
        self.ops.front().copied()
    }

    fn pop_front(&mut self) {
        self.ops.pop_front();
    }

    fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[must_use = "sinks do nothing unless polled"]
    pub struct Unfold<
        StreamState,
        Send,
        Flush,
        Close,
        Reset,
        SendFuture,
        FlushFuture,
        CloseFuture,
        ResetFuture,
        SinkError,
    > {
        send: Send,
        flush: Flush,
        close: Close,
        reset: Reset,
        pending: PendingWriteQueue,
        _error: std::marker::PhantomData<fn() -> SinkError>,
        #[pin]
        state: State<StreamState, SendFuture, FlushFuture, CloseFuture, ResetFuture>,
    }
}

impl<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
>
    Unfold<
        StreamState,
        Send,
        Flush,
        Close,
        Reset,
        SendFuture,
        FlushFuture,
        CloseFuture,
        ResetFuture,
        SinkError,
    >
where
    SendFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    FlushFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    CloseFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    ResetFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
    SinkError: From<quic::StreamError>,
{
    fn is_flush(&self) -> bool {
        matches!(self.state, State::Flush { .. })
    }

    fn is_close(&self) -> bool {
        matches!(self.state, State::Close { .. })
    }

    fn is_reset(&self) -> bool {
        matches!(self.state, State::Reset { .. })
    }

    fn set_value(mut self: Pin<&mut Self>, value: StreamState) {
        self.as_mut().project().state.set(State::Value { value });
    }

    fn poll_current_to_value(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), SinkError>> {
        let completed = {
            let mut project = self.as_mut().project();
            match project.state.as_mut().project() {
                StateProj::Value { .. } => return Poll::Ready(Ok(())),
                StateProj::Send { future, .. } => match ready!(future.poll(cx)) {
                    Either::Left((stream, result)) => (stream, result),
                    Either::Right(stream) => (stream, Ok(())),
                },
                StateProj::Flush { future, .. } => match ready!(future.poll(cx)) {
                    Either::Left((stream, result)) => (stream, result),
                    Either::Right(stream) => (stream, Ok(())),
                },
                StateProj::Close { future, .. } => match ready!(future.poll(cx)) {
                    Either::Left((stream, result)) => (stream, result),
                    Either::Right(stream) => (stream, Ok(())),
                },
                StateProj::Reset { future } => {
                    let (stream, result) = ready!(future.poll(cx));
                    (stream, result.map_err(SinkError::from))
                }
                StateProj::Empty => unreachable!("invalid state for poll_current_to_value"),
            }
        };
        self.as_mut().set_value(completed.0);
        Poll::Ready(completed.1)
    }

    fn poll_current_to_value_after_reset(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<StreamState> {
        let stream = {
            let mut project = self.as_mut().project();
            match project.state.as_mut().project() {
                StateProj::Value { .. } => project
                    .state
                    .as_mut()
                    .take_value()
                    .expect("value state should contain stream"),
                StateProj::Send { token, future } => {
                    token.cancel();
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, _)) | Either::Right(stream) => stream,
                    }
                }
                StateProj::Flush { token, future } => {
                    token.cancel();
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, _)) | Either::Right(stream) => stream,
                    }
                }
                StateProj::Close { token, future } => {
                    token.cancel();
                    match ready!(future.poll(cx)) {
                        Either::Left((stream, _)) | Either::Right(stream) => stream,
                    }
                }
                StateProj::Reset { .. } => unreachable!("reset is already active"),
                StateProj::Empty => unreachable!("invalid state for reset restoration"),
            }
        };
        Poll::Ready(stream)
    }

    fn start_flush(mut self: Pin<&mut Self>)
    where
        Flush: FnMut(StreamState, CancellationToken) -> FlushFuture,
    {
        let mut project = self.as_mut().project();
        let stream = project.state.as_mut().take_value().expect("value state");
        let token = CancellationToken::new();
        project.state.set(State::Flush {
            token: token.clone(),
            future: (project.flush)(stream, token),
        });
    }

    fn start_close(mut self: Pin<&mut Self>)
    where
        Close: FnMut(StreamState, CancellationToken) -> CloseFuture,
    {
        let mut project = self.as_mut().project();
        let stream = project.state.as_mut().take_value().expect("value state");
        let token = CancellationToken::new();
        project.state.set(State::Close {
            token: token.clone(),
            future: (project.close)(stream, token),
        });
    }

    fn start_reset(mut self: Pin<&mut Self>, code: VarInt)
    where
        Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    {
        let mut project = self.as_mut().project();
        let stream = project.state.as_mut().take_value().expect("value state");
        project.state.set(State::Reset {
            future: (project.reset)(stream, code),
        });
    }

    fn poll_reset_op(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), quic::StreamError>>
    where
        Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    {
        let Some(PendingWriteOp::Reset(code)) = self.as_mut().project().pending.front() else {
            return Poll::Ready(Ok(()));
        };

        if !self.is_reset() {
            let stream = ready!(self.as_mut().poll_current_to_value_after_reset(cx));
            self.as_mut().set_value(stream);
            self.as_mut().start_reset(code);
        }

        let (stream, result) = {
            let mut project = self.as_mut().project();
            match project.state.as_mut().project() {
                StateProj::Reset { future } => ready!(future.poll(cx)),
                _ => unreachable!("reset operation should be active"),
            }
        };
        self.as_mut().set_value(stream);
        self.as_mut().project().pending.pop_front();
        Poll::Ready(result)
    }

    fn poll_pending_until(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        target: Option<PendingWriteOp>,
    ) -> Poll<Result<(), SinkError>>
    where
        Flush: FnMut(StreamState, CancellationToken) -> FlushFuture,
        Close: FnMut(StreamState, CancellationToken) -> CloseFuture,
        Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    {
        loop {
            let op = {
                let project = self.as_mut().project();
                if let Some(target) = target
                    && !project.pending.contains_kind(target)
                {
                    return Poll::Ready(Ok(()));
                }
                match project.pending.front() {
                    Some(op) => op,
                    None => return Poll::Ready(Ok(())),
                }
            };

            match op {
                PendingWriteOp::Reset(_) => {
                    ready!(self.as_mut().poll_reset_op(cx)).map_err(SinkError::from)?;
                }
                PendingWriteOp::Flush => {
                    if !self.is_flush() {
                        ready!(self.as_mut().poll_current_to_value(cx)?);
                        self.as_mut().start_flush();
                    }
                    ready!(self.as_mut().poll_current_to_value(cx)?);
                    self.as_mut().project().pending.pop_front();
                    if target == Some(PendingWriteOp::Flush) {
                        return Poll::Ready(Ok(()));
                    }
                }
                PendingWriteOp::Close => {
                    if !self.is_close() {
                        ready!(self.as_mut().poll_current_to_value(cx)?);
                        self.as_mut().start_close();
                    }
                    ready!(self.as_mut().poll_current_to_value(cx)?);
                    self.as_mut().project().pending.pop_front();
                    if target == Some(PendingWriteOp::Close) {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
    Item,
> Sink<Item>
    for Unfold<
        StreamState,
        Send,
        Flush,
        Close,
        Reset,
        SendFuture,
        FlushFuture,
        CloseFuture,
        ResetFuture,
        SinkError,
    >
where
    Send: FnMut(StreamState, CancellationToken, Item) -> SendFuture,
    Flush: FnMut(StreamState, CancellationToken) -> FlushFuture,
    Close: FnMut(StreamState, CancellationToken) -> CloseFuture,
    Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    SendFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    FlushFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    CloseFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    ResetFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
    SinkError: From<quic::StreamError>,
{
    type Error = SinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        while !self.as_mut().project().pending.is_empty() {
            ready!(self.as_mut().poll_pending_until(cx, None)?);
        }
        ready!(self.as_mut().poll_current_to_value(cx)?);
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let mut project = self.project();
        let stream = project
            .state
            .as_mut()
            .take_value()
            .expect("start_send called without poll_ready being called first");
        let token = CancellationToken::new();
        project.state.set(State::Send {
            token: token.clone(),
            future: (project.send)(stream, token, item),
        });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().project().pending.enqueue_flush();
        self.poll_pending_until(cx, Some(PendingWriteOp::Flush))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.as_mut().project().pending.enqueue_close();
        self.poll_pending_until(cx, Some(PendingWriteOp::Close))
    }
}

// ---------------------------------------------------------------------------
// QUIC control trait forwarding for Unfold
// ---------------------------------------------------------------------------

impl<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
> GetStreamId
    for Unfold<
        StreamState,
        Send,
        Flush,
        Close,
        Reset,
        SendFuture,
        FlushFuture,
        CloseFuture,
        ResetFuture,
        SinkError,
    >
where
    StreamState: GetStreamId + Unpin,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let project = self.project();
        match project.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_stream_id(cx),
            _ => Poll::Pending,
        }
    }
}

impl<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
> ResetStream
    for Unfold<
        StreamState,
        Send,
        Flush,
        Close,
        Reset,
        SendFuture,
        FlushFuture,
        CloseFuture,
        ResetFuture,
        SinkError,
    >
where
    Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    SendFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    FlushFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    CloseFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    ResetFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
    SinkError: From<quic::StreamError>,
{
    fn poll_reset(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        self.as_mut().project().pending.enqueue_reset(code);
        self.poll_reset_op(cx)
    }
}

// ---------------------------------------------------------------------------
// Unfold constructor
// ---------------------------------------------------------------------------

pub fn unfold<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
    Item,
>(
    init: StreamState,
    send: Send,
    flush: Flush,
    close: Close,
    reset: Reset,
) -> Unfold<
    StreamState,
    Send,
    Flush,
    Close,
    Reset,
    SendFuture,
    FlushFuture,
    CloseFuture,
    ResetFuture,
    SinkError,
>
where
    Send: FnMut(StreamState, CancellationToken, Item) -> SendFuture,
    SendFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    Flush: FnMut(StreamState, CancellationToken) -> FlushFuture,
    FlushFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    Close: FnMut(StreamState, CancellationToken) -> CloseFuture,
    CloseFuture: Future<Output = Either<(StreamState, Result<(), SinkError>), StreamState>>,
    Reset: FnMut(StreamState, VarInt) -> ResetFuture,
    ResetFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
{
    Unfold {
        send,
        flush,
        close,
        reset,
        pending: PendingWriteQueue::default(),
        _error: std::marker::PhantomData,
        state: State::Value { value: init },
    }
}

// ---------------------------------------------------------------------------
// WriteStream conversion methods
// ---------------------------------------------------------------------------

impl WriteStream {
    pub fn as_bytes_sink(&mut self) -> impl WriteMessageStream + '_ {
        unfold(
            self,
            async |stream: &mut WriteStream, token, buf: Bytes| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.write_data(buf) => Either::Left((stream, result)),
                }
            },
            async |stream: &mut WriteStream, token| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.flush() => Either::Left((stream, result)),
                }
            },
            async |stream: &mut WriteStream, token| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.close() => Either::Left((stream, result)),
                }
            },
            async |stream: &mut WriteStream, code| {
                let result =
                    futures::future::poll_fn(|cx| Pin::new(&mut *stream).poll_reset(cx, code))
                        .await;
                (stream, result)
            },
        )
    }

    pub fn as_writer(&mut self) -> SinkWriter<impl WriteMessageStream + '_> {
        SinkWriter::new(self.as_bytes_sink())
    }

    pub fn as_box_writer(&mut self) -> BoxMessageStreamWriter<'_> {
        SinkWriter::new(Box::pin(self.as_bytes_sink()))
    }

    pub fn into_bytes_sink(self) -> impl WriteMessageStream {
        unfold(
            self,
            async |mut stream: WriteStream, token, buf: Bytes| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.write_data(buf) => Either::Left((stream, result)),
                }
            },
            async |mut stream: WriteStream, token| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.flush() => Either::Left((stream, result)),
                }
            },
            async |mut stream: WriteStream, token| {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => Either::Right(stream),
                    result = stream.close() => Either::Left((stream, result)),
                }
            },
            async |mut stream: WriteStream, code| {
                let result =
                    futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_reset(cx, code)).await;
                (stream, result)
            },
        )
    }

    pub fn into_writer(self) -> SinkWriter<impl WriteMessageStream> {
        SinkWriter::new(self.into_bytes_sink())
    }

    pub fn into_box_writer(self) -> BoxMessageStreamWriter<'static> {
        SinkWriter::new(Box::pin(self.into_bytes_sink()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use futures::{
        FutureExt, SinkExt,
        future::{Either, poll_fn},
    };

    use super::*;
    use crate::quic::{GetStreamId, ResetStream};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Send(Bytes),
        Flush,
        Close,
        Reset(VarInt),
    }

    #[derive(Debug)]
    struct ControlSink {
        stream_id: VarInt,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl GetStreamId for ControlSink {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl ResetStream for ControlSink {
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

    type ControlResult = Either<(ControlSink, Result<(), MessageStreamError>), ControlSink>;
    type ControlReady = futures::future::Ready<ControlResult>;
    type ResetReady = futures::future::Ready<(ControlSink, Result<(), quic::StreamError>)>;
    type ReadyState = State<ControlSink, ControlReady, ControlReady, ControlReady, ResetReady>;

    fn control_sink(stream_id: VarInt) -> ControlSink {
        ControlSink {
            stream_id,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn ready_control(stream_id: VarInt) -> ControlReady {
        futures::future::ready(Either::Left((control_sink(stream_id), Ok(()))))
    }

    fn send_ok(stream: ControlSink, _token: CancellationToken, _item: Bytes) -> ControlReady {
        futures::future::ready(Either::Left((stream, Ok(()))))
    }

    fn operation_ok(stream: ControlSink, _token: CancellationToken) -> ControlReady {
        futures::future::ready(Either::Left((stream, Ok(()))))
    }

    fn send_pending(
        _stream: ControlSink,
        _token: CancellationToken,
        _item: Bytes,
    ) -> futures::future::Pending<ControlResult> {
        futures::future::pending()
    }

    fn operation_pending(
        _stream: ControlSink,
        _token: CancellationToken,
    ) -> futures::future::Pending<ControlResult> {
        futures::future::pending()
    }

    fn send_message_failed(
        stream: ControlSink,
        _token: CancellationToken,
        _item: Bytes,
    ) -> ControlReady {
        futures::future::ready(Either::Left((
            stream,
            Err(MessageStreamError::MessageSendFailed),
        )))
    }

    fn send_malformed_outgoing(
        stream: ControlSink,
        _token: CancellationToken,
        _item: Bytes,
    ) -> ControlReady {
        futures::future::ready(Either::Left((
            stream,
            Err(MessageStreamError::MalformedOutgoingMessage),
        )))
    }

    fn operation_message_failed(stream: ControlSink, _token: CancellationToken) -> ControlReady {
        futures::future::ready(Either::Left((
            stream,
            Err(MessageStreamError::MessageSendFailed),
        )))
    }

    fn operation_malformed_outgoing(
        stream: ControlSink,
        _token: CancellationToken,
    ) -> ControlReady {
        futures::future::ready(Either::Left((
            stream,
            Err(MessageStreamError::MalformedOutgoingMessage),
        )))
    }

    fn record_send(stream: ControlSink, _token: CancellationToken, item: Bytes) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Send(item));
        futures::future::ready(Either::Left((stream, Ok(()))))
    }

    fn record_flush(stream: ControlSink, _token: CancellationToken) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Flush);
        futures::future::ready(Either::Left((stream, Ok(()))))
    }

    fn record_close(stream: ControlSink, _token: CancellationToken) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Close);
        futures::future::ready(Either::Left((stream, Ok(()))))
    }

    fn record_reset(stream: ControlSink, code: VarInt) -> ResetReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Reset(code));
        futures::future::ready((stream, Ok(())))
    }

    fn reset_ok(stream: ControlSink, _code: VarInt) -> ResetReady {
        futures::future::ready((stream, Ok(())))
    }

    #[derive(Debug)]
    struct GateFuture {
        value: Option<ControlSink>,
        open: Arc<AtomicBool>,
    }

    impl Future for GateFuture {
        type Output = ControlResult;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.open.load(Ordering::SeqCst) {
                Poll::Ready(Either::Left((
                    self.value.take().expect("gate future polled after ready"),
                    Ok(()),
                )))
            } else {
                Poll::Pending
            }
        }
    }

    #[test]
    fn state_take_value_only_extracts_value_state() {
        let mut value = ReadyState::Value {
            value: control_sink(VarInt::from_u32(3)),
        };
        assert_eq!(
            Pin::new(&mut value)
                .take_value()
                .expect("value state should yield inner value")
                .stream_id,
            VarInt::from_u32(3)
        );
        assert!(
            Pin::new(&mut value).take_value().is_none(),
            "taking the value should leave the state empty"
        );

        let mut send = ReadyState::Send {
            token: CancellationToken::new(),
            future: ready_control(VarInt::from_u32(5)),
        };
        assert!(Pin::new(&mut send).take_value().is_none());

        let mut flush = ReadyState::Flush {
            token: CancellationToken::new(),
            future: ready_control(VarInt::from_u32(7)),
        };
        assert!(Pin::new(&mut flush).take_value().is_none());

        let mut close = ReadyState::Close {
            token: CancellationToken::new(),
            future: ready_control(VarInt::from_u32(9)),
        };
        assert!(Pin::new(&mut close).take_value().is_none());
    }

    #[tokio::test]
    async fn unfold_sends_flushes_and_closes_in_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(11),
                events: events.clone(),
            },
            record_send,
            record_flush,
            record_close,
            record_reset,
        ));

        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink ready");
        sink.as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        poll_fn(|cx| sink.as_mut().poll_flush(cx))
            .await
            .expect("sink flushed");
        poll_fn(|cx| sink.as_mut().poll_close(cx))
            .await
            .expect("sink closed");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![
                Event::Send(Bytes::from_static(b"payload")),
                Event::Flush,
                Event::Close,
            ]
        );
    }

    #[tokio::test]
    async fn unfold_flush_and_close_keep_single_in_flight_operation_until_ready() {
        let flush_open = Arc::new(AtomicBool::new(false));
        let close_open = Arc::new(AtomicBool::new(false));
        let flush_started = Arc::new(AtomicUsize::new(0));
        let close_started = Arc::new(AtomicUsize::new(0));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(31),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            {
                let flush_open = flush_open.clone();
                let flush_started = flush_started.clone();
                move |stream: ControlSink, _token| {
                    flush_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: flush_open.clone(),
                    }
                }
            },
            {
                let close_open = close_open.clone();
                let close_started = close_started.clone();
                move |stream: ControlSink, _token| {
                    close_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: close_open.clone(),
                    }
                }
            },
            reset_ok,
        ));

        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink ready");

        assert!(
            poll_fn(|cx| sink.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            flush_started.load(Ordering::SeqCst),
            1,
            "first flush poll should start one flush future"
        );
        assert!(
            poll_fn(|cx| sink.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            flush_started.load(Ordering::SeqCst),
            1,
            "polling an in-flight flush must not start another flush"
        );

        flush_open.store(true, Ordering::SeqCst);
        poll_fn(|cx| sink.as_mut().poll_flush(cx))
            .await
            .expect("flush completes once gate opens");
        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink ready after completed flush");
        assert_eq!(
            flush_started.load(Ordering::SeqCst),
            1,
            "poll_ready on value state must not flush again"
        );

        assert!(
            poll_fn(|cx| sink.as_mut().poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            close_started.load(Ordering::SeqCst),
            1,
            "first close poll should start one close future"
        );
        assert!(
            poll_fn(|cx| sink.as_mut().poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(
            close_started.load(Ordering::SeqCst),
            1,
            "polling an in-flight close must not start another close"
        );

        close_open.store(true, Ordering::SeqCst);
        poll_fn(|cx| sink.as_mut().poll_close(cx))
            .await
            .expect("close completes once gate opens");
        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink ready after completed close");
        assert_eq!(
            close_started.load(Ordering::SeqCst),
            1,
            "poll_ready on value state must not close again"
        );
    }

    #[tokio::test]
    async fn unfold_flush_and_close_wait_for_in_flight_send_before_starting() {
        let send_open = Arc::new(AtomicBool::new(false));
        let send_started = Arc::new(AtomicUsize::new(0));
        let flush_started = Arc::new(AtomicUsize::new(0));
        let mut flush_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(35),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            {
                let send_open = send_open.clone();
                let send_started = send_started.clone();
                move |stream: ControlSink, _token, _item: Bytes| {
                    send_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: send_open.clone(),
                    }
                }
            },
            {
                let flush_started = flush_started.clone();
                move |stream: ControlSink, _token| {
                    flush_started.fetch_add(1, Ordering::SeqCst);
                    futures::future::ready(Either::Left((stream, Ok::<_, MessageStreamError>(()))))
                }
            },
            operation_ok,
            reset_ok,
        ));

        poll_fn(|cx| flush_sink.as_mut().poll_ready(cx))
            .await
            .expect("sink initially ready");
        flush_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(
            poll_fn(|cx| flush_sink.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(send_started.load(Ordering::SeqCst), 1);
        assert_eq!(flush_started.load(Ordering::SeqCst), 0);

        send_open.store(true, Ordering::SeqCst);
        poll_fn(|cx| flush_sink.as_mut().poll_flush(cx))
            .await
            .expect("flush starts after send completes");
        assert_eq!(flush_started.load(Ordering::SeqCst), 1);

        let send_open = Arc::new(AtomicBool::new(false));
        let send_started = Arc::new(AtomicUsize::new(0));
        let close_started = Arc::new(AtomicUsize::new(0));
        let mut close_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(39),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            {
                let send_open = send_open.clone();
                let send_started = send_started.clone();
                move |stream: ControlSink, _token, _item: Bytes| {
                    send_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: send_open.clone(),
                    }
                }
            },
            operation_ok,
            {
                let close_started = close_started.clone();
                move |stream: ControlSink, _token| {
                    close_started.fetch_add(1, Ordering::SeqCst);
                    futures::future::ready(Either::Left((stream, Ok::<_, MessageStreamError>(()))))
                }
            },
            reset_ok,
        ));

        poll_fn(|cx| close_sink.as_mut().poll_ready(cx))
            .await
            .expect("sink initially ready");
        close_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(
            poll_fn(|cx| close_sink.as_mut().poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(send_started.load(Ordering::SeqCst), 1);
        assert_eq!(close_started.load(Ordering::SeqCst), 0);

        send_open.store(true, Ordering::SeqCst);
        poll_fn(|cx| close_sink.as_mut().poll_close(cx))
            .await
            .expect("close starts after send completes");
        assert_eq!(close_started.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unfold_poll_ready_waits_for_send_then_restores_control_traits() {
        let send_open = Arc::new(AtomicBool::new(false));
        let send_started = Arc::new(AtomicUsize::new(0));
        let stream_id = VarInt::from_u32(33);
        let reset_code = VarInt::from_u32(34);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id,
                events: events.clone(),
            },
            {
                let send_open = send_open.clone();
                let send_started = send_started.clone();
                move |stream: ControlSink, _token, _item: Bytes| {
                    send_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: send_open.clone(),
                    }
                }
            },
            operation_ok,
            operation_ok,
            record_reset,
        ));

        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink initially ready");
        sink.as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(
            poll_fn(|cx| sink.as_mut().poll_ready(cx))
                .now_or_never()
                .is_none()
        );
        assert_eq!(send_started.load(Ordering::SeqCst), 1);

        send_open.store(true, Ordering::SeqCst);
        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("send completes once gate opens");
        assert_eq!(send_started.load(Ordering::SeqCst), 1);
        assert_eq!(
            poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id should be available after send completes"),
            stream_id
        );
        poll_fn(|cx| sink.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("reset should be available after send completes");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![Event::Reset(reset_code)]
        );
    }

    #[tokio::test]
    async fn control_traits_forward_while_value_available() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stream_id = VarInt::from_u32(37);
        let reset_code = VarInt::from_u32(41);
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id,
                events: events.clone(),
            },
            send_ok,
            operation_ok,
            operation_ok,
            record_reset,
        ));

        assert_eq!(
            poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| sink.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("reset forwarded");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![Event::Reset(reset_code)]
        );
    }

    #[tokio::test]
    async fn control_traits_wait_while_send_future_owns_value() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(37),
                events,
            },
            send_pending,
            operation_ok,
            operation_ok,
            reset_ok,
        ));

        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink ready");
        sink.as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");

        assert!(
            poll_fn(|cx| sink.as_mut().poll_ready(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| sink.as_mut().poll_reset(cx, VarInt::from_u32(41)))
                .now_or_never()
                .is_none()
        );
    }

    #[tokio::test]
    async fn reset_uses_reset_closure_after_interrupting_pending_send() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let reset_code = VarInt::from_u32(41);
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(37),
                events: events.clone(),
            },
            |stream: ControlSink, token, bytes| async move {
                stream
                    .events
                    .lock()
                    .expect("event log poisoned")
                    .push(Event::Send(bytes));
                token.cancelled().await;
                Either::<(ControlSink, Result<(), MessageStreamError>), ControlSink>::Right(stream)
            },
            |stream, _token| async move { Either::Left((stream, Ok::<(), MessageStreamError>(()))) },
            |stream, _token| async move { Either::Left((stream, Ok::<(), MessageStreamError>(()))) },
            |stream: ControlSink, code| async move {
                stream
                    .events
                    .lock()
                    .expect("event log poisoned")
                    .push(Event::Reset(code));
                (stream, Ok::<(), quic::StreamError>(()))
            },
        ));

        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .await
            .expect("sink initially ready");
        sink.as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");

        poll_fn(|cx| sink.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("reset should complete");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![
                Event::Send(Bytes::from_static(b"payload")),
                Event::Reset(reset_code),
            ]
        );
    }

    #[test]
    fn start_send_without_poll_ready_panics_after_value_is_taken() {
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(1),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            operation_ok,
            operation_ok,
            reset_ok,
        ));
        poll_fn(|cx| sink.as_mut().poll_ready(cx))
            .now_or_never()
            .expect("poll_ready should complete immediately")
            .expect("sink ready");
        sink.as_mut()
            .start_send(Bytes::from_static(b"first"))
            .expect("first start_send should succeed");

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sink.as_mut()
                .start_send(Bytes::from_static(b"second"))
                .expect("start_send panics before returning");
        }));

        assert!(panic.is_err());
    }

    #[tokio::test]
    async fn control_traits_wait_while_flush_or_close_future_owns_value() {
        let mut flush_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(55),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            operation_pending,
            operation_ok,
            reset_ok,
        ));
        poll_fn(|cx| flush_sink.as_mut().poll_ready(cx))
            .await
            .expect("flush sink ready");
        flush_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(
            poll_fn(|cx| flush_sink.as_mut().poll_flush(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| flush_sink.as_mut().poll_stream_id(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| flush_sink.as_mut().poll_reset(cx, VarInt::from_u32(56)))
                .now_or_never()
                .is_none()
        );

        let mut close_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(57),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            operation_ok,
            operation_pending,
            reset_ok,
        ));
        assert!(
            poll_fn(|cx| close_sink.as_mut().poll_close(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| close_sink.as_mut().poll_stream_id(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| close_sink.as_mut().poll_reset(cx, VarInt::from_u32(58)))
                .now_or_never()
                .is_none()
        );
    }

    #[tokio::test]
    async fn unfold_flush_and_close_propagate_in_flight_send_errors() {
        let mut flush_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(63),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_message_failed,
            operation_malformed_outgoing,
            operation_ok,
            reset_ok,
        ));
        poll_fn(|cx| flush_sink.as_mut().poll_ready(cx))
            .await
            .expect("flush sink ready");
        flush_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(matches!(
            poll_fn(|cx| flush_sink.as_mut().poll_flush(cx)).await,
            Err(MessageStreamError::MessageSendFailed)
        ));

        let mut close_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(64),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_malformed_outgoing,
            operation_ok,
            operation_message_failed,
            reset_ok,
        ));
        poll_fn(|cx| close_sink.as_mut().poll_ready(cx))
            .await
            .expect("close sink ready");
        close_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(matches!(
            poll_fn(|cx| close_sink.as_mut().poll_close(cx)).await,
            Err(MessageStreamError::MalformedOutgoingMessage)
        ));
    }

    #[tokio::test]
    async fn unfold_propagates_flush_and_close_errors() {
        let mut flush_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(61),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            operation_message_failed,
            operation_ok,
            reset_ok,
        ));
        poll_fn(|cx| flush_sink.as_mut().poll_ready(cx))
            .await
            .expect("flush sink ready");
        flush_sink
            .as_mut()
            .start_send(Bytes::from_static(b"payload"))
            .expect("send accepted");
        assert!(matches!(
            poll_fn(|cx| flush_sink.as_mut().poll_flush(cx)).await,
            Err(MessageStreamError::MessageSendFailed)
        ));

        let mut close_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(62),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            send_ok,
            operation_ok,
            operation_malformed_outgoing,
            reset_ok,
        ));
        assert!(matches!(
            poll_fn(|cx| close_sink.as_mut().poll_close(cx)).await,
            Err(MessageStreamError::MalformedOutgoingMessage)
        ));
    }

    #[tokio::test]
    async fn write_stream_adapter_builders_preserve_sink_and_control_traits() {
        let stream_id = VarInt::from_u32(71);
        let reset_code = VarInt::from_u32(72);

        let mut bytes_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut sink = Box::pin(bytes_stream.as_bytes_sink());
            assert_eq!(
                poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_bytes_sink stream id"),
                stream_id
            );
            poll_fn(|cx| sink.as_mut().poll_reset(cx, reset_code))
                .await
                .expect("as_bytes_sink reset");
            sink.as_mut()
                .send(Bytes::from_static(b"payload"))
                .await
                .expect("as_bytes_sink send");
            sink.as_mut().flush().await.expect("as_bytes_sink flush");
            sink.as_mut().close().await.expect("as_bytes_sink close");
        }

        let mut owned_sink =
            Box::pin(crate::message::test::write_stream_for_test(stream_id).into_bytes_sink());
        assert_eq!(
            poll_fn(|cx| owned_sink.as_mut().poll_stream_id(cx))
                .await
                .expect("into_bytes_sink stream id"),
            stream_id
        );
        poll_fn(|cx| owned_sink.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("into_bytes_sink reset");
        owned_sink
            .as_mut()
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("into_bytes_sink send");
        owned_sink
            .as_mut()
            .flush()
            .await
            .expect("into_bytes_sink flush");
        owned_sink
            .as_mut()
            .close()
            .await
            .expect("into_bytes_sink close");

        let mut borrowed_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut writer = Box::pin(borrowed_stream.as_writer());
            assert_eq!(
                poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_writer stream id"),
                stream_id
            );
            poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
                .await
                .expect("as_writer reset");
            writer
                .as_mut()
                .send(Bytes::from_static(b"payload"))
                .await
                .expect("as_writer send");
            writer.as_mut().close().await.expect("as_writer close");
        }

        let mut borrowed_box_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut writer = Box::pin(borrowed_box_stream.as_box_writer());
            assert_eq!(
                poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_box_writer stream id"),
                stream_id
            );
            poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
                .await
                .expect("as_box_writer reset");
            writer
                .as_mut()
                .send(Bytes::from_static(b"payload"))
                .await
                .expect("as_box_writer send");
            writer.as_mut().close().await.expect("as_box_writer close");
        }

        let mut writer =
            Box::pin(crate::message::test::write_stream_for_test(stream_id).into_writer());
        assert_eq!(
            poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                .await
                .expect("into_writer stream id"),
            stream_id
        );
        poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("into_writer reset");
        writer
            .as_mut()
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("into_writer send");
        writer.as_mut().close().await.expect("into_writer close");

        let mut boxed_writer =
            Box::pin(crate::message::test::write_stream_for_test(stream_id).into_box_writer());
        assert_eq!(
            poll_fn(|cx| boxed_writer.as_mut().poll_stream_id(cx))
                .await
                .expect("into_box_writer stream id"),
            stream_id
        );
        poll_fn(|cx| boxed_writer.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("into_box_writer reset");
        boxed_writer
            .as_mut()
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("into_box_writer send");
        boxed_writer
            .as_mut()
            .close()
            .await
            .expect("into_box_writer close");

        let mut from_writer = Box::pin(BoxMessageStreamWriter::from(
            crate::message::test::write_stream_for_test(stream_id),
        ));
        assert_eq!(
            poll_fn(|cx| from_writer.as_mut().poll_stream_id(cx))
                .await
                .expect("from stream id"),
            stream_id
        );
        poll_fn(|cx| from_writer.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("from reset");
        from_writer
            .as_mut()
            .send(Bytes::from_static(b"payload"))
            .await
            .expect("from send");
        from_writer.as_mut().close().await.expect("from close");
    }

    #[tokio::test]
    async fn write_stream_writer_adapters_forward_control_with_buffered_send_then_flush_and_close()
    {
        let stream_id = VarInt::from_u32(81);
        let reset_code = VarInt::from_u32(82);

        let mut borrowed_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut writer = Box::pin(borrowed_stream.as_writer());
            poll_fn(|cx| writer.as_mut().poll_ready(cx))
                .await
                .expect("as_writer initially ready");
            writer
                .as_mut()
                .start_send(Bytes::from_static(b"buffered"))
                .expect("as_writer buffers send");
            assert_eq!(
                poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_writer stream id with buffered send"),
                stream_id
            );
            poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
                .await
                .expect("as_writer reset with buffered send");
            writer.as_mut().flush().await.expect("as_writer flush");
            assert_eq!(
                poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_writer stream id after flush"),
                stream_id
            );
            writer.as_mut().close().await.expect("as_writer close");
        }

        let mut borrowed_box_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut writer = Box::pin(borrowed_box_stream.as_box_writer());
            poll_fn(|cx| writer.as_mut().poll_ready(cx))
                .await
                .expect("as_box_writer initially ready");
            writer
                .as_mut()
                .start_send(Bytes::from_static(b"buffered"))
                .expect("as_box_writer buffers send");
            assert_eq!(
                poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_box_writer stream id with buffered send"),
                stream_id
            );
            poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
                .await
                .expect("as_box_writer reset with buffered send");
            writer.as_mut().flush().await.expect("as_box_writer flush");
            writer.as_mut().close().await.expect("as_box_writer close");
        }

        let mut writer =
            Box::pin(crate::message::test::write_stream_for_test(stream_id).into_writer());
        poll_fn(|cx| writer.as_mut().poll_ready(cx))
            .await
            .expect("into_writer initially ready");
        writer
            .as_mut()
            .start_send(Bytes::from_static(b"buffered"))
            .expect("into_writer buffers send");
        assert_eq!(
            poll_fn(|cx| writer.as_mut().poll_stream_id(cx))
                .await
                .expect("into_writer stream id with buffered send"),
            stream_id
        );
        poll_fn(|cx| writer.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("into_writer reset with buffered send");
        writer.as_mut().flush().await.expect("into_writer flush");
        writer.as_mut().close().await.expect("into_writer close");

        let mut boxed_writer =
            Box::pin(crate::message::test::write_stream_for_test(stream_id).into_box_writer());
        poll_fn(|cx| boxed_writer.as_mut().poll_ready(cx))
            .await
            .expect("into_box_writer initially ready");
        boxed_writer
            .as_mut()
            .start_send(Bytes::from_static(b"buffered"))
            .expect("into_box_writer buffers send");
        assert_eq!(
            poll_fn(|cx| boxed_writer.as_mut().poll_stream_id(cx))
                .await
                .expect("into_box_writer stream id with buffered send"),
            stream_id
        );
        poll_fn(|cx| boxed_writer.as_mut().poll_reset(cx, reset_code))
            .await
            .expect("into_box_writer reset with buffered send");
        boxed_writer
            .as_mut()
            .flush()
            .await
            .expect("into_box_writer flush");
        boxed_writer
            .as_mut()
            .close()
            .await
            .expect("into_box_writer close");
    }
}
