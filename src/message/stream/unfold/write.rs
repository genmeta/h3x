//! since futures::sink::unfold only works for send, we implement our own version here to support flush and close as well.

use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::Sink;

use super::super::{MessageStreamError, WriteStream};
use crate::{
    codec::SinkWriter,
    quic::{self, CancelStream, GetStreamId},
    varint::VarInt,
};

/// A message-level byte sink that also supports QUIC stream control operations.
///
/// This is the message-layer analog of [`quic::WriteStream`], combining DATA-frame
/// byte sinking with the underlying QUIC stream's [`CancelStream`] and
/// [`GetStreamId`] capabilities.
pub trait WriteMessageStream:
    CancelStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send
{
}

impl<T: CancelStream + GetStreamId + Sink<Bytes, Error = MessageStreamError> + Send + ?Sized>
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
    enum State<T, S, F, C> {
        Value {
            value: T,
        },
        Send {
            #[pin]
            future: S,
        },
        Flush {
            #[pin]
            future: F,
        },
        Close {
            #[pin]
            future: C,
        },
        Empty,
    }
}

impl<T, S, F, C> State<T, S, F, C> {
    fn take_value(self: Pin<&mut Self>) -> Option<T> {
        match &*self {
            Self::Value { .. } => match self.project_replace(Self::Empty) {
                StateProjReplace::Value { value } => Some(value),
                _ => unreachable!(),
            },
            _ => None,
        }
    }

    fn poll_value<E>(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<T, E>>
    where
        S: Future<Output = Result<T, E>>,
        F: Future<Output = Result<T, E>>,
        C: Future<Output = Result<T, E>>,
    {
        match self.as_mut().project() {
            StateProj::Send { future } => future.poll(cx),
            StateProj::Flush { future } => future.poll(cx),
            StateProj::Close { future } => future.poll(cx),
            StateProj::Value { .. } | StateProj::Empty => {
                Poll::Ready(Ok(self.take_value().expect("value lost, this is a bug")))
            }
        }
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[must_use = "sinks do nothing unless polled"]
    pub struct Unfold<T, S, F, C, SF, FF, CF> {
        send: S,
        flush: F,
        close: C,
        #[pin]
        state: State<T, SF, FF, CF>,
    }
}

impl<T, S, F, C, SF, FF, CF, Item, E> Sink<Item> for Unfold<T, S, F, C, SF, FF, CF>
where
    S: FnMut(T, Item) -> SF,
    SF: Future<Output = Result<T, E>>,
    F: FnMut(T) -> FF,
    FF: Future<Output = Result<T, E>>,
    C: FnMut(T) -> CF,
    CF: Future<Output = Result<T, E>>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.project();
        let value = ready!(project.state.as_mut().poll_value(cx)?);
        project.state.set(State::Value { value });
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let mut project = self.project();
        let future = match project.state.as_mut().take_value() {
            Some(value) => (project.send)(value, item),
            None => panic!("start_send called without poll_ready being called first"),
        };
        project.state.set(State::Send { future });
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, State::Flush { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(State::Flush {
                future: (project.flush)(value),
            });
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        loop {
            if matches!(self.deref().state, State::Close { .. }) {
                return self.poll_ready(cx);
            }

            let mut project = self.as_mut().project();
            let value = ready!(project.state.as_mut().poll_value(cx))?;
            project.state.set(State::Close {
                future: (project.close)(value),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// QUIC control trait forwarding for Unfold
// ---------------------------------------------------------------------------

impl<T: GetStreamId + Unpin, S, F, C, SF, FF, CF> GetStreamId for Unfold<T, S, F, C, SF, FF, CF> {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let this = self.project();
        match this.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_stream_id(cx),
            _ => Poll::Pending,
        }
    }
}

impl<T: CancelStream + Unpin, S, F, C, SF, FF, CF> CancelStream for Unfold<T, S, F, C, SF, FF, CF> {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.project();
        match this.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_cancel(cx, code),
            _ => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Unfold constructor
// ---------------------------------------------------------------------------

pub fn unfold<T, S, F, C, SF, FF, CF, Item, E>(
    init: T,
    send: S,
    flush: F,
    close: C,
) -> Unfold<T, S, F, C, SF, FF, CF>
where
    S: FnMut(T, Item) -> SF,
    SF: Future<Output = Result<T, E>>,
    F: FnMut(T) -> FF,
    FF: Future<Output = Result<T, E>>,
    C: FnMut(T) -> CF,
    CF: Future<Output = Result<T, E>>,
{
    let state = State::Value { value: init };
    Unfold {
        send,
        flush,
        close,
        state,
    }
}

// ---------------------------------------------------------------------------
// WriteStream conversion methods
// ---------------------------------------------------------------------------

impl WriteStream {
    pub fn as_bytes_sink(&mut self) -> impl WriteMessageStream + '_ {
        unfold(
            self,
            async |stream: &mut WriteStream, buf: Bytes| {
                stream.write_data(buf).await.map(|_| stream)
            },
            async |stream: &mut WriteStream| stream.flush().await.map(|_| stream),
            async |stream: &mut WriteStream| stream.close().await.map(|_| stream),
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
            async |mut stream: WriteStream, buf: Bytes| {
                stream.write_data(buf).await.map(|_| stream)
            },
            async |mut stream: WriteStream| stream.flush().await.map(|_| stream),
            async |mut stream: WriteStream| stream.close().await.map(|_| stream),
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

    use futures::{FutureExt, SinkExt, future::poll_fn};

    use super::*;
    use crate::quic::{CancelStream, GetStreamId};

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Send(Bytes),
        Flush,
        Close,
        Cancel(VarInt),
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

    impl CancelStream for ControlSink {
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

    type ControlReady = futures::future::Ready<Result<ControlSink, MessageStreamError>>;
    type ReadyState = State<ControlSink, ControlReady, ControlReady, ControlReady>;

    fn control_sink(stream_id: VarInt) -> ControlSink {
        ControlSink {
            stream_id,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn ready_control(stream_id: VarInt) -> ControlReady {
        futures::future::ready(Ok(control_sink(stream_id)))
    }

    fn send_ok(stream: ControlSink, _item: Bytes) -> ControlReady {
        futures::future::ready(Ok(stream))
    }

    fn operation_ok(stream: ControlSink) -> ControlReady {
        futures::future::ready(Ok(stream))
    }

    fn send_pending(
        _stream: ControlSink,
        _item: Bytes,
    ) -> futures::future::Pending<Result<ControlSink, MessageStreamError>> {
        futures::future::pending()
    }

    fn operation_pending(
        _stream: ControlSink,
    ) -> futures::future::Pending<Result<ControlSink, MessageStreamError>> {
        futures::future::pending()
    }

    fn send_message_failed(_stream: ControlSink, _item: Bytes) -> ControlReady {
        futures::future::ready(Err(MessageStreamError::MessageSendFailed))
    }

    fn send_malformed_outgoing(_stream: ControlSink, _item: Bytes) -> ControlReady {
        futures::future::ready(Err(MessageStreamError::MalformedOutgoingMessage))
    }

    fn operation_message_failed(_stream: ControlSink) -> ControlReady {
        futures::future::ready(Err(MessageStreamError::MessageSendFailed))
    }

    fn operation_malformed_outgoing(_stream: ControlSink) -> ControlReady {
        futures::future::ready(Err(MessageStreamError::MalformedOutgoingMessage))
    }

    fn record_send(stream: ControlSink, item: Bytes) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Send(item));
        futures::future::ready(Ok(stream))
    }

    fn record_flush(stream: ControlSink) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Flush);
        futures::future::ready(Ok(stream))
    }

    fn record_close(stream: ControlSink) -> ControlReady {
        stream
            .events
            .lock()
            .expect("event log poisoned")
            .push(Event::Close);
        futures::future::ready(Ok(stream))
    }

    #[derive(Debug)]
    struct GateFuture {
        value: Option<ControlSink>,
        open: Arc<AtomicBool>,
    }

    impl Future for GateFuture {
        type Output = Result<ControlSink, MessageStreamError>;

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.open.load(Ordering::SeqCst) {
                Poll::Ready(Ok(self
                    .value
                    .take()
                    .expect("gate future polled after ready")))
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
            future: ready_control(VarInt::from_u32(5)),
        };
        assert!(Pin::new(&mut send).take_value().is_none());

        let mut flush = ReadyState::Flush {
            future: ready_control(VarInt::from_u32(7)),
        };
        assert!(Pin::new(&mut flush).take_value().is_none());

        let mut close = ReadyState::Close {
            future: ready_control(VarInt::from_u32(9)),
        };
        assert!(Pin::new(&mut close).take_value().is_none());
    }

    #[test]
    fn state_poll_value_covers_value_send_flush_close_and_empty() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut value = ReadyState::Value {
            value: ControlSink {
                stream_id: VarInt::from_u32(13),
                events: events.clone(),
            },
        };
        assert_eq!(
            poll_fn(|cx| Pin::new(&mut value).poll_value(cx))
                .now_or_never()
                .expect("value state should be ready")
                .expect("value state should return Ok")
                .stream_id,
            VarInt::from_u32(13)
        );

        let mut send = ReadyState::Send {
            future: futures::future::ready(Ok(ControlSink {
                stream_id: VarInt::from_u32(17),
                events: events.clone(),
            })),
        };
        assert_eq!(
            poll_fn(|cx| Pin::new(&mut send).poll_value(cx))
                .now_or_never()
                .expect("send future should be ready")
                .expect("send future should return Ok")
                .stream_id,
            VarInt::from_u32(17)
        );

        let mut flush = ReadyState::Flush {
            future: futures::future::ready(Ok(ControlSink {
                stream_id: VarInt::from_u32(19),
                events: events.clone(),
            })),
        };
        assert_eq!(
            poll_fn(|cx| Pin::new(&mut flush).poll_value(cx))
                .now_or_never()
                .expect("flush future should be ready")
                .expect("flush future should return Ok")
                .stream_id,
            VarInt::from_u32(19)
        );

        let mut close = ReadyState::Close {
            future: futures::future::ready(Ok(ControlSink {
                stream_id: VarInt::from_u32(23),
                events,
            })),
        };
        assert_eq!(
            poll_fn(|cx| Pin::new(&mut close).poll_value(cx))
                .now_or_never()
                .expect("close future should be ready")
                .expect("close future should return Ok")
                .stream_id,
            VarInt::from_u32(23)
        );

        let mut empty = ReadyState::Empty;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = poll_fn(|cx| Pin::new(&mut empty).poll_value(cx)).now_or_never();
        }));
        assert!(panic.is_err());
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
                move |stream: ControlSink| {
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
                move |stream: ControlSink| {
                    close_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: close_open.clone(),
                    }
                }
            },
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
                move |stream: ControlSink, _item: Bytes| {
                    send_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: send_open.clone(),
                    }
                }
            },
            {
                let flush_started = flush_started.clone();
                move |stream: ControlSink| {
                    flush_started.fetch_add(1, Ordering::SeqCst);
                    futures::future::ready(Ok::<_, MessageStreamError>(stream))
                }
            },
            operation_ok,
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
                move |stream: ControlSink, _item: Bytes| {
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
                move |stream: ControlSink| {
                    close_started.fetch_add(1, Ordering::SeqCst);
                    futures::future::ready(Ok::<_, MessageStreamError>(stream))
                }
            },
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
        let cancel_code = VarInt::from_u32(34);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id,
                events: events.clone(),
            },
            {
                let send_open = send_open.clone();
                let send_started = send_started.clone();
                move |stream: ControlSink, _item: Bytes| {
                    send_started.fetch_add(1, Ordering::SeqCst);
                    GateFuture {
                        value: Some(stream),
                        open: send_open.clone(),
                    }
                }
            },
            operation_ok,
            operation_ok,
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
        poll_fn(|cx| sink.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("cancel should be available after send completes");
        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![Event::Cancel(cancel_code)]
        );
    }

    #[tokio::test]
    async fn control_traits_forward_while_value_available() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stream_id = VarInt::from_u32(37);
        let cancel_code = VarInt::from_u32(41);
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id,
                events: events.clone(),
            },
            send_ok,
            operation_ok,
            operation_ok,
        ));

        assert_eq!(
            poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| sink.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("cancel forwarded");

        assert_eq!(
            *events.lock().expect("event log poisoned"),
            vec![Event::Cancel(cancel_code)]
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
            poll_fn(|cx| sink.as_mut().poll_cancel(cx, VarInt::from_u32(41)))
                .now_or_never()
                .is_none()
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
            poll_fn(|cx| flush_sink.as_mut().poll_cancel(cx, VarInt::from_u32(56)))
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
            poll_fn(|cx| close_sink.as_mut().poll_cancel(cx, VarInt::from_u32(58)))
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
        ));
        assert!(matches!(
            poll_fn(|cx| close_sink.as_mut().poll_close(cx)).await,
            Err(MessageStreamError::MalformedOutgoingMessage)
        ));
    }

    #[tokio::test]
    async fn write_stream_adapter_builders_preserve_sink_and_control_traits() {
        let stream_id = VarInt::from_u32(71);
        let cancel_code = VarInt::from_u32(72);

        let mut bytes_stream = crate::message::test::write_stream_for_test(stream_id);
        {
            let mut sink = Box::pin(bytes_stream.as_bytes_sink());
            assert_eq!(
                poll_fn(|cx| sink.as_mut().poll_stream_id(cx))
                    .await
                    .expect("as_bytes_sink stream id"),
                stream_id
            );
            poll_fn(|cx| sink.as_mut().poll_cancel(cx, cancel_code))
                .await
                .expect("as_bytes_sink cancel");
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
        poll_fn(|cx| owned_sink.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("into_bytes_sink cancel");
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
            poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
                .await
                .expect("as_writer cancel");
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
            poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
                .await
                .expect("as_box_writer cancel");
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
        poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("into_writer cancel");
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
        poll_fn(|cx| boxed_writer.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("into_box_writer cancel");
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
        poll_fn(|cx| from_writer.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("from cancel");
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
        let cancel_code = VarInt::from_u32(82);

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
            poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
                .await
                .expect("as_writer cancel with buffered send");
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
            poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
                .await
                .expect("as_box_writer cancel with buffered send");
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
        poll_fn(|cx| writer.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("into_writer cancel with buffered send");
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
        poll_fn(|cx| boxed_writer.as_mut().poll_cancel(cx, cancel_code))
            .await
            .expect("into_box_writer cancel with buffered send");
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
