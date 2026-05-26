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
        sync::{Arc, Mutex},
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

    #[tokio::test]
    async fn unfold_sends_flushes_and_closes_in_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(11),
                events: events.clone(),
            },
            |stream: ControlSink, item: Bytes| async move {
                stream
                    .events
                    .lock()
                    .expect("event log poisoned")
                    .push(Event::Send(item));
                Ok::<_, MessageStreamError>(stream)
            },
            |stream: ControlSink| async move {
                stream
                    .events
                    .lock()
                    .expect("event log poisoned")
                    .push(Event::Flush);
                Ok::<_, MessageStreamError>(stream)
            },
            |stream: ControlSink| async move {
                stream
                    .events
                    .lock()
                    .expect("event log poisoned")
                    .push(Event::Close);
                Ok::<_, MessageStreamError>(stream)
            },
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
    async fn control_traits_forward_while_value_available() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let stream_id = VarInt::from_u32(37);
        let cancel_code = VarInt::from_u32(41);
        let mut sink = Box::pin(unfold(
            ControlSink {
                stream_id,
                events: events.clone(),
            },
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
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
            |_stream: ControlSink, _item: Bytes| {
                futures::future::pending::<Result<ControlSink, MessageStreamError>>()
            },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
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
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
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
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |_stream: ControlSink| {
                futures::future::pending::<Result<ControlSink, MessageStreamError>>()
            },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
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
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
            |_stream: ControlSink| {
                futures::future::pending::<Result<ControlSink, MessageStreamError>>()
            },
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
    async fn unfold_propagates_flush_and_close_errors() {
        let mut flush_sink = Box::pin(unfold(
            ControlSink {
                stream_id: VarInt::from_u32(61),
                events: Arc::new(Mutex::new(Vec::new())),
            },
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |_stream: ControlSink| async move {
                Err::<ControlSink, _>(MessageStreamError::MessageSendFailed)
            },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
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
            |stream: ControlSink, _item: Bytes| async move { Ok::<_, MessageStreamError>(stream) },
            |stream: ControlSink| async move { Ok::<_, MessageStreamError>(stream) },
            |_stream: ControlSink| async move {
                Err::<ControlSink, _>(MessageStreamError::MalformedOutgoingMessage)
            },
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
}
