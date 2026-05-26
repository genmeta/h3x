use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::stream::FusedStream;

use super::super::{MessageStreamError, ReadStream};
use crate::{
    codec::StreamReader,
    quic::{self, GetStreamId, StopStream},
    varint::VarInt,
};

/// A message-level byte stream that also supports QUIC stream control operations.
///
/// This is the message-layer analog of [`quic::ReadStream`], combining DATA-frame
/// byte streaming with the underlying QUIC stream's [`StopStream`] and
/// [`GetStreamId`] capabilities.
pub trait ReadMessageStream:
    StopStream + GetStreamId + FusedStream<Item = Result<Bytes, MessageStreamError>> + Send
{
}

impl<
    T: StopStream
        + GetStreamId
        + FusedStream<Item = Result<Bytes, MessageStreamError>>
        + Send
        + ?Sized,
> ReadMessageStream for T
{
}

/// Boxed stream reader with QUIC stream control traits preserved.
pub type BoxMessageStreamReader<'s> = StreamReader<Pin<Box<dyn ReadMessageStream + 's>>>;

impl From<ReadStream> for BoxMessageStreamReader<'static> {
    fn from(value: ReadStream) -> Self {
        value.into_box_reader()
    }
}

// ---------------------------------------------------------------------------
// Unfold – custom stream unfold that preserves QUIC traits
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = StateProj]
    #[project_replace = StateProjReplace]
    enum State<T, Fut> {
        Value { value: T },
        Future { #[pin] future: Fut },
        Done,
        Empty,
    }
}

pin_project_lite::pin_project! {
    /// A fused stream adapter similar to [`futures::stream::unfold`], but the
    /// inner value's QUIC control traits ([`GetStreamId`], [`StopStream`]) are
    /// forwarded when the value is not consumed by an in-flight future.
    #[must_use = "streams do nothing unless polled"]
    pub struct Unfold<T, F, Fut> {
        f: F,
        #[pin]
        state: State<T, Fut>,
    }
}

/// Create an [`Unfold`] stream.
///
/// Works like [`futures::stream::unfold`] but the returned stream conditionally
/// implements [`GetStreamId`] and [`StopStream`] when `T` does.
pub fn unfold<T, F, Fut, Item>(init: T, f: F) -> Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(Item, T)>>,
{
    Unfold {
        f,
        state: State::Value { value: init },
    }
}

impl<T, F, Fut, Item> futures::Stream for Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(Item, T)>>,
{
    type Item = Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            match this.state.as_mut().project() {
                StateProj::Value { .. } => {
                    let value = match this.state.as_mut().project_replace(State::Empty) {
                        StateProjReplace::Value { value } => value,
                        _ => unreachable!(),
                    };
                    let fut = (this.f)(value);
                    this.state.set(State::Future { future: fut });
                }
                StateProj::Future { future } => match ready!(future.poll(cx)) {
                    Some((item, value)) => {
                        this.state.set(State::Value { value });
                        return Poll::Ready(Some(item));
                    }
                    None => {
                        this.state.set(State::Done);
                        return Poll::Ready(None);
                    }
                },
                StateProj::Done | StateProj::Empty => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

impl<T, F, Fut, Item> FusedStream for Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(Item, T)>>,
{
    fn is_terminated(&self) -> bool {
        matches!(self.state, State::Done)
    }
}

impl<T: GetStreamId + Unpin, F, Fut, Item> GetStreamId for Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(Item, T)>>,
{
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

impl<T: StopStream + Unpin, F, Fut, Item> StopStream for Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(Item, T)>>,
{
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.project();
        match this.state.project() {
            StateProj::Value { value } => Pin::new(value).poll_stop(cx, code),
            _ => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// ReadStream conversion methods
// ---------------------------------------------------------------------------

impl ReadStream {
    pub fn as_bytes_stream(&mut self) -> impl ReadMessageStream + '_ {
        unfold(self, |this: &mut ReadStream| async move {
            match this.read_data_chunk().await {
                Ok(Some(bytes)) => Some((Ok(bytes), this)),
                Ok(None) => None,
                Err(error) => Some((Err(error), this)),
            }
        })
    }

    pub fn as_reader(&mut self) -> StreamReader<impl ReadMessageStream + '_> {
        StreamReader::new(self.as_bytes_stream())
    }

    pub fn as_box_reader(&mut self) -> BoxMessageStreamReader<'_> {
        StreamReader::new(Box::pin(self.as_bytes_stream()))
    }

    pub fn into_bytes_stream(self) -> impl ReadMessageStream {
        unfold(self, |mut this: ReadStream| async move {
            match this.read_data_chunk().await {
                Ok(Some(bytes)) => Some((Ok(bytes), this)),
                Ok(None) => None,
                Err(error) => Some((Err(error), this)),
            }
        })
    }

    pub fn into_reader(self) -> StreamReader<impl ReadMessageStream> {
        StreamReader::new(self.into_bytes_stream())
    }

    pub fn into_box_reader(self) -> BoxMessageStreamReader<'static> {
        StreamReader::new(Box::pin(self.into_bytes_stream()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use futures::{FutureExt, StreamExt, future::poll_fn};

    use super::*;

    #[derive(Debug)]
    struct ControlStream {
        stream_id: VarInt,
        stopped: Arc<Mutex<Option<VarInt>>>,
    }

    impl GetStreamId for ControlStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for ControlStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn unfold_yields_items_and_reports_termination() {
        let mut stream = Box::pin(unfold(0, |value| async move {
            if value < 3 {
                Some((value, value + 1))
            } else {
                None
            }
        }));

        assert_eq!(stream.as_mut().next().await, Some(0));
        assert_eq!(stream.as_mut().next().await, Some(1));
        assert_eq!(stream.as_mut().next().await, Some(2));
        assert_eq!(stream.as_mut().next().await, None);
        assert!(stream.as_ref().get_ref().is_terminated());
    }

    #[tokio::test]
    async fn control_traits_forward_while_value_available() {
        let stopped = Arc::new(Mutex::new(None));
        let stream_id = VarInt::from_u32(37);
        let stop_code = VarInt::from_u32(41);
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id,
                stopped: stopped.clone(),
            },
            |stream| async move { Some(((), stream)) },
        ));

        assert_eq!(
            poll_fn(|cx| stream.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop forwarded");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn control_traits_wait_while_future_owns_value() {
        let stopped = Arc::new(Mutex::new(None));
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id: VarInt::from_u32(37),
                stopped,
            },
            |_stream| futures::future::pending::<Option<((), ControlStream)>>(),
        ));

        assert!(futures::poll!(stream.as_mut().next()).is_pending());
        assert!(
            poll_fn(|cx| stream.as_mut().poll_stream_id(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| stream.as_mut().poll_stop(cx, VarInt::from_u32(41)))
                .now_or_never()
                .is_none()
        );
    }
}
