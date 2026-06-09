use std::{
    future::Future,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::stream::FusedStream;

use super::super::{BoxMessageReader, MessageReader, MessageStreamError};
use crate::{
    codec::StreamReader,
    quic::{self, GetStreamId as QuicGetStreamId, StopStream as QuicStopStream},
    stream,
    varint::VarInt,
};

impl From<MessageReader> for BoxMessageReader {
    fn from(value: MessageReader) -> Self {
        value.into_box_reader()
    }
}

// ---------------------------------------------------------------------------
// Unfold – custom stream unfold that preserves QUIC traits
// ---------------------------------------------------------------------------

pin_project_lite::pin_project! {
    #[project = StateProj]
    #[project_replace = StateProjReplace]
    enum State<StreamState, ReadFuture, StopFuture> {
        Stream { stream: StreamState },
        Read {
            token: tokio_util::sync::CancellationToken,
            #[pin]
            future: ReadFuture,
        },
        Stop {
            code: VarInt,
            #[pin]
            future: StopFuture,
        },
        Empty,
    }
}

impl<StreamState, ReadFuture, StopFuture> State<StreamState, ReadFuture, StopFuture> {
    fn take_stream(self: Pin<&mut Self>) -> StreamState {
        match self.project_replace(Self::Empty) {
            StateProjReplace::Stream { stream } => stream,
            _ => unreachable!("invalid state for take_stream"),
        }
    }
}

pin_project_lite::pin_project! {
    /// A fused stream adapter similar to [`futures::stream::unfold`], but with
    /// stream-specific read and stop futures that always return the stream state.
    #[must_use = "streams do nothing unless polled"]
    pub struct Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item> {
        read: Read,
        stop: Stop,
        terminated: bool,
        pending_stop: Option<VarInt>,
        pending_item: Option<Item>,
        _item: std::marker::PhantomData<fn() -> Item>,
        #[pin]
        state: State<StreamState, ReadFuture, StopFuture>,
    }
}

trait StreamErrorItem {
    fn from_stream_error(error: quic::StreamError) -> Self;
}

impl<Value, Error> StreamErrorItem for Result<Value, Error>
where
    Error: From<quic::StreamError>,
{
    fn from_stream_error(error: quic::StreamError) -> Self {
        Err(error.into())
    }
}

/// Create an [`Unfold`] stream.
///
/// The read future yields either a delivered item plus the returned stream
/// state, EOF plus the returned stream state, or an internally interrupted
/// stream state. The stop future is a separate operation so callers can adapt
/// states whose stop behavior is not expressed directly as a [`crate::quic::StopStream`]
/// implementation.
pub fn unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>(
    init: StreamState,
    read: Read,
    stop: Stop,
) -> Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
{
    Unfold {
        read,
        stop,
        terminated: false,
        pending_stop: None,
        pending_item: None,
        _item: std::marker::PhantomData,
        state: State::Stream { stream: init },
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
    Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
{
    fn poll_pending_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), quic::StreamError>> {
        let Some(code) = self.as_mut().project().pending_stop.as_ref().copied() else {
            return Poll::Ready(Ok(()));
        };

        loop {
            let mut project = self.as_mut().project();
            match project.state.as_mut().project() {
                StateProj::Stream { .. } => {
                    let stream = project.state.as_mut().take_stream();
                    project.state.set(State::Stop {
                        code,
                        future: (project.stop)(stream, code),
                    });
                }
                StateProj::Read { .. } => return Poll::Pending,
                StateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    project.state.set(State::Stream { stream });
                    *project.pending_stop = None;
                    return Poll::Ready(result);
                }
                StateProj::Empty => unreachable!("invalid state for poll_pending_stop"),
            }
        }
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> futures::Stream
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
    Item: StreamErrorItem,
{
    type Item = Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(item) = self.as_mut().project().pending_item.take() {
            return Poll::Ready(Some(item));
        }

        loop {
            let mut project = self.as_mut().project();
            match project.state.as_mut().project() {
                StateProj::Stream { .. } => {
                    if *project.terminated {
                        return Poll::Ready(None);
                    }
                    let stream = project.state.as_mut().take_stream();
                    let token = tokio_util::sync::CancellationToken::new();
                    project.state.set(State::Read {
                        token: token.clone(),
                        future: (project.read)(stream, token),
                    });
                }
                StateProj::Read { future, .. } => match ready!(future.poll(cx)) {
                    futures::future::Either::Left((stream, item)) => {
                        if item.is_none() {
                            *project.terminated = true;
                        }
                        project.state.set(State::Stream { stream });
                        return Poll::Ready(item);
                    }
                    futures::future::Either::Right(stream) => {
                        project.state.set(State::Stream { stream });
                    }
                },
                StateProj::Stop { future, .. } => {
                    let (stream, result) = ready!(future.poll(cx));
                    project.state.set(State::Stream { stream });
                    *project.pending_stop = None;
                    if let Err(error) = result {
                        return Poll::Ready(Some(Item::from_stream_error(error)));
                    }
                }
                StateProj::Empty => unreachable!("invalid state for poll_next"),
            }
        }
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> FusedStream
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
    Item: StreamErrorItem,
{
    fn is_terminated(&self) -> bool {
        self.terminated
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> stream::GetStreamId<quic::StreamError>
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    StreamState: stream::GetStreamId<quic::StreamError> + Unpin,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let project = self.project();
        match project.state.project() {
            StateProj::Stream { stream } => Pin::new(stream).poll_stream_id(cx),
            _ => Poll::Pending,
        }
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> stream::StopStream<quic::StreamError>
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
{
    fn poll_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        if self.as_mut().project().pending_stop.is_none() {
            *self.as_mut().project().pending_stop = Some(code);
        }
        self.poll_pending_stop(cx)
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> QuicGetStreamId
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    StreamState: QuicGetStreamId + Unpin,
{
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let project = self.project();
        match project.state.project() {
            StateProj::Stream { stream } => Pin::new(stream).poll_stream_id(cx),
            _ => Poll::Pending,
        }
    }
}

impl<StreamState, Read, Stop, ReadFuture, StopFuture, Item> QuicStopStream
    for Unfold<StreamState, Read, Stop, ReadFuture, StopFuture, Item>
where
    Read: FnMut(StreamState, tokio_util::sync::CancellationToken) -> ReadFuture,
    ReadFuture: Future<Output = futures::future::Either<(StreamState, Option<Item>), StreamState>>,
    Stop: FnMut(StreamState, VarInt) -> StopFuture,
    StopFuture: Future<Output = (StreamState, Result<(), quic::StreamError>)>,
{
    fn poll_stop(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        if self.as_mut().project().pending_stop.is_none() {
            *self.as_mut().project().pending_stop = Some(code);
        }
        self.poll_pending_stop(cx)
    }
}

// ---------------------------------------------------------------------------
// MessageReader conversion methods
// ---------------------------------------------------------------------------

impl MessageReader {
    pub fn as_bytes_stream(
        &mut self,
    ) -> impl stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
    + QuicGetStreamId
    + QuicStopStream
    + FusedStream
    + Send
    + '_ {
        unfold(
            self,
            |stream: &mut MessageReader, token| async move {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => futures::future::Either::Right(stream),
                    result = stream.read_data_chunk() => {
                        let item = match result {
                            Ok(Some(bytes)) => Some(Ok(bytes)),
                            Ok(None) => None,
                            Err(error) => Some(Err(error)),
                        };
                        futures::future::Either::Left((stream, item))
                    }
                }
            },
            |mut stream: &mut MessageReader, code| async move {
                let result = futures::future::poll_fn(|cx| {
                    QuicStopStream::poll_stop(Pin::new(stream.deref_mut()), cx, code)
                })
                .await;
                (stream, result)
            },
        )
    }

    pub fn as_reader(
        &mut self,
    ) -> StreamReader<
        impl stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + QuicGetStreamId
        + QuicStopStream
        + FusedStream
        + Send
        + '_,
    > {
        StreamReader::new(self.as_bytes_stream())
    }

    pub fn as_box_reader(
        &mut self,
    ) -> Pin<
        Box<
            dyn stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
                + Send
                + '_,
        >,
    > {
        Box::pin(self.as_bytes_stream())
    }

    pub fn into_bytes_stream(
        self,
    ) -> impl stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
    + QuicGetStreamId
    + QuicStopStream
    + FusedStream
    + Send {
        unfold(
            self,
            |mut stream: MessageReader, token| async move {
                tokio::select! {
                    biased;
                    _ = token.cancelled() => futures::future::Either::Right(stream),
                    result = stream.read_data_chunk() => {
                        let item = match result {
                            Ok(Some(bytes)) => Some(Ok(bytes)),
                            Ok(None) => None,
                            Err(error) => Some(Err(error)),
                        };
                        futures::future::Either::Left((stream, item))
                    }
                }
            },
            |mut stream: MessageReader, code| async move {
                let result = futures::future::poll_fn(|cx| {
                    QuicStopStream::poll_stop(Pin::new(&mut stream), cx, code)
                })
                .await;
                (stream, result)
            },
        )
    }

    pub fn into_reader(
        self,
    ) -> StreamReader<
        impl stream::ReadStream<Bytes, MessageStreamError, quic::StreamError, quic::StreamError>
        + QuicGetStreamId
        + QuicStopStream
        + FusedStream
        + Send,
    > {
        StreamReader::new(self.into_bytes_stream())
    }

    pub fn into_box_reader(self) -> BoxMessageReader {
        Box::pin(self.into_bytes_stream())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use futures::{
        FutureExt, Stream, StreamExt,
        future::{Either, poll_fn},
    };
    use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

    use super::*;

    #[derive(Debug)]
    struct ControlStream {
        stream_id: VarInt,
        stopped: Arc<Mutex<Option<VarInt>>>,
    }

    impl stream::GetStreamId<quic::StreamError> for ControlStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl stream::StopStream<quic::StreamError> for ControlStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    impl QuicGetStreamId for ControlStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl QuicStopStream for ControlStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            *self.stopped.lock().expect("stop state poisoned") = Some(code);
            Poll::Ready(Ok(()))
        }
    }

    async fn stop_ok<StreamState>(
        stream: StreamState,
        _code: VarInt,
    ) -> (StreamState, Result<(), quic::StreamError>) {
        (stream, Ok(()))
    }

    #[tokio::test]
    async fn unfold_yields_items_and_reports_termination() {
        let mut stream = Box::pin(unfold(
            0,
            |value, _token| async move {
                let item = (value < 3).then_some(Ok::<_, quic::StreamError>(value));
                Either::Left((value + 1, item))
            },
            stop_ok,
        ));

        assert_eq!(stream.as_mut().next().await.unwrap().unwrap(), 0);
        assert_eq!(stream.as_mut().next().await.unwrap().unwrap(), 1);
        assert_eq!(stream.as_mut().next().await.unwrap().unwrap(), 2);
        assert!(stream.as_mut().next().await.is_none());
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
            |stream, _token| async move { Either::Left((stream, Some(Ok::<_, quic::StreamError>(())))) },
            |stream: ControlStream, code| async move {
                *stream.stopped.lock().expect("stop state poisoned") = Some(code);
                (stream, Ok(()))
            },
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
            |_stream, _token| {
                futures::future::pending::<
                    Either<(ControlStream, Option<Result<(), quic::StreamError>>), ControlStream>,
                >()
            },
            |stream: ControlStream, code| async move {
                *stream.stopped.lock().expect("stop state poisoned") = Some(code);
                (stream, Ok(()))
            },
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

    #[tokio::test]
    async fn stop_waits_for_pending_read_before_forwarding() {
        let stopped = Arc::new(Mutex::new(None));
        let stop_code = VarInt::from_u32(41);
        let stream_id = VarInt::from_u32(37);
        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let mut read_rx = Some(read_rx);
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id,
                stopped: stopped.clone(),
            },
            move |stream, _token| {
                let read_rx = read_rx.take().expect("single read future");
                async move {
                    read_rx.await.expect("read release sent");
                    Either::Left((stream, Some(Ok::<_, quic::StreamError>(()))))
                }
            },
            |stream: ControlStream, code| async move {
                *stream.stopped.lock().expect("stop state poisoned") = Some(code);
                (stream, Ok(()))
            },
        ));

        assert!(
            poll_fn(|cx| stream.as_mut().poll_next(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
                .now_or_never()
                .is_none()
        );
        assert_eq!(*stopped.lock().expect("stop state poisoned"), None);

        read_tx.send(()).expect("release pending read");
        assert!(matches!(stream.as_mut().next().await, Some(Ok(()))));
        poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop should complete after read yields stream");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
        assert_eq!(
            poll_fn(|cx| stream.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id should remain available"),
            stream_id
        );
    }

    #[tokio::test]
    async fn stop_does_not_interrupt_pending_next() {
        let stopped = Arc::new(Mutex::new(None));
        let stop_code = VarInt::from_u32(41);
        let (read_tx, read_rx) = tokio::sync::oneshot::channel();
        let mut read_rx = Some(read_rx);
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id: VarInt::from_u32(37),
                stopped: stopped.clone(),
            },
            move |stream, token| {
                let read_rx = read_rx.take().expect("single read future");
                async move {
                    tokio::select! {
                        biased;
                        _ = token.cancelled() => Either::Left((
                            stream,
                            Some(Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"interrupted"))),
                        )),
                        item = read_rx => Either::Left((
                            stream,
                            Some(Ok::<Bytes, MessageStreamError>(
                                item.expect("read release sent"),
                            )),
                        )),
                    }
                }
            },
            |stream: ControlStream, code| async move {
                *stream.stopped.lock().expect("stop state poisoned") = Some(code);
                (stream, Ok(()))
            },
        ));

        assert!(
            poll_fn(|cx| stream.as_mut().poll_next(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
                .now_or_never()
                .is_none(),
            "stop must wait for the read future without cancelling it"
        );
        assert_eq!(*stopped.lock().expect("stop state poisoned"), None);

        read_tx
            .send(Bytes::from_static(b"read"))
            .expect("release pending read");
        assert_eq!(
            stream
                .as_mut()
                .next()
                .await
                .expect("read item")
                .expect("read succeeds"),
            Bytes::from_static(b"read")
        );
        assert_eq!(*stopped.lock().expect("stop state poisoned"), None);

        poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop completes after read yields the stream");
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn stop_waits_for_pending_read_that_reaches_eof() {
        let stopped = Arc::new(Mutex::new(None));
        let stop_code = VarInt::from_u32(41);
        let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
        let mut eof_rx = Some(eof_rx);
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id: VarInt::from_u32(37),
                stopped: stopped.clone(),
            },
            move |stream, _token| {
                let eof_rx = eof_rx.take().expect("single read future");
                async move {
                    eof_rx.await.expect("eof release sent");
                    Either::<
                        (ControlStream, Option<Result<(), quic::StreamError>>),
                        ControlStream,
                    >::Left((stream, None))
                }
            },
            |stream: ControlStream, code| async move {
                *stream.stopped.lock().expect("stop state poisoned") = Some(code);
                (stream, Ok(()))
            },
        ));

        assert!(
            poll_fn(|cx| stream.as_mut().poll_next(cx))
                .now_or_never()
                .is_none()
        );
        assert!(
            poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
                .now_or_never()
                .is_none()
        );

        eof_tx.send(()).expect("release pending eof");
        assert!(stream.as_mut().next().await.is_none());
        poll_fn(|cx| stream.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop should complete after eof yields stream");

        assert!(stream.as_ref().get_ref().is_terminated());
        assert_eq!(
            *stopped.lock().expect("stop state poisoned"),
            Some(stop_code)
        );
    }

    #[tokio::test]
    async fn unfold_yields_error_items_without_terminating_the_stream() {
        let mut stream = Box::pin(unfold(
            VecDeque::from([
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"chunk-1")),
                Err::<Bytes, MessageStreamError>(MessageStreamError::MalformedIncomingMessage),
                Ok(Bytes::from_static(b"chunk-2")),
            ]),
            |mut items, _token| async move {
                let item = items.pop_front();
                Either::Left((items, item))
            },
            stop_ok,
        ));

        match stream.as_mut().next().await {
            Some(Ok(item)) => assert_eq!(item, Bytes::from_static(b"chunk-1")),
            value => panic!("unexpected first item: {value:?}"),
        }
        assert!(matches!(
            stream.as_mut().next().await,
            Some(Err(MessageStreamError::MalformedIncomingMessage))
        ));
        match stream.as_mut().next().await {
            Some(Ok(item)) => assert_eq!(item, Bytes::from_static(b"chunk-2")),
            value => panic!("unexpected third item: {value:?}"),
        }
        assert!(stream.as_mut().next().await.is_none());
        assert!(stream.as_ref().get_ref().is_terminated());
    }

    #[tokio::test]
    async fn stream_reader_implements_async_read_and_hits_eof() {
        let mut reader = Box::pin(StreamReader::new(unfold(
            VecDeque::from([
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"hel")),
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"lo")),
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"")),
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"world")),
            ]),
            |mut chunks, _token| async move {
                let chunk = chunks.pop_front();
                Either::Left((chunks, chunk))
            },
            stop_ok,
        )));

        let mut data = Vec::new();
        let mut read = 0;

        loop {
            let mut buf = [0_u8; 4];
            let n = poll_fn(|cx| {
                let mut read_buf = ReadBuf::new(&mut buf);
                match reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(ready) => Poll::Ready(ready.map(|_| read_buf.filled().len())),
                }
            })
            .await
            .unwrap();

            if n == 0 {
                break;
            }

            data.extend_from_slice(&buf[..n]);
            read += n;
        }

        assert_eq!(read, 10);
        assert_eq!(data, b"helloworld");
        let mut buf = [0_u8; 4];
        assert_eq!(
            poll_fn(|cx| {
                let mut read_buf = ReadBuf::new(&mut buf);
                match reader.as_mut().poll_read(cx, &mut read_buf) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(ready) => Poll::Ready(ready.map(|_| read_buf.filled().len())),
                }
            })
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn stream_reader_implements_async_buf_read() {
        let mut reader = Box::pin(StreamReader::new(unfold(
            VecDeque::from([
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"ab")),
                Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"cd")),
            ]),
            |mut chunks, _token| async move {
                let chunk = chunks.pop_front();
                Either::Left((chunks, chunk))
            },
            stop_ok,
        )));

        assert_eq!(
            poll_fn(|cx| {
                reader
                    .as_mut()
                    .poll_fill_buf(cx)
                    .map(|result| result.map(|buf| buf.to_vec()))
            })
            .await
            .unwrap(),
            b"ab"
        );
        reader.as_mut().consume(1);
        assert_eq!(
            poll_fn(|cx| {
                reader
                    .as_mut()
                    .poll_fill_buf(cx)
                    .map(|result| result.map(|buf| buf.to_vec()))
            })
            .await
            .unwrap(),
            b"b"
        );
        reader.as_mut().consume(1);
        assert_eq!(
            poll_fn(|cx| {
                reader
                    .as_mut()
                    .poll_fill_buf(cx)
                    .map(|result| result.map(|buf| buf.to_vec()))
            })
            .await
            .unwrap(),
            b"cd"
        );
        reader.as_mut().consume(2);
        assert_eq!(
            poll_fn(|cx| {
                reader
                    .as_mut()
                    .poll_fill_buf(cx)
                    .map(|result| result.map(|buf| buf.to_vec()))
            })
            .await
            .unwrap(),
            b""
        );
    }

    #[tokio::test]
    async fn read_stream_as_reader_reports_eof_and_termination() {
        let mut stream = crate::dhttp::message::test::read_stream_for_test(VarInt::from_u32(71));
        let mut reader = Box::pin(stream.as_reader());

        assert!(poll_fn(|cx| reader.as_mut().poll_next(cx)).await.is_none());
        assert!(reader.stream().is_terminated());
    }

    #[tokio::test]
    async fn read_stream_into_bytes_stream_forwards_control_traits_until_eof() {
        let stream_id = VarInt::from_u32(72);
        let stop_code = VarInt::from_u32(73);
        let stream = crate::dhttp::message::test::read_stream_for_test(stream_id);
        let mut bytes = Box::pin(stream.into_bytes_stream());

        assert_eq!(
            poll_fn(|cx| bytes.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );
        poll_fn(|cx| bytes.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop forwarded");

        assert!(poll_fn(|cx| bytes.as_mut().poll_next(cx)).await.is_none());
        assert!(bytes.as_ref().get_ref().is_terminated());
        assert_eq!(
            poll_fn(|cx| bytes.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id after eof"),
            stream_id
        );
        poll_fn(|cx| bytes.as_mut().poll_stop(cx, stop_code))
            .await
            .expect("stop after eof");
    }

    #[tokio::test]
    async fn read_stream_into_reader_reports_eof_and_termination() {
        let stream = crate::dhttp::message::test::read_stream_for_test(VarInt::from_u32(74));
        let mut reader = Box::pin(stream.into_reader());

        assert!(poll_fn(|cx| reader.as_mut().poll_next(cx)).await.is_none());
        assert!(reader.stream().is_terminated());
    }

    #[tokio::test]
    async fn read_stream_from_conversion_builds_box_reader() {
        let stream_id = VarInt::from_u32(75);
        let stream = crate::dhttp::message::test::read_stream_for_test(stream_id);
        let mut reader: BoxMessageReader = stream.into();

        assert_eq!(
            poll_fn(|cx| Pin::new(&mut reader).poll_stream_id(cx))
                .await
                .expect("stream id"),
            stream_id
        );

        assert!(poll_fn(|cx| reader.as_mut().poll_next(cx)).await.is_none());
    }

    #[tokio::test]
    async fn read_stream_into_box_reader_forwards_control_traits_and_stops_at_eof() {
        let stream_id = VarInt::from_u32(90);
        let stop_code = VarInt::from_u32(102);

        let mut stream = crate::dhttp::message::test::read_stream_for_test(stream_id);
        let mut reader = stream.as_box_reader();

        assert_eq!(
            poll_fn(|cx| stream::GetStreamId::poll_stream_id(Pin::new(&mut reader), cx))
                .await
                .unwrap(),
            stream_id
        );
        poll_fn(|cx| stream::StopStream::poll_stop(Pin::new(&mut reader), cx, stop_code))
            .await
            .unwrap();

        assert!(poll_fn(|cx| reader.as_mut().poll_next(cx)).await.is_none());
    }

    #[tokio::test]
    async fn unfold_waits_for_termination_controls_after_done() {
        let mut stream = Box::pin(unfold(
            ControlStream {
                stream_id: VarInt::from_u32(37),
                stopped: Arc::new(Mutex::new(None)),
            },
            |stream: ControlStream, _token| async move {
                Either::Left((stream, None::<Result<(), quic::StreamError>>))
            },
            stop_ok,
        ));

        assert!(stream.as_mut().next().await.is_none());
        assert!(stream.as_ref().get_ref().is_terminated());
        assert_eq!(
            poll_fn(|cx| stream.as_mut().poll_stream_id(cx))
                .await
                .expect("stream id after termination"),
            VarInt::from_u32(37)
        );
        poll_fn(|cx| stream.as_mut().poll_stop(cx, VarInt::from_u32(41)))
            .await
            .expect("stop after termination");
    }

    #[tokio::test]
    async fn stream_reader_maps_message_stream_error_items_to_io_errors() {
        let mut reader = Box::pin(StreamReader::new(unfold(
            VecDeque::from([Err::<Bytes, MessageStreamError>(
                MessageStreamError::MalformedIncomingMessage,
            )]),
            |mut chunks, _token| async move {
                let chunk = chunks.pop_front();
                Either::Left((chunks, chunk))
            },
            stop_ok,
        )));
        let mut buf = [0_u8; 4];

        let error = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut buf);
            match reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => Poll::Ready(result),
            }
        })
        .await
        .expect_err("error item should become io error");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn stream_reader_poll_next_returns_buffered_chunk_then_eof() {
        let mut reader = Box::pin(StreamReader::new(unfold(
            VecDeque::from([Ok::<Bytes, MessageStreamError>(Bytes::from_static(b"abcd"))]),
            |mut chunks, _token| async move {
                let chunk = chunks.pop_front();
                Either::Left((chunks, chunk))
            },
            stop_ok,
        )));
        let mut buf = [0_u8; 2];

        let read = poll_fn(|cx| {
            let mut read_buf = ReadBuf::new(&mut buf);
            match reader.as_mut().poll_read(cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => Poll::Ready(result.map(|_| read_buf.filled().len())),
            }
        })
        .await
        .expect("partial read succeeds");
        assert_eq!(read, 2);
        assert_eq!(&buf, b"ab");

        match poll_fn(|cx| reader.as_mut().poll_next(cx)).await {
            Some(Ok(chunk)) => assert_eq!(chunk, Bytes::from_static(b"cd")),
            value => panic!("unexpected buffered chunk: {value:?}"),
        }
        assert!(poll_fn(|cx| reader.as_mut().poll_next(cx)).await.is_none());
    }
}
