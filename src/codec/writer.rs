use std::{
    future::poll_fn,
    mem,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{BufMut, Bytes};
use futures::{Sink, Stream, StreamExt};
use tokio::io::{self, AsyncWrite};

use crate::{
    quic::{CancelStream, GetStreamId, StreamError},
    varint::VarInt,
};

pin_project_lite::pin_project! {
    /// Sink writer that supports both [`Sink`] and [`AsyncWrite`] interfaces.
    ///
    /// Be different from [`SinkWriter`] in [`tokio-util`], this writer will buffer
    /// data written by `AsyncWrite` interface, and you may need to call [`Self::poll_flush_buffer`]
    /// or [`Self::flush_buffer`] to flush the buffer to the underlying sink.
    ///
    /// [`SinkWriter`]: tokio_util::io::SinkWriter
    pub struct SinkWriter<S: ?Sized> {
        buffer: Bytes,
        #[pin]
        sink: S,
    }
}

impl<S> SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
{
    pub const fn new(sink: S) -> Self
    where
        S: Sized,
    {
        Self {
            sink,
            buffer: Bytes::new(),
        }
    }

    pub fn poll_flush_buffer(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        let mut project = self.as_mut().project();
        while !project.buffer.is_empty() {
            ready!(project.sink.as_mut().poll_ready(cx)?);
            let bytes = mem::take(project.buffer);
            project.sink.as_mut().start_send(bytes)?;
        }
        Poll::Ready(Ok(()))
    }

    pub async fn flush_buffer(&mut self) -> Result<(), S::Error>
    where
        S: Unpin,
    {
        poll_fn(|cx| Pin::new(&mut *self).poll_flush_buffer(cx)).await
    }

    pub fn poll_flush_inner(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), S::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        self.project().sink.poll_flush(cx)
    }

    pub async fn flush_inner(&mut self) -> Result<(), S::Error>
    where
        S: Unpin,
    {
        poll_fn(|cx| Pin::new(&mut *self).poll_flush_inner(cx)).await
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub fn into_inner(self) -> S
    where
        S: Sized,
    {
        self.sink
    }

    pub fn map_sink<S1>(self, f: impl FnOnce(S) -> S1) -> SinkWriter<S1>
    where
        S: Sized,
    {
        SinkWriter {
            buffer: self.buffer,
            sink: f(self.sink),
        }
    }
}

impl<S> Sink<Bytes> for SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
{
    type Error = S::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_flush_buffer(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        debug_assert!(
            project.buffer.is_empty(),
            "poll_ready must be called before start_send"
        );
        *project.buffer = item;
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        self.project().sink.poll_close(cx)
    }
}

impl<S> AsyncWrite for SinkWriter<S>
where
    S: Sink<Bytes> + ?Sized,
    io::Error: From<S::Error>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let project = self.as_mut().project();

        // optimize: try to write into the internal buffer without flushing
        if project.buffer.len() + buf.len() < 8 * 1024 {
            match mem::take(project.buffer).try_into_mut() {
                Ok(mut bytes_mut) => {
                    bytes_mut.put(buf);
                    *project.buffer = bytes_mut.freeze();
                    return Poll::Ready(Ok(buf.len()));
                }
                Err(bytes) => {
                    *project.buffer = bytes;
                }
            }
        }
        ready!(self.as_mut().poll_flush_buffer(cx)?);
        *self.project().buffer = Bytes::copy_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(self, cx).map_err(io::Error::from)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_close(self, cx).map_err(io::Error::from)
    }
}

impl<S: CancelStream + ?Sized> CancelStream for SinkWriter<S> {
    fn poll_cancel(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        self.project().sink.poll_cancel(cx, code)
    }
}

impl<S: GetStreamId + ?Sized> GetStreamId for SinkWriter<S> {
    fn poll_stream_id(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        self.project().sink.poll_stream_id(cx)
    }
}

pin_project_lite::pin_project! {
    /// A sink wrapper that guarantees once `poll_ready` returns `Ready`, the item will not be lost.
    pub struct Feed<S, T> {
        item: Option<T>,
        #[pin]
        sink: S,
    }
}

impl<S, T> Feed<S, T>
where
    S: Sink<T>,
{
    pub const fn new(sink: S) -> Self {
        Self { sink, item: None }
    }

    pub async fn ready(mut self: Pin<&mut Self>) -> Result<(), S::Error> {
        poll_fn(|cx| self.as_mut().poll_ready(cx)).await
    }

    pub async fn send_all(
        mut self: Pin<&mut Self>,
        items: impl Stream<Item = T>,
    ) -> Result<(), S::Error> {
        tokio::pin!(items);
        loop {
            self.as_mut().ready().await?;
            match items.next().await {
                Some(item) => self.as_mut().start_send(item)?,
                None => break,
            }
        }
        Ok(())
    }
}

impl<S, T> Sink<T> for Feed<S, T>
where
    S: Sink<T>,
{
    type Error = S::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.as_mut().project();
        while project.item.is_some() {
            ready!(project.sink.as_mut().poll_ready(cx)?);
            let item = project.item.take().expect("item is Some");
            project.sink.as_mut().start_send(item)?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        let project = self.project();
        assert!(
            project.item.is_none(),
            "start_send called before poll_ready"
        );
        *project.item = Some(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx)?);
        self.project().sink.poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_ready(cx)?);
        self.project().sink.poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{
        Sink, SinkExt,
        stream::{self, pending},
        task::noop_waker,
    };
    use tokio::io::{AsyncWriteExt, Error as IoError};

    use super::{Feed, SinkWriter};
    use crate::{
        quic::{CancelStream, GetStreamId, StreamError},
        varint::VarInt,
    };

    #[derive(Debug, Clone, Copy, Eq, PartialEq)]
    struct TestError(&'static str);

    impl fmt::Display for TestError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for TestError {}

    impl From<TestError> for IoError {
        fn from(error: TestError) -> Self {
            Self::other(error)
        }
    }

    #[test]
    fn test_error_display_and_io_conversion_are_stable() {
        assert_eq!(TestError("not ready").to_string(), "not ready");

        let error = IoError::from(TestError("io bridge"));

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.to_string(), "io bridge");
    }

    #[derive(Default)]
    struct RecordingSink {
        items: Vec<Bytes>,
        ready_pending: usize,
        ready_error: Option<TestError>,
        flushes: usize,
        closes: usize,
        cancel_codes: Vec<VarInt>,
        stream_id: Option<VarInt>,
    }

    impl Sink<Bytes> for RecordingSink {
        type Error = TestError;

        fn poll_ready(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if let Some(error) = self.ready_error.take() {
                return Poll::Ready(Err(error));
            }
            if self.ready_pending > 0 {
                self.ready_pending -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.items.push(item);
            Ok(())
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.closes += 1;
            Poll::Ready(Ok(()))
        }
    }

    impl CancelStream for RecordingSink {
        fn poll_cancel(
            mut self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), StreamError>> {
            self.cancel_codes.push(code);
            Poll::Ready(Ok(()))
        }
    }

    impl GetStreamId for RecordingSink {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, StreamError>> {
            Poll::Ready(Ok(self.stream_id.expect("stream id is configured")))
        }
    }

    #[tokio::test]
    async fn async_write_buffers_small_writes_until_flush() {
        let mut writer = SinkWriter::new(RecordingSink::default());

        writer.write_all(b"hello ").await.expect("write succeeds");
        writer.write_all(b"world").await.expect("write succeeds");
        assert!(writer.sink().items.is_empty());

        AsyncWriteExt::flush(&mut writer)
            .await
            .expect("flush succeeds");

        assert_eq!(
            writer.sink().items,
            vec![Bytes::from_static(b"hello world")]
        );
        assert_eq!(writer.sink().flushes, 1);
    }

    #[tokio::test]
    async fn async_write_flushes_existing_buffer_before_buffering_large_write() {
        let mut writer = SinkWriter::new(RecordingSink::default());
        let large = vec![b'x'; 8 * 1024];

        writer.write_all(b"small").await.expect("write succeeds");
        writer.write_all(&large).await.expect("write succeeds");

        assert_eq!(writer.sink().items, vec![Bytes::from_static(b"small")]);

        AsyncWriteExt::flush(&mut writer)
            .await
            .expect("flush succeeds");

        assert_eq!(
            writer.sink().items,
            vec![Bytes::from_static(b"small"), Bytes::from(large)]
        );
        assert_eq!(writer.sink().flushes, 1);
    }

    #[tokio::test]
    async fn async_write_shutdown_flushes_buffer_and_closes_inner_sink() {
        let mut writer = SinkWriter::new(RecordingSink::default());

        writer.write_all(b"body").await.expect("write succeeds");
        writer.shutdown().await.expect("shutdown succeeds");

        assert_eq!(writer.sink().items, vec![Bytes::from_static(b"body")]);
        assert_eq!(writer.sink().closes, 1);
    }

    #[tokio::test]
    async fn sink_accessors_map_sink_and_into_inner_preserve_buffer_and_inner_state() {
        let mut writer = SinkWriter::new(RecordingSink::default());
        writer.sink_mut().flushes = 7;
        writer.write_all(b"buffered").await.expect("write succeeds");

        let mut writer = writer.map_sink(|mut sink| {
            sink.stream_id = Some(VarInt::from_u32(9));
            sink
        });
        writer.flush_buffer().await.expect("flush succeeds");
        let inner = writer.into_inner();

        assert_eq!(inner.items, vec![Bytes::from_static(b"buffered")]);
        assert_eq!(inner.flushes, 7);
        assert_eq!(inner.stream_id, Some(VarInt::from_u32(9)));
    }

    #[test]
    fn cancel_stream_and_get_stream_id_forward_to_inner_sink() {
        let mut writer = SinkWriter::new(RecordingSink {
            stream_id: Some(VarInt::from_u32(33)),
            ..RecordingSink::default()
        });
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let cancel_code = VarInt::from_u32(44);
        assert!(matches!(
            Pin::new(&mut writer).poll_cancel(&mut cx, cancel_code),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(writer.sink().cancel_codes, vec![cancel_code]);
        assert!(matches!(
            Pin::new(&mut writer).poll_stream_id(&mut cx),
            Poll::Ready(Ok(id)) if id == VarInt::from_u32(33)
        ));
    }

    #[tokio::test]
    async fn feed_ready_sends_queued_item_after_pending_inner_readiness() {
        let mut feed = Feed::new(RecordingSink {
            ready_pending: 1,
            ..RecordingSink::default()
        });

        Pin::new(&mut feed)
            .start_send(Bytes::from_static(b"queued"))
            .expect("queue item");
        Pin::new(&mut feed).ready().await.expect("ready succeeds");

        assert_eq!(feed.sink.items, vec![Bytes::from_static(b"queued")]);
    }

    #[tokio::test]
    async fn feed_send_all_sends_each_stream_item_and_poll_close_closes_inner_sink() {
        let mut feed = Feed::new(RecordingSink::default());

        Pin::new(&mut feed)
            .send_all(stream::iter([
                Bytes::from_static(b"one"),
                Bytes::from_static(b"two"),
            ]))
            .await
            .expect("send all succeeds");
        assert_eq!(
            feed.sink.items,
            vec![Bytes::from_static(b"one"), Bytes::from_static(b"two")]
        );

        Pin::new(&mut feed)
            .start_send(Bytes::from_static(b"closing"))
            .expect("queue close item");
        Pin::new(&mut feed).close().await.expect("close succeeds");

        assert_eq!(
            feed.sink.items,
            vec![
                Bytes::from_static(b"one"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"closing")
            ]
        );
        assert_eq!(feed.sink.closes, 1);
    }

    #[test]
    #[should_panic(expected = "start_send called before poll_ready")]
    fn feed_start_send_panics_when_previous_item_has_not_been_flushed() {
        let mut feed = Feed::new(RecordingSink::default());

        Pin::new(&mut feed)
            .start_send(Bytes::from_static(b"first"))
            .expect("queue first item");
        Pin::new(&mut feed)
            .start_send(Bytes::from_static(b"second"))
            .expect("second item panics first");
    }

    #[test]
    fn feed_poll_ready_preserves_item_on_pending_and_error() {
        let mut pending_feed = Feed::new(RecordingSink {
            ready_pending: 1,
            ..RecordingSink::default()
        });
        Pin::new(&mut pending_feed)
            .start_send(Bytes::from_static(b"pending"))
            .expect("queue pending item");
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut pending_feed).poll_ready(&mut cx),
            Poll::Pending
        ));
        assert!(pending_feed.item.is_some());
        assert!(matches!(
            Pin::new(&mut pending_feed).poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            pending_feed.sink.items,
            vec![Bytes::from_static(b"pending")]
        );

        let mut error_feed = Feed::new(RecordingSink {
            ready_error: Some(TestError("not ready")),
            ..RecordingSink::default()
        });
        Pin::new(&mut error_feed)
            .start_send(Bytes::from_static(b"error"))
            .expect("queue error item");

        assert_eq!(
            Pin::new(&mut error_feed).poll_ready(&mut cx),
            Poll::Ready(Err(TestError("not ready")))
        );
        assert!(error_feed.item.is_some());
        assert!(error_feed.sink.items.is_empty());
    }

    #[tokio::test]
    async fn feed_send_all_waits_for_stream_item_after_becoming_ready() {
        let mut feed = Feed::<_, Bytes>::new(RecordingSink::default());
        let mut send_all = Box::pin(Pin::new(&mut feed).send_all(pending()));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(send_all.as_mut().poll(&mut cx), Poll::Pending));
        drop(send_all);

        assert!(feed.sink.items.is_empty());
    }
}
