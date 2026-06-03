use std::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream};
use tracing::Instrument;

use crate::{
    codec::{BoxReadStream, BoxWriteStream},
    error::Code,
    quic::{self, ResetStreamExt, StopStreamExt},
    varint::VarInt,
};

// ---------------------------------------------------------------------------
// Sentinel — panics if the stream is used after take / drop
// ---------------------------------------------------------------------------

struct DroppedStream;

fn stream_used_after_dropped() -> ! {
    panic!("guarded QUIC stream used after being taken or dropped, this is a bug")
}

impl Stream for DroppedStream {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        stream_used_after_dropped()
    }
}

impl Sink<Bytes> for DroppedStream {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn start_send(self: Pin<&mut Self>, _: Bytes) -> Result<(), Self::Error> {
        stream_used_after_dropped()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        stream_used_after_dropped()
    }
}

impl quic::ResetStream for DroppedStream {
    fn poll_reset(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::StopStream for DroppedStream {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        stream_used_after_dropped()
    }
}

impl quic::GetStreamId for DroppedStream {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        stream_used_after_dropped()
    }
}

fn dropped_reader() -> BoxReadStream {
    Box::pin(DroppedStream)
}

fn dropped_writer() -> BoxWriteStream {
    Box::pin(DroppedStream)
}

// ---------------------------------------------------------------------------
// GuardedQuicReader
// ---------------------------------------------------------------------------

/// A QUIC read stream wrapper that automatically stops the stream on drop
/// if it hasn't been fully consumed (EOF) or explicitly stopped.
pub struct GuardedQuicReader {
    inner: BoxReadStream,
    completed: bool,
}

impl GuardedQuicReader {
    pub fn new(inner: BoxReadStream) -> Self {
        Self {
            inner,
            completed: false,
        }
    }

    /// Take the inner stream, replacing it with a sentinel.
    /// Marks this guard as completed (no cleanup on drop).
    pub fn take(&mut self) -> Self {
        let inner = mem::replace(&mut self.inner, dropped_reader());
        let completed = self.completed;
        self.completed = true;
        Self { inner, completed }
    }
}

impl Stream for GuardedQuicReader {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(None) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::StopStream for GuardedQuicReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_stop(cx, code);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::GetStreamId for GuardedQuicReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.get_mut().inner.as_mut().poll_stream_id(cx)
    }
}

impl Drop for GuardedQuicReader {
    fn drop(&mut self) {
        if !self.completed {
            let mut inner = mem::replace(&mut self.inner, dropped_reader());
            tokio::spawn(
                async move {
                    _ = inner.stop(Code::H3_NO_ERROR.into()).await;
                }
                .in_current_span(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// GuardedQuicWriter
// ---------------------------------------------------------------------------

/// A QUIC write stream wrapper that automatically resets the stream on drop if
/// it hasn't been properly closed or explicitly reset.
pub struct GuardedQuicWriter {
    inner: BoxWriteStream,
    completed: bool,
}

impl GuardedQuicWriter {
    pub fn new(inner: BoxWriteStream) -> Self {
        Self {
            inner,
            completed: false,
        }
    }

    /// Take the inner stream, replacing it with a sentinel.
    /// Marks this guard as completed (no cleanup on drop).
    pub fn take(&mut self) -> Self {
        let inner = mem::replace(&mut self.inner, dropped_writer());
        let completed = self.completed;
        self.completed = true;
        Self { inner, completed }
    }
}

impl Sink<Bytes> for GuardedQuicWriter {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.as_mut().poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.get_mut().inner.as_mut().start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut().inner.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_close(cx);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::ResetStream for GuardedQuicWriter {
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_reset(cx, code);
        if let Poll::Ready(Ok(())) = &result {
            this.completed = true;
        }
        result
    }
}

impl quic::GetStreamId for GuardedQuicWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        self.get_mut().inner.as_mut().poll_stream_id(cx)
    }
}

impl Drop for GuardedQuicWriter {
    fn drop(&mut self) {
        if !self.completed {
            let mut inner = mem::replace(&mut self.inner, dropped_writer());
            tokio::spawn(
                async move {
                    _ = inner.reset(Code::H3_NO_ERROR.into()).await;
                }
                .in_current_span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        panic::{AssertUnwindSafe, catch_unwind},
        sync::{Arc, Mutex},
    };

    use futures::{SinkExt, StreamExt, future::poll_fn, task::noop_waker_ref};
    use tokio::{
        sync::mpsc,
        time::{Duration, timeout},
    };

    use super::*;
    use crate::quic::{GetStreamId, GetStreamIdExt, ResetStream, StopStream};

    fn stream_error(code: u32) -> quic::StreamError {
        quic::StreamError::Reset {
            code: VarInt::from_u32(code),
        }
    }

    fn no_op_cx() -> Context<'static> {
        Context::from_waker(noop_waker_ref())
    }

    fn assert_guard_panic(action: impl FnOnce()) {
        let panic = catch_unwind(AssertUnwindSafe(action))
            .expect_err("guard should panic after take or drop");
        let message = if let Some(message) = panic.downcast_ref::<&str>() {
            *message
        } else if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else {
            panic!("panic payload should be a string");
        };
        assert_eq!(
            message,
            "guarded QUIC stream used after being taken or dropped, this is a bug",
        );
    }

    async fn assert_no_code(mut rx: mpsc::UnboundedReceiver<VarInt>) {
        match timeout(Duration::from_millis(50), rx.recv()).await {
            Err(_) | Ok(None) => {}
            Ok(Some(code)) => panic!("unexpected stop/reset notification received: {code}"),
        }
    }

    type ReadPollResult = Option<Result<Bytes, quic::StreamError>>;
    type ReadPollQueue = Arc<Mutex<VecDeque<ReadPollResult>>>;
    type StopResultQueue = Arc<Mutex<VecDeque<Result<(), quic::StreamError>>>>;
    type SentItems = Arc<Mutex<Vec<Bytes>>>;

    #[derive(Clone)]
    struct ReaderState {
        stream_id: VarInt,
        next_results: ReadPollQueue,
        stop_results: StopResultQueue,
    }

    struct TestReader {
        state: ReaderState,
        stop_tx: mpsc::UnboundedSender<VarInt>,
    }

    impl Stream for TestReader {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let next = self
                .state
                .next_results
                .lock()
                .expect("reader next queue lock should not be poisoned")
                .pop_front()
                .unwrap_or(None);
            Poll::Ready(next)
        }
    }

    impl quic::StopStream for TestReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.stop_tx
                .send(code)
                .expect("reader stop receiver should still be alive");
            let result = self
                .state
                .stop_results
                .lock()
                .expect("reader stop queue lock should not be poisoned")
                .pop_front()
                .unwrap_or(Ok(()));
            Poll::Ready(result)
        }
    }

    impl quic::GetStreamId for TestReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.state.stream_id))
        }
    }

    fn reader_guard(
        stream_id: u32,
        next_results: impl IntoIterator<Item = Option<Result<Bytes, quic::StreamError>>>,
        stop_results: impl IntoIterator<Item = Result<(), quic::StreamError>>,
    ) -> (GuardedQuicReader, mpsc::UnboundedReceiver<VarInt>) {
        let state = ReaderState {
            stream_id: VarInt::from_u32(stream_id),
            next_results: Arc::new(Mutex::new(next_results.into_iter().collect())),
            stop_results: Arc::new(Mutex::new(stop_results.into_iter().collect())),
        };
        let (stop_tx, stop_rx) = mpsc::unbounded_channel();
        (
            GuardedQuicReader::new(Box::pin(TestReader { state, stop_tx })),
            stop_rx,
        )
    }

    #[derive(Clone)]
    struct WriterState {
        stream_id: VarInt,
        sent_items: SentItems,
        close_results: StopResultQueue,
        reset_results: StopResultQueue,
    }

    struct TestWriter {
        state: WriterState,
        reset_tx: mpsc::UnboundedSender<VarInt>,
    }

    impl Sink<Bytes> for TestWriter {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .sent_items
                .lock()
                .expect("writer sent-items lock should not be poisoned")
                .push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let result = self
                .state
                .close_results
                .lock()
                .expect("writer close queue lock should not be poisoned")
                .pop_front()
                .unwrap_or(Ok(()));
            Poll::Ready(result)
        }
    }

    impl quic::ResetStream for TestWriter {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.reset_tx
                .send(code)
                .expect("writer reset receiver should still be alive");
            let result = self
                .state
                .reset_results
                .lock()
                .expect("writer reset queue lock should not be poisoned")
                .pop_front()
                .unwrap_or(Ok(()));
            Poll::Ready(result)
        }
    }

    impl quic::GetStreamId for TestWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.state.stream_id))
        }
    }

    fn writer_guard(
        stream_id: u32,
        close_results: impl IntoIterator<Item = Result<(), quic::StreamError>>,
        reset_results: impl IntoIterator<Item = Result<(), quic::StreamError>>,
    ) -> (
        GuardedQuicWriter,
        SentItems,
        mpsc::UnboundedReceiver<VarInt>,
    ) {
        let sent_items = Arc::new(Mutex::new(Vec::new()));
        let state = WriterState {
            stream_id: VarInt::from_u32(stream_id),
            sent_items: sent_items.clone(),
            close_results: Arc::new(Mutex::new(close_results.into_iter().collect())),
            reset_results: Arc::new(Mutex::new(reset_results.into_iter().collect())),
        };
        let (reset_tx, reset_rx) = mpsc::unbounded_channel();
        (
            GuardedQuicWriter::new(Box::pin(TestWriter { state, reset_tx })),
            sent_items,
            reset_rx,
        )
    }

    #[tokio::test]
    async fn reader_take_moves_inner_stream_and_panics_on_original_use() {
        let (mut guard, stop_rx) = reader_guard(7, [], [Ok(())]);
        let mut taken = GuardedQuicReader::take(&mut guard);

        assert_eq!(
            taken
                .stream_id()
                .await
                .expect("taken reader should expose stream id"),
            VarInt::from_u32(7),
        );

        let mut cx = no_op_cx();
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_next(&mut cx);
        });
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_stop(&mut cx, VarInt::from_u32(1));
        });
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_stream_id(&mut cx);
        });

        drop(guard);
        drop(taken);

        assert_eq!(
            timeout(Duration::from_secs(1), async move {
                let mut stop_rx = stop_rx;
                stop_rx.recv().await
            })
            .await
            .expect("reader drop cleanup should run")
            .expect("reader stop code should be sent"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn reader_eof_marks_completed_and_drop_skips_stop() {
        let (mut guard, stop_rx) = reader_guard(11, [None], []);

        assert!(guard.next().await.is_none());

        drop(guard);
        assert_no_code(stop_rx).await;
    }

    #[tokio::test]
    async fn reader_stop_ok_marks_completed_and_drop_skips_second_stop() {
        let (mut guard, mut stop_rx) = reader_guard(12, [], [Ok(())]);

        poll_fn(|cx| Pin::new(&mut guard).poll_stop(cx, VarInt::from_u32(33)))
            .await
            .expect("stop should succeed");
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("stop call should notify")
                .expect("stop code should be present"),
            VarInt::from_u32(33),
        );

        drop(guard);
        assert_no_code(stop_rx).await;
    }

    #[tokio::test]
    async fn reader_stop_error_keeps_guard_incomplete_for_drop_cleanup() {
        let (mut guard, mut stop_rx) = reader_guard(13, [], [Err(stream_error(44)), Ok(())]);

        let error = poll_fn(|cx| Pin::new(&mut guard).poll_stop(cx, VarInt::from_u32(55)))
            .await
            .expect_err("explicit stop should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(44)
        ));
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("failing stop should notify")
                .expect("stop code should be present"),
            VarInt::from_u32(55),
        );

        drop(guard);

        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("drop cleanup should retry stop")
                .expect("drop stop code should be present"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn writer_take_moves_inner_stream_and_panics_on_original_use() {
        let (mut guard, sent_items, reset_rx) = writer_guard(8, [], [Ok(())]);
        let mut taken = GuardedQuicWriter::take(&mut guard);

        assert_eq!(
            taken
                .stream_id()
                .await
                .expect("taken writer should expose stream id"),
            VarInt::from_u32(8),
        );
        taken
            .send(Bytes::from_static(b"hello"))
            .await
            .expect("taken writer should accept sends");
        assert_eq!(
            sent_items
                .lock()
                .expect("sent-items lock should not be poisoned")
                .as_slice(),
            &[Bytes::from_static(b"hello")],
        );

        let mut cx = no_op_cx();
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_ready(&mut cx);
        });
        assert_guard_panic(|| {
            Pin::new(&mut guard)
                .start_send(Bytes::from_static(b"panic"))
                .expect("start_send should panic before returning");
        });
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_flush(&mut cx);
        });
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_close(&mut cx);
        });
        assert_guard_panic(|| {
            let _ = Pin::new(&mut guard).poll_reset(&mut cx, VarInt::from_u32(2));
        });

        drop(guard);
        drop(taken);

        assert_eq!(
            timeout(Duration::from_secs(1), async move {
                let mut reset_rx = reset_rx;
                reset_rx.recv().await
            })
            .await
            .expect("writer drop cleanup should run")
            .expect("writer reset code should be sent"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn writer_close_ok_marks_completed_and_drop_skips_reset() {
        let (mut guard, _, reset_rx) = writer_guard(21, [Ok(())], []);

        guard.close().await.expect("close should succeed");

        drop(guard);
        assert_no_code(reset_rx).await;
    }

    #[tokio::test]
    async fn writer_reset_ok_marks_completed_and_drop_skips_second_reset() {
        let (mut guard, _, mut reset_rx) = writer_guard(22, [], [Ok(())]);

        poll_fn(|cx| Pin::new(&mut guard).poll_reset(cx, VarInt::from_u32(66)))
            .await
            .expect("reset should succeed");
        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("reset call should notify")
                .expect("reset code should be present"),
            VarInt::from_u32(66),
        );

        drop(guard);
        assert_no_code(reset_rx).await;
    }

    #[tokio::test]
    async fn writer_close_error_keeps_guard_incomplete_for_drop_cleanup() {
        let (mut guard, _, mut reset_rx) = writer_guard(23, [Err(stream_error(77))], [Ok(())]);

        let error = guard.close().await.expect_err("close should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(77)
        ));

        drop(guard);

        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("drop cleanup should reset")
                .expect("reset code should be present"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }
}
