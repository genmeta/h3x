use std::{
    mem,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream};
use tracing::Instrument;

use crate::{
    error::Code,
    quic::{self, BoxQuicStreamReader, BoxQuicStreamWriter, ResetStreamExt, StopStreamExt},
    varint::VarInt,
};

fn stream_used_after_taken() -> ! {
    panic!("guarded QUIC stream used after being taken, this is a bug")
}

fn reader_closed_before_stream_id_observed() -> ! {
    panic!("guarded QUIC reader closed before stream id was observed, this is a bug")
}

fn writer_closed_before_stream_id_observed() -> ! {
    panic!("guarded QUIC writer closed before stream id was observed, this is a bug")
}

fn writer_used_after_closed() -> ! {
    panic!("guarded QUIC writer used after send side closed, this is a bug")
}

#[derive(Debug, Clone)]
pub(super) enum QuicWriterStateSnapshot {
    Open,
    Closed,
    Reset { code: VarInt },
    ConnectionClosed { source: quic::ConnectionError },
    Taken,
}

enum QuicReaderState {
    Open { stream: BoxQuicStreamReader },
    Closed,
    Reset { code: VarInt },
    ConnectionClosed { source: quic::ConnectionError },
    Taken,
}

impl QuicReaderState {
    fn open(stream: BoxQuicStreamReader) -> Self {
        Self::Open { stream }
    }

    fn take(&mut self) -> Self {
        mem::replace(self, Self::Taken)
    }
}

enum QuicWriterState {
    Open { stream: BoxQuicStreamWriter },
    Closed,
    Reset { code: VarInt },
    ConnectionClosed { source: quic::ConnectionError },
    Taken,
}

impl QuicWriterState {
    fn open(stream: BoxQuicStreamWriter) -> Self {
        Self::Open { stream }
    }

    fn take(&mut self) -> Self {
        mem::replace(self, Self::Taken)
    }

    fn snapshot(&self) -> QuicWriterStateSnapshot {
        match self {
            Self::Open { .. } => QuicWriterStateSnapshot::Open,
            Self::Closed => QuicWriterStateSnapshot::Closed,
            Self::Reset { code } => QuicWriterStateSnapshot::Reset { code: *code },
            Self::ConnectionClosed { source } => QuicWriterStateSnapshot::ConnectionClosed {
                source: source.clone(),
            },
            Self::Taken => QuicWriterStateSnapshot::Taken,
        }
    }
}

// ---------------------------------------------------------------------------
// GuardedQuicReader
// ---------------------------------------------------------------------------

/// A QUIC read stream wrapper that automatically stops the stream on drop
/// while the receive side is still open.
pub struct GuardedQuicReader {
    stream_id: Option<VarInt>,
    state: QuicReaderState,
}

impl GuardedQuicReader {
    pub fn new(inner: BoxQuicStreamReader) -> Self {
        Self {
            stream_id: None,
            state: QuicReaderState::open(inner),
        }
    }

    pub(super) fn set_stream_id(&mut self, stream_id: VarInt) {
        self.stream_id = Some(stream_id);
    }

    /// Take the stream lifecycle state, leaving this guard unusable.
    pub fn take(&mut self) -> Self {
        Self {
            stream_id: self.stream_id,
            state: self.state.take(),
        }
    }

    /// Consume this guard and return the protected stream without running drop cleanup.
    pub(super) fn into_inner(mut self) -> BoxQuicStreamReader {
        match self.state.take() {
            QuicReaderState::Open { stream } => stream,
            QuicReaderState::Closed => {
                panic!("closed guarded QUIC reader cannot be taken as an open stream")
            }
            QuicReaderState::Reset { .. } | QuicReaderState::ConnectionClosed { .. } => {
                panic!("failed guarded QUIC reader cannot be taken as an open stream")
            }
            QuicReaderState::Taken => stream_used_after_taken(),
        }
    }

    pub(super) fn mark_reset(&mut self, code: VarInt) {
        self.state = QuicReaderState::Reset { code };
    }

    pub(super) fn mark_connection_closed(&mut self, source: quic::ConnectionError) {
        self.state = QuicReaderState::ConnectionClosed { source };
    }

    fn mark_quic_error(&mut self, error: &quic::StreamError) {
        match error {
            quic::StreamError::Connection { source } => {
                self.mark_connection_closed(source.clone());
            }
            quic::StreamError::Reset { code } => {
                self.mark_reset(*code);
            }
        }
    }
}

impl Stream for GuardedQuicReader {
    type Item = Result<Bytes, quic::StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicReaderState::Open { stream } => stream.as_mut().poll_next(cx),
            QuicReaderState::Closed => return Poll::Ready(None),
            QuicReaderState::Reset { code } => {
                return Poll::Ready(Some(Err(quic::StreamError::Reset { code: *code })));
            }
            QuicReaderState::ConnectionClosed { source } => {
                return Poll::Ready(Some(Err(quic::StreamError::Connection {
                    source: source.clone(),
                })));
            }
            QuicReaderState::Taken => stream_used_after_taken(),
        };
        match result {
            Poll::Ready(None) => {
                this.state = QuicReaderState::Closed;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                this.mark_quic_error(&error);
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }
}

impl quic::StopStream for GuardedQuicReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicReaderState::Open { stream } => stream.as_mut().poll_stop(cx, code),
            QuicReaderState::Closed => return Poll::Ready(Ok(())),
            QuicReaderState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicReaderState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicReaderState::Taken => stream_used_after_taken(),
        };
        if let Poll::Ready(Err(error)) = result {
            this.mark_quic_error(&error);
            return Poll::Ready(Err(error));
        }
        result
    }
}

impl quic::GetStreamId for GuardedQuicReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicReaderState::Open { stream } => {
                if let Some(stream_id) = this.stream_id {
                    return Poll::Ready(Ok(stream_id));
                }
                stream.as_mut().poll_stream_id(cx)
            }
            QuicReaderState::Closed => match this.stream_id {
                Some(stream_id) => return Poll::Ready(Ok(stream_id)),
                None => reader_closed_before_stream_id_observed(),
            },
            QuicReaderState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicReaderState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicReaderState::Taken => stream_used_after_taken(),
        };
        match result {
            Poll::Ready(Ok(stream_id)) => Poll::Ready(Ok(stream_id)),
            Poll::Ready(Err(error)) => {
                this.mark_quic_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for GuardedQuicReader {
    fn drop(&mut self) {
        if let QuicReaderState::Open { mut stream } = self.state.take() {
            // Inherent termination: the task owns the only remaining stream
            // handle and exits once the committed STOP_SENDING operation
            // resolves or the underlying stream reports failure.
            tokio::spawn(
                async move {
                    _ = stream.stop(Code::H3_NO_ERROR.into()).await;
                }
                .in_current_span(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// GuardedQuicWriter
// ---------------------------------------------------------------------------

/// A QUIC write stream wrapper that automatically resets the stream on drop
/// while the send side is still open.
pub struct GuardedQuicWriter {
    state: QuicWriterState,
}

impl GuardedQuicWriter {
    pub fn new(inner: BoxQuicStreamWriter) -> Self {
        Self {
            state: QuicWriterState::open(inner),
        }
    }

    pub(super) fn state_snapshot(&self) -> QuicWriterStateSnapshot {
        self.state.snapshot()
    }

    pub(super) fn mark_reset(&mut self, code: VarInt) {
        self.state = QuicWriterState::Reset { code };
    }

    pub(super) fn mark_connection_closed(&mut self, source: quic::ConnectionError) {
        self.state = QuicWriterState::ConnectionClosed { source };
    }

    fn mark_quic_error(&mut self, error: &quic::StreamError) {
        match error {
            quic::StreamError::Connection { source } => {
                self.mark_connection_closed(source.clone());
            }
            quic::StreamError::Reset { code } => {
                self.mark_reset(*code);
            }
        }
    }

    /// Take the stream lifecycle state, leaving this guard unusable.
    pub fn take(&mut self) -> Self {
        Self {
            state: self.state.take(),
        }
    }
}

impl Sink<Bytes> for GuardedQuicWriter {
    type Error = quic::StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().poll_ready(cx),
            QuicWriterState::Closed => writer_used_after_closed(),
            QuicWriterState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        if let Poll::Ready(Err(error)) = result {
            this.mark_quic_error(&error);
            return Poll::Ready(Err(error));
        }
        result
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().start_send(item),
            QuicWriterState::Closed => writer_used_after_closed(),
            QuicWriterState::Reset { code } => {
                return Err(quic::StreamError::Reset { code: *code });
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Err(quic::StreamError::Connection {
                    source: source.clone(),
                });
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        if let Err(error) = &result {
            this.mark_quic_error(error);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().poll_flush(cx),
            QuicWriterState::Closed => writer_used_after_closed(),
            QuicWriterState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        if let Poll::Ready(Err(error)) = result {
            this.mark_quic_error(&error);
            return Poll::Ready(Err(error));
        }
        result
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().poll_close(cx),
            QuicWriterState::Closed => writer_used_after_closed(),
            QuicWriterState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        match result {
            Poll::Ready(Ok(())) => {
                this.state = QuicWriterState::Closed;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.mark_quic_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl quic::ResetStream for GuardedQuicWriter {
    fn poll_reset(
        self: Pin<&mut Self>,
        cx: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().poll_reset(cx, code),
            QuicWriterState::Closed => writer_used_after_closed(),
            QuicWriterState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        match result {
            Poll::Ready(Ok(())) => {
                this.state = QuicWriterState::Reset { code };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                this.mark_quic_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl quic::GetStreamId for GuardedQuicWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        let this = self.get_mut();
        let result = match &mut this.state {
            QuicWriterState::Open { stream } => stream.as_mut().poll_stream_id(cx),
            QuicWriterState::Closed => writer_closed_before_stream_id_observed(),
            QuicWriterState::Reset { code } => {
                return Poll::Ready(Err(quic::StreamError::Reset { code: *code }));
            }
            QuicWriterState::ConnectionClosed { source } => {
                return Poll::Ready(Err(quic::StreamError::Connection {
                    source: source.clone(),
                }));
            }
            QuicWriterState::Taken => stream_used_after_taken(),
        };
        match result {
            Poll::Ready(Ok(stream_id)) => Poll::Ready(Ok(stream_id)),
            Poll::Ready(Err(error)) => {
                this.mark_quic_error(&error);
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for GuardedQuicWriter {
    fn drop(&mut self) {
        if let QuicWriterState::Open { mut stream } = self.state.take() {
            // Inherent termination: the task owns the only remaining stream
            // handle and exits once the committed RESET_STREAM operation
            // resolves or the underlying stream reports failure.
            tokio::spawn(
                async move {
                    _ = stream.reset(Code::H3_NO_ERROR.into()).await;
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
            "guarded QUIC stream used after being taken, this is a bug",
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

    struct DropNotifyingReader {
        stream_id: VarInt,
        next_results: VecDeque<Option<Result<Bytes, quic::StreamError>>>,
        stop_tx: mpsc::UnboundedSender<VarInt>,
        drop_tx: Option<mpsc::UnboundedSender<()>>,
    }

    impl Stream for DropNotifyingReader {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.get_mut().next_results.pop_front().unwrap_or(None))
        }
    }

    impl quic::StopStream for DropNotifyingReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.get_mut()
                .stop_tx
                .send(code)
                .expect("reader stop receiver should still be alive");
            Poll::Ready(Ok(()))
        }
    }

    impl quic::GetStreamId for DropNotifyingReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl Drop for DropNotifyingReader {
        fn drop(&mut self) {
            if let Some(drop_tx) = self.drop_tx.take() {
                _ = drop_tx.send(());
            }
        }
    }

    struct DropNotifyingWriter {
        stream_id: VarInt,
        close_results: VecDeque<Result<(), quic::StreamError>>,
        reset_results: VecDeque<Result<(), quic::StreamError>>,
        reset_tx: mpsc::UnboundedSender<VarInt>,
        drop_tx: Option<mpsc::UnboundedSender<()>>,
    }

    impl Sink<Bytes> for DropNotifyingWriter {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Bytes) -> Result<(), Self::Error> {
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
            Poll::Ready(self.get_mut().close_results.pop_front().unwrap_or(Ok(())))
        }
    }

    impl quic::ResetStream for DropNotifyingWriter {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            let this = self.get_mut();
            this.reset_tx
                .send(code)
                .expect("writer reset receiver should still be alive");
            Poll::Ready(this.reset_results.pop_front().unwrap_or(Ok(())))
        }
    }

    impl quic::GetStreamId for DropNotifyingWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.get_mut().stream_id))
        }
    }

    impl Drop for DropNotifyingWriter {
        fn drop(&mut self) {
            if let Some(drop_tx) = self.drop_tx.take() {
                _ = drop_tx.send(());
            }
        }
    }

    #[tokio::test]
    async fn reader_take_moves_inner_stream_and_panics_on_original_use() {
        let (mut guard, stop_rx) = reader_guard(7, [], [Ok(())]);
        guard.set_stream_id(VarInt::from_u32(7));
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
    async fn reader_eof_releases_inner_stream_immediately() {
        let (stop_tx, _stop_rx) = mpsc::unbounded_channel();
        let (drop_tx, mut drop_rx) = mpsc::unbounded_channel();
        let mut guard = GuardedQuicReader::new(Box::pin(DropNotifyingReader {
            stream_id: VarInt::from_u32(111),
            next_results: [None].into_iter().collect(),
            stop_tx,
            drop_tx: Some(drop_tx),
        }));

        assert!(guard.next().await.is_none());

        timeout(Duration::from_secs(1), drop_rx.recv())
            .await
            .expect("inner reader should be released on EOF")
            .expect("inner reader drop should be observed");
    }

    #[tokio::test]
    async fn reader_stop_ok_keeps_receive_side_open_for_drop_cleanup() {
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
        assert_eq!(
            timeout(Duration::from_secs(1), stop_rx.recv())
                .await
                .expect("drop cleanup should stop the still-open receive side")
                .expect("drop stop code should be present"),
            VarInt::from(Code::H3_NO_ERROR),
        );
    }

    #[tokio::test]
    async fn reader_stop_error_transitions_to_reset_and_skips_drop_cleanup() {
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
        assert_no_code(stop_rx).await;
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
    async fn writer_close_releases_inner_stream_immediately() {
        let (reset_tx, _reset_rx) = mpsc::unbounded_channel();
        let (drop_tx, mut drop_rx) = mpsc::unbounded_channel();
        let mut guard = GuardedQuicWriter::new(Box::pin(DropNotifyingWriter {
            stream_id: VarInt::from_u32(121),
            close_results: [Ok(())].into_iter().collect(),
            reset_results: [].into_iter().collect(),
            reset_tx,
            drop_tx: Some(drop_tx),
        }));

        guard.close().await.expect("close should succeed");

        timeout(Duration::from_secs(1), drop_rx.recv())
            .await
            .expect("inner writer should be released on close")
            .expect("inner writer drop should be observed");
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
    async fn writer_reset_releases_inner_stream_immediately() {
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel();
        let (drop_tx, mut drop_rx) = mpsc::unbounded_channel();
        let mut guard = GuardedQuicWriter::new(Box::pin(DropNotifyingWriter {
            stream_id: VarInt::from_u32(122),
            close_results: [].into_iter().collect(),
            reset_results: [Ok(())].into_iter().collect(),
            reset_tx,
            drop_tx: Some(drop_tx),
        }));

        poll_fn(|cx| Pin::new(&mut guard).poll_reset(cx, VarInt::from_u32(77)))
            .await
            .expect("reset should succeed");
        assert_eq!(
            timeout(Duration::from_secs(1), reset_rx.recv())
                .await
                .expect("reset call should notify")
                .expect("reset code should be present"),
            VarInt::from_u32(77),
        );
        timeout(Duration::from_secs(1), drop_rx.recv())
            .await
            .expect("inner writer should be released on reset")
            .expect("inner writer drop should be observed");
    }

    #[tokio::test]
    async fn writer_close_error_transitions_to_reset_and_skips_drop_cleanup() {
        let (mut guard, _, reset_rx) = writer_guard(23, [Err(stream_error(77))], [Ok(())]);

        let error = guard.close().await.expect_err("close should fail");
        assert!(matches!(
            error,
            quic::StreamError::Reset { code } if code == VarInt::from_u32(77)
        ));

        drop(guard);
        assert_no_code(reset_rx).await;
    }
}
