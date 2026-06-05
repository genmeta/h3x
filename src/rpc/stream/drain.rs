use std::pin::Pin;

use futures::future::poll_fn;
use tracing::Instrument as _;

use super::{
    frame::{ReadCommand, ReadEvent, WriteCommand, WriteEvent},
    io::FrameIo,
    reader::ActiveBridgeStreamReader,
    writer::ActiveBridgeStreamWriter,
};
use crate::{quic, rpc::lifecycle::LifecycleExt};

pub(crate) trait DrainLifecycle: LifecycleExt + 'static {}

impl<T> DrainLifecycle for T where T: LifecycleExt + 'static {}

pub(crate) trait ReadDrainIo<E>:
    FrameIo<ReadCommand, ReadEvent, E> + Send + 'static
{
}

impl<T, E> ReadDrainIo<E> for T where T: FrameIo<ReadCommand, ReadEvent, E> + Send + 'static {}

pub(crate) trait WriteDrainIo<E>:
    FrameIo<WriteCommand, WriteEvent, E> + Send + 'static
{
}

impl<T, E> WriteDrainIo<E> for T where T: FrameIo<WriteCommand, WriteEvent, E> + Send + 'static {}

pub(super) fn spawn_read_drain<Io, L, E>(mut active: Pin<Box<ActiveBridgeStreamReader<Io, L, E>>>)
where
    L: DrainLifecycle,
    Io: ReadDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    // Inherent termination: this task owns a moved active bridge containing only
    // already committed outbound frames. It exits after those frames are written
    // or typed frame IO closes, and it never waits for operation acknowledgements.
    let _task = tokio::spawn(
        async move {
            poll_fn(|cx| active.as_mut().poll_drain(cx)).await;
        }
        .in_current_span(),
    );
}

pub(super) fn spawn_write_drain<Io, L, E>(mut active: Pin<Box<ActiveBridgeStreamWriter<Io, L, E>>>)
where
    L: DrainLifecycle,
    Io: WriteDrainIo<E>,
    E: 'static,
    quic::ConnectionError: From<E>,
{
    // Inherent termination: this task owns a moved active bridge containing only
    // already committed outbound frames. It exits after those frames are written
    // or typed frame IO closes, and it never waits for operation acknowledgements.
    let _task = tokio::spawn(
        async move {
            poll_fn(|cx| active.as_mut().poll_drain(cx)).await;
        }
        .in_current_span(),
    );
}

pub(super) fn log_drain_error(error: &quic::StreamError, context: &'static str) {
    let report = snafu::Report::from_error(error);
    tracing::warn!(error = %report, context, "stream frame drain failed");
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        fmt::Debug,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
        time::Duration,
    };

    use bytes::Bytes;
    use futures::{FutureExt as _, Sink, Stream, future::poll_fn};

    use crate::{
        quic::{ResetStream, StopStream},
        rpc::stream::{
            frame::{ReadCommand, ReadEvent, WriteCommand, WriteEvent},
            reader::BridgeStreamReader,
            test_io::{TestFrameIoError, TestLifecycle},
            writer::BridgeStreamWriter,
        },
        varint::VarInt,
    };

    struct ControlledFrameIo<Out, In, E> {
        state: Arc<Mutex<ControlledState<Out, In, E>>>,
    }

    struct ControlledFrameIoHandle<Out, In, E> {
        state: Arc<Mutex<ControlledState<Out, In, E>>>,
    }

    struct ControlledState<Out, In, E> {
        hold_flush: bool,
        buffered: Vec<Out>,
        sent: Vec<Out>,
        inbound: VecDeque<Result<In, E>>,
    }

    impl<Out, In, E> ControlledFrameIo<Out, In, E> {
        fn new() -> (Self, ControlledFrameIoHandle<Out, In, E>) {
            let state = Arc::new(Mutex::new(ControlledState {
                hold_flush: false,
                buffered: Vec::new(),
                sent: Vec::new(),
                inbound: VecDeque::new(),
            }));
            (
                Self {
                    state: state.clone(),
                },
                ControlledFrameIoHandle { state },
            )
        }
    }

    impl<Out, In, E> ControlledFrameIoHandle<Out, In, E> {
        fn hold_flush(&self, hold_flush: bool) {
            self.state.lock().unwrap().hold_flush = hold_flush;
        }

        fn push_inbound(&self, frame: In) {
            self.state.lock().unwrap().inbound.push_back(Ok(frame));
        }

        fn inbound_len(&self) -> usize {
            self.state.lock().unwrap().inbound.len()
        }
    }

    impl<Out, In, E> ControlledFrameIoHandle<Out, In, E>
    where
        Out: Clone,
    {
        fn sent(&self) -> Vec<Out> {
            self.state.lock().unwrap().sent.clone()
        }
    }

    impl<Out, In, E> Unpin for ControlledFrameIo<Out, In, E> {}

    impl<Out, In, E> Sink<Out> for ControlledFrameIo<Out, In, E> {
        type Error = E;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Out) -> Result<(), Self::Error> {
            self.state.lock().unwrap().buffered.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let mut state = self.state.lock().unwrap();
            if state.hold_flush {
                return Poll::Pending;
            }
            let buffered = std::mem::take(&mut state.buffered);
            state.sent.extend(buffered);
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.poll_flush(cx)
        }
    }

    impl<Out, In, E> Stream for ControlledFrameIo<Out, In, E> {
        type Item = Result<In, E>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.state.lock().unwrap().inbound.pop_front() {
                Some(frame) => Poll::Ready(Some(frame)),
                None => Poll::Pending,
            }
        }
    }

    type TestReaderIo = ControlledFrameIo<ReadCommand, ReadEvent, TestFrameIoError>;
    type TestReaderHandle = ControlledFrameIoHandle<ReadCommand, ReadEvent, TestFrameIoError>;
    type TestWriterIo = ControlledFrameIo<WriteCommand, WriteEvent, TestFrameIoError>;
    type TestWriterHandle = ControlledFrameIoHandle<WriteCommand, WriteEvent, TestFrameIoError>;

    fn reader(
        stream_id: VarInt,
    ) -> (
        BridgeStreamReader<TestReaderIo, TestLifecycle, TestFrameIoError>,
        TestReaderHandle,
    ) {
        let lifecycle = Arc::new(TestLifecycle::new());
        let (io, handle) = ControlledFrameIo::new();
        (BridgeStreamReader::new(stream_id, io, lifecycle), handle)
    }

    fn writer(
        stream_id: VarInt,
    ) -> (
        BridgeStreamWriter<TestWriterIo, TestLifecycle, TestFrameIoError>,
        TestWriterHandle,
    ) {
        let lifecycle = Arc::new(TestLifecycle::new());
        let (io, handle) = ControlledFrameIo::new();
        (BridgeStreamWriter::new(stream_id, io, lifecycle), handle)
    }

    async fn wait_sent<Out, In, E>(handle: &ControlledFrameIoHandle<Out, In, E>, expected: Vec<Out>)
    where
        Out: Clone + Debug + PartialEq,
    {
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if handle.sent() == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_elapsed| {
            panic!(
                "timed out waiting for sent frames {expected:?}; actual {:?}",
                handle.sent()
            )
        });
    }

    async fn assert_no_sent_after_yield<Out, In, E>(handle: &ControlledFrameIoHandle<Out, In, E>)
    where
        Out: Clone + Debug + PartialEq,
    {
        tokio::task::yield_now().await;
        assert_eq!(handle.sent(), []);
    }

    #[tokio::test]
    async fn dropping_reader_after_committed_stop_drains_only_that_stop() {
        let code = VarInt::from_u32(201);
        let (mut bridge, handle) = reader(VarInt::from_u32(202));
        handle.hold_flush(true);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_stop(cx, code))
                .now_or_never()
                .is_none(),
            "first stop poll should commit and wait for flush"
        );
        assert_eq!(handle.sent(), []);

        handle.hold_flush(false);
        drop(bridge);

        wait_sent(&handle, vec![ReadCommand::Stop { code }]).await;
    }

    #[tokio::test]
    async fn dropping_reader_with_no_committed_outbound_sends_no_frame() {
        let (bridge, handle) = reader(VarInt::from_u32(203));

        drop(bridge);

        assert_no_sent_after_yield(&handle).await;
    }

    #[tokio::test]
    async fn dropping_writer_after_committed_reset_drains_reset_without_ack() {
        let code = VarInt::from_u32(204);
        let (mut bridge, handle) = writer(VarInt::from_u32(205));
        handle.hold_flush(true);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_reset(cx, code))
                .now_or_never()
                .is_none(),
            "first reset poll should commit and wait for flush"
        );
        assert_eq!(handle.sent(), []);

        handle.hold_flush(false);
        drop(bridge);

        wait_sent(&handle, vec![WriteCommand::Reset { code }]).await;
    }

    #[tokio::test]
    async fn dropping_writer_with_only_cached_credit_sends_no_frame() {
        let (mut bridge, handle) = writer(VarInt::from_u32(206));
        handle.push_inbound(WriteEvent::Pull);

        poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
            .await
            .expect("cached credit should make writer ready");
        drop(bridge);

        assert_no_sent_after_yield(&handle).await;
    }

    #[tokio::test]
    async fn dropping_writer_with_pending_push_drains_push_without_synthesizing_eos() {
        let data = Bytes::from_static(b"drained push");
        let (mut bridge, handle) = writer(VarInt::from_u32(207));
        handle.push_inbound(WriteEvent::Pull);

        poll_fn(|cx| Pin::new(&mut bridge).poll_ready(cx))
            .await
            .expect("cached credit should make writer ready");
        Pin::new(&mut bridge)
            .start_send(data.clone())
            .expect("start_send should commit push");
        drop(bridge);

        wait_sent(&handle, vec![WriteCommand::Push { data }]).await;
    }

    #[tokio::test]
    async fn dropping_reader_with_flushed_pull_and_pending_stop_drains_stop_only() {
        let code = VarInt::from_u32(208);
        let (mut bridge, handle) = reader(VarInt::from_u32(209));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_next(cx))
                .now_or_never()
                .is_none(),
            "pull should be flushed and wait for inbound data"
        );
        assert_eq!(handle.sent(), [ReadCommand::Pull]);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_stop(cx, code))
                .now_or_never()
                .is_none(),
            "stop should be committed behind the in-flight pull"
        );
        handle.push_inbound(ReadEvent::Push {
            data: Bytes::from_static(b"not drained"),
        });
        drop(bridge);

        wait_sent(&handle, vec![ReadCommand::Pull, ReadCommand::Stop { code }]).await;
        assert_eq!(
            handle.inbound_len(),
            1,
            "drain must not poll inbound pull results"
        );
    }

    #[tokio::test]
    async fn dropping_writer_awaiting_ack_does_not_flush_second_acked_command() {
        let (mut bridge, handle) = writer(VarInt::from_u32(210));

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_flush(cx))
                .now_or_never()
                .is_none(),
            "flush should be sent and wait for FlushAck"
        );
        assert_eq!(handle.sent(), [WriteCommand::Flush]);

        assert!(
            poll_fn(|cx| Pin::new(&mut bridge).poll_close(cx))
                .now_or_never()
                .is_none(),
            "eos should be committed behind the awaiting flush"
        );
        drop(bridge);

        tokio::task::yield_now().await;
        assert_eq!(
            handle.sent(),
            [WriteCommand::Flush],
            "drain must not pipeline Eos behind an awaiting FlushAck"
        );
    }
}
