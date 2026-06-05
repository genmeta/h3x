pub(crate) mod read;
pub(crate) mod write;

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
        time::Duration,
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt as _, Stream, StreamExt as _, channel::mpsc};

    use super::{read::run_read_bridge, write::run_write_bridge};
    use crate::{
        quic::{self, GetStreamId, ResetStream, StopStream},
        rpc::stream::{
            frame::{ReadCommand, ReadEvent, WriteCommand, WriteEvent},
            test_io::{TestFrameIoError, worker_reader_pair, worker_writer_pair},
        },
        varint::VarInt,
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(100);

    struct RecordingReader {
        stream_id: VarInt,
        inbound: mpsc::UnboundedReceiver<Result<Bytes, quic::StreamError>>,
        stops: Arc<Mutex<Vec<VarInt>>>,
    }

    struct ReaderHandle {
        inbound: mpsc::UnboundedSender<Result<Bytes, quic::StreamError>>,
        stops: Arc<Mutex<Vec<VarInt>>>,
    }

    fn recording_reader(stream_id: VarInt) -> (RecordingReader, ReaderHandle) {
        let (inbound, rx) = mpsc::unbounded();
        let stops = Arc::new(Mutex::new(Vec::new()));
        (
            RecordingReader {
                stream_id,
                inbound: rx,
                stops: stops.clone(),
            },
            ReaderHandle { inbound, stops },
        )
    }

    impl ReaderHandle {
        fn push(&self, data: Bytes) {
            self.inbound
                .unbounded_send(Ok(data))
                .expect("reader data should queue");
        }

        fn stops(&self) -> Vec<VarInt> {
            self.stops.lock().unwrap().clone()
        }
    }

    impl Unpin for RecordingReader {}

    impl GetStreamId for RecordingReader {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for RecordingReader {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.stops.lock().unwrap().push(code);
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for RecordingReader {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.get_mut().inbound.poll_next_unpin(cx)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum WriterOp {
        Push(Bytes),
        Flush,
        Eos,
        Reset(VarInt),
    }

    struct RecordingWriter {
        stream_id: VarInt,
        state: Arc<Mutex<WriterState>>,
    }

    #[derive(Clone)]
    struct WriterHandle {
        state: Arc<Mutex<WriterState>>,
    }

    struct WriterState {
        hold_flush: bool,
        waker: Option<Waker>,
        buffered: Vec<Bytes>,
        ops: Vec<WriterOp>,
    }

    fn recording_writer(stream_id: VarInt) -> (RecordingWriter, WriterHandle) {
        let state = Arc::new(Mutex::new(WriterState {
            hold_flush: false,
            waker: None,
            buffered: Vec::new(),
            ops: Vec::new(),
        }));
        (
            RecordingWriter {
                stream_id,
                state: state.clone(),
            },
            WriterHandle { state },
        )
    }

    impl WriterHandle {
        fn hold_flush(&self, hold_flush: bool) {
            let waker = {
                let mut state = self.state.lock().unwrap();
                state.hold_flush = hold_flush;
                state.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }

        fn ops(&self) -> Vec<WriterOp> {
            self.state.lock().unwrap().ops.clone()
        }
    }

    impl Unpin for RecordingWriter {}

    impl GetStreamId for RecordingWriter {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl ResetStream for RecordingWriter {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state.lock().unwrap().ops.push(WriterOp::Reset(code));
            Poll::Ready(Ok(()))
        }
    }

    impl Sink<Bytes> for RecordingWriter {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state.lock().unwrap().buffered.push(item);
            Ok(())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            let mut state = self.state.lock().unwrap();
            if state.hold_flush {
                state.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let buffered = std::mem::take(&mut state.buffered);
            if buffered.is_empty() {
                state.ops.push(WriterOp::Flush);
            } else {
                state.ops.extend(buffered.into_iter().map(WriterOp::Push));
            }
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.state.lock().unwrap().ops.push(WriterOp::Eos);
            Poll::Ready(Ok(()))
        }
    }

    async fn expect_read_event(
        worker: &mut crate::rpc::stream::test_io::MemoryFrameIo<
            ReadCommand,
            ReadEvent,
            TestFrameIoError,
        >,
    ) -> ReadEvent {
        worker
            .next_frame()
            .await
            .expect("read event should be sent")
            .expect("read event should decode")
    }

    async fn expect_write_event(
        worker: &mut crate::rpc::stream::test_io::MemoryFrameIo<
            WriteCommand,
            WriteEvent,
            TestFrameIoError,
        >,
    ) -> WriteEvent {
        worker
            .next_frame()
            .await
            .expect("write event should be sent")
            .expect("write event should decode")
    }

    #[tokio::test]
    async fn read_bridge_executes_pull_then_stop_in_received_order() {
        let stop_code = VarInt::from_u32(301);
        let data = Bytes::from_static(b"read bridge data");
        let (reader, handle) = recording_reader(VarInt::from_u32(302));
        let (mut worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_read_bridge(reader, hypervisor));

        worker
            .send(ReadCommand::Pull)
            .await
            .expect("pull should send");
        worker
            .send(ReadCommand::Stop { code: stop_code })
            .await
            .expect("stop should send behind pull");
        handle.push(data.clone());

        assert_eq!(
            expect_read_event(&mut worker).await,
            ReadEvent::Push { data }
        );
        assert_eq!(
            expect_read_event(&mut worker).await,
            ReadEvent::StopAck { code: stop_code }
        );
        assert_eq!(handle.stops(), [stop_code]);
        drop(worker);
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("read bridge should finish after worker eof")
            .expect("read bridge task should not panic");
    }

    #[tokio::test]
    async fn read_bridge_worker_eof_does_not_generate_stop() {
        let (reader, handle) = recording_reader(VarInt::from_u32(303));
        let (worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_read_bridge(reader, hypervisor));

        drop(worker);

        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("read bridge should finish after worker eof")
            .expect("read bridge task should not panic");
        assert!(handle.stops().is_empty());
    }

    #[tokio::test]
    async fn read_bridge_ignores_worker_outbound_eof_while_replying() {
        let (reader, handle) = recording_reader(VarInt::from_u32(304));
        let (mut worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_read_bridge(reader, hypervisor));

        worker
            .send(ReadCommand::Pull)
            .await
            .expect("pull should send");
        drop(worker);
        handle.push(Bytes::from_static(b"abandoned"));

        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("read bridge should finish after abandoned response")
            .expect("read bridge task should not panic");
    }

    #[tokio::test]
    async fn write_bridge_sends_initial_pull_credit() {
        let (writer, _handle) = recording_writer(VarInt::from_u32(305));
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        drop(worker);
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should finish after worker eof")
            .expect("write bridge task should not panic");
    }

    #[tokio::test]
    async fn write_bridge_treats_flush_and_eos_as_fifo_barriers() {
        let data = Bytes::from_static(b"fifo data");
        let (writer, handle) = recording_writer(VarInt::from_u32(306));
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Push { data: data.clone() })
            .await
            .expect("push should send");
        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Flush)
            .await
            .expect("flush should send");
        worker
            .send(WriteCommand::Eos)
            .await
            .expect("eos should send");

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::FlushAck);
        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::EosAck);
        assert_eq!(
            handle.ops(),
            [WriterOp::Push(data), WriterOp::Flush, WriterOp::Eos]
        );
        drop(worker);
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should finish after eos")
            .expect("write bridge task should not panic");
    }

    #[tokio::test]
    async fn write_bridge_reset_clears_queued_work_without_interrupting_current_push() {
        let reset = VarInt::from_u32(307);
        let first = Bytes::from_static(b"first");
        let (writer, handle) = recording_writer(VarInt::from_u32(308));
        handle.hold_flush(true);
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Push {
                data: first.clone(),
            })
            .await
            .expect("first push should send");
        worker
            .send(WriteCommand::Flush)
            .await
            .expect("flush should queue");
        worker
            .send(WriteCommand::Reset { code: reset })
            .await
            .expect("reset should queue");

        tokio::task::yield_now().await;
        assert_eq!(handle.ops(), []);
        handle.hold_flush(false);

        assert_eq!(
            expect_write_event(&mut worker).await,
            WriteEvent::ResetAck { code: reset }
        );
        assert_eq!(
            handle.ops(),
            [WriterOp::Push(first), WriterOp::Reset(reset)]
        );
        drop(worker);
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should finish after reset")
            .expect("write bridge task should not panic");
    }

    #[tokio::test]
    async fn write_bridge_does_not_pull_after_terminal_command() {
        let reset = VarInt::from_u32(309);
        let (writer, _handle) = recording_writer(VarInt::from_u32(310));
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Reset { code: reset })
            .await
            .expect("reset should send");
        assert_eq!(
            expect_write_event(&mut worker).await,
            WriteEvent::ResetAck { code: reset }
        );
        match tokio::time::timeout(Duration::from_millis(10), worker.next_frame()).await {
            Ok(Some(Ok(frame))) => panic!("terminal reset must not send another frame: {frame:?}"),
            Ok(Some(Err(error))) => panic!("terminal reset produced frame error: {error:?}"),
            Ok(None) | Err(_) => {}
        }
        drop(worker);
        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should finish after reset")
            .expect("write bridge task should not panic");
    }

    #[tokio::test]
    async fn write_bridge_worker_eof_drains_queued_work_without_fin_or_reset() {
        let data = Bytes::from_static(b"queued before eof");
        let (writer, handle) = recording_writer(VarInt::from_u32(311));
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Push { data: data.clone() })
            .await
            .expect("push should send");
        worker
            .send(WriteCommand::Flush)
            .await
            .expect("flush should send");
        drop(worker);

        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should drain after worker eof")
            .expect("write bridge task should not panic");
        assert_eq!(handle.ops(), [WriterOp::Push(data), WriterOp::Flush]);
    }

    #[tokio::test]
    async fn write_bridge_ignores_worker_outbound_eof_while_sending_ack() {
        let (writer, handle) = recording_writer(VarInt::from_u32(312));
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        let task = tokio::spawn(run_write_bridge(writer, hypervisor));

        assert_eq!(expect_write_event(&mut worker).await, WriteEvent::Pull);
        worker
            .send(WriteCommand::Flush)
            .await
            .expect("flush should send");
        drop(worker);

        tokio::time::timeout(TEST_TIMEOUT, task)
            .await
            .expect("write bridge should ignore closed ack receiver")
            .expect("write bridge task should not panic");
        assert_eq!(handle.ops(), [WriterOp::Flush]);
    }
}
