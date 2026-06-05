use std::{
    borrow::Cow,
    marker::PhantomData,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use futures::{Sink, SinkExt as _, Stream, StreamExt as _, channel::mpsc};
use snafu::Snafu;

use super::frame::{
    HyperReadIn, HyperReadOut, HyperWriteIn, HyperWriteOut, WorkerReadIn, WorkerReadOut,
    WorkerWriteIn, WorkerWriteOut,
};
use crate::{
    error::Code,
    quic,
    rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt},
    varint::VarInt,
};

const MEMORY_FRAME_IO_CAPACITY: usize = 8;
const TEST_FRAME_IO_FRAME_TYPE: VarInt = VarInt::from_u32(0x3f02);

pub(crate) struct TestLifecycle {
    latch: ConnectionErrorLatch,
    closed_error: Mutex<Option<quic::ConnectionError>>,
}

impl TestLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            latch: ConnectionErrorLatch::new(),
            closed_error: Mutex::new(None),
        }
    }

    pub(crate) fn set_closed_error(&self, error: quic::ConnectionError) {
        *self.closed_error.lock().unwrap() = Some(error);
    }
}

impl HasLatch for TestLifecycle {
    fn latch(&self) -> &ConnectionErrorLatch {
        &self.latch
    }
}

impl quic::Lifecycle for TestLifecycle {
    fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

    fn check(&self) -> Result<(), quic::ConnectionError> {
        self.check_with_probe(|| None)
    }

    async fn closed(&self) -> quic::ConnectionError {
        self.resolve_closed(async {
            self.closed_error
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| quic::ConnectionError::from(TestFrameIoError::new(0xfe)))
        })
        .await
    }
}

#[derive(Debug, Snafu, Clone, PartialEq, Eq)]
#[snafu(display("test frame io error {kind}"))]
pub(crate) struct TestFrameIoError {
    kind: VarInt,
}

impl TestFrameIoError {
    pub(crate) const fn new(kind: u32) -> Self {
        Self {
            kind: VarInt::from_u32(kind),
        }
    }

    pub(crate) const fn kind(&self) -> VarInt {
        self.kind
    }
}

impl From<TestFrameIoError> for quic::ConnectionError {
    fn from(error: TestFrameIoError) -> Self {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: error.kind(),
                frame_type: TEST_FRAME_IO_FRAME_TYPE,
                reason: "test frame io error".into(),
            },
        }
    }
}

#[derive(Debug, Snafu, Clone)]
#[snafu(display("memory frame io peer closed"))]
pub(crate) struct MemoryFrameIoClosed;

impl From<MemoryFrameIoClosed> for TestFrameIoError {
    fn from(_error: MemoryFrameIoClosed) -> Self {
        Self::new(0xff)
    }
}

pub(crate) struct MemoryFrameIo<Out, In, E> {
    outgoing: mpsc::Sender<Result<Out, E>>,
    incoming: mpsc::Receiver<Result<In, E>>,
    _error: PhantomData<E>,
}

impl<Out, In, E> MemoryFrameIo<Out, In, E> {
    pub(crate) async fn next_frame(&mut self) -> Option<Result<In, E>> {
        self.incoming.next().await
    }
}

impl<Out, In, E> Unpin for MemoryFrameIo<Out, In, E> {}

impl<Out, In, E> Sink<Out> for MemoryFrameIo<Out, In, E>
where
    E: From<MemoryFrameIoClosed>,
{
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.outgoing.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_error)) => Poll::Ready(Err(MemoryFrameIoClosed.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Out) -> Result<(), Self::Error> {
        let this = self.get_mut();
        match this.outgoing.start_send_unpin(Ok(item)) {
            Ok(()) => Ok(()),
            Err(_error) => Err(MemoryFrameIoClosed.into()),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.outgoing.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_error)) => Poll::Ready(Err(MemoryFrameIoClosed.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.outgoing.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_error)) => Poll::Ready(Err(MemoryFrameIoClosed.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<Out, In, E> Stream for MemoryFrameIo<Out, In, E> {
    type Item = Result<In, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.incoming.poll_next_unpin(cx)
    }
}

fn memory_frame_io_pair<AOut, AIn, E>() -> (MemoryFrameIo<AOut, AIn, E>, MemoryFrameIo<AIn, AOut, E>)
{
    let (a_outgoing, b_incoming) = mpsc::channel(MEMORY_FRAME_IO_CAPACITY);
    let (b_outgoing, a_incoming) = mpsc::channel(MEMORY_FRAME_IO_CAPACITY);

    (
        MemoryFrameIo {
            outgoing: a_outgoing,
            incoming: a_incoming,
            _error: PhantomData,
        },
        MemoryFrameIo {
            outgoing: b_outgoing,
            incoming: b_incoming,
            _error: PhantomData,
        },
    )
}

pub(crate) fn worker_reader_pair<E>() -> (
    MemoryFrameIo<WorkerReadOut, WorkerReadIn, E>,
    MemoryFrameIo<HyperReadOut, HyperReadIn, E>,
) {
    memory_frame_io_pair()
}

pub(crate) fn worker_writer_pair<E>() -> (
    MemoryFrameIo<WorkerWriteOut, WorkerWriteIn, E>,
    MemoryFrameIo<HyperWriteOut, HyperWriteIn, E>,
) {
    memory_frame_io_pair()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::rpc::stream::{
        error::{
            DeferredStreamError, DriverProtocolError, defer_err_conn, latch_frame_io_error,
            latch_protocol_error,
        },
        io::FrameIo,
    };

    fn transport(error: &quic::ConnectionError) -> &quic::TransportError {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("connection error should be transport-scoped");
        };
        source
    }

    fn transport_kind(error: &quic::ConnectionError) -> VarInt {
        transport(error).kind
    }

    fn transport_reason(error: &quic::ConnectionError) -> &str {
        transport(error).reason.as_ref()
    }

    fn stream_connection_kind(error: quic::StreamError) -> VarInt {
        let quic::StreamError::Connection { source } = error else {
            panic!("stream error should be connection-scoped");
        };
        transport_kind(&source)
    }

    fn assert_frame_io<IO, Out, In, Error>(_io: &IO)
    where
        IO: FrameIo<Out, In, Error>,
    {
    }

    #[tokio::test]
    async fn frame_io_error_is_latched_first_wins() {
        let lifecycle = TestLifecycle::new();

        let first = latch_frame_io_error(&lifecycle, TestFrameIoError::new(11));
        let second = latch_frame_io_error(&lifecycle, TestFrameIoError::new(12));

        assert_eq!(stream_connection_kind(first), VarInt::from_u32(11));
        assert_eq!(stream_connection_kind(second), VarInt::from_u32(11));
        assert_eq!(
            transport_kind(&lifecycle.latch().check().unwrap_err()),
            VarInt::from_u32(11)
        );
    }

    #[tokio::test]
    async fn protocol_error_is_latched_first_wins() {
        let lifecycle = TestLifecycle::new();

        let first = latch_protocol_error(&lifecycle, DriverProtocolError::UnexpectedReaderFrame);
        let second = latch_protocol_error(&lifecycle, DriverProtocolError::UnexpectedWriterAck);

        assert_eq!(
            stream_connection_kind(first),
            stream_connection_kind(second)
        );
        let latched = lifecycle.latch().check().unwrap_err();
        assert_eq!(
            transport_reason(&latched),
            "received frame that is invalid for the current reader operation"
        );
        assert_eq!(
            transport_reason(&latched),
            transport_reason(&quic::Lifecycle::closed(&lifecycle).await)
        );
    }

    #[tokio::test]
    async fn defer_err_conn_uses_immediate_check_when_already_closed() {
        let lifecycle = Arc::new(TestLifecycle::new());
        lifecycle
            .latch()
            .latch_with(|| quic::ConnectionError::from(TestFrameIoError::new(21)));

        let DeferredStreamError::Ready { error } = defer_err_conn(lifecycle) else {
            panic!("already closed lifecycle should produce immediate stream error");
        };

        assert_eq!(stream_connection_kind(error), VarInt::from_u32(21));
    }

    #[tokio::test]
    async fn defer_err_conn_can_wait_for_closed_when_not_latched() {
        let lifecycle = Arc::new(TestLifecycle::new());
        lifecycle.set_closed_error(quic::ConnectionError::from(TestFrameIoError::new(31)));

        let DeferredStreamError::Pending { future } = defer_err_conn(lifecycle) else {
            panic!("clean lifecycle should defer until closed");
        };

        assert_eq!(stream_connection_kind(future.await), VarInt::from_u32(31));
    }

    #[tokio::test]
    async fn worker_reader_io_eof_is_latched_as_connection_error_not_read_eos() {
        let lifecycle = TestLifecycle::new();
        let (mut worker, hypervisor) = worker_reader_pair::<TestFrameIoError>();
        assert_frame_io::<_, WorkerReadOut, WorkerReadIn, TestFrameIoError>(&worker);
        drop(hypervisor);

        let eof = match worker.next_frame().await {
            None => latch_protocol_error(&lifecycle, DriverProtocolError::FrameEof),
            Some(Ok(WorkerReadIn::Eos)) => {
                panic!("worker bridge IO EOF must not synthesize read EOS")
            }
            Some(frame) => panic!("worker bridge IO EOF produced unexpected frame {frame:?}"),
        };
        let quic::StreamError::Connection { source } = eof else {
            panic!("worker frame EOF should be a connection error");
        };

        assert_eq!(
            transport_reason(&source),
            "typed frame stream ended before operation completed"
        );
        assert_eq!(
            transport_reason(&source),
            transport_reason(&quic::Lifecycle::closed(&lifecycle).await)
        );
    }

    #[tokio::test]
    async fn worker_writer_io_eof_is_latched_as_connection_error_not_write_close() {
        let lifecycle = TestLifecycle::new();
        let (mut worker, hypervisor) = worker_writer_pair::<TestFrameIoError>();
        assert_frame_io::<_, WorkerWriteOut, WorkerWriteIn, TestFrameIoError>(&worker);
        drop(hypervisor);

        let eof = match worker.next_frame().await {
            None => latch_protocol_error(&lifecycle, DriverProtocolError::FrameEof),
            Some(Ok(WorkerWriteIn::EosAck)) => {
                panic!("worker bridge IO EOF must not synthesize write close ack")
            }
            Some(frame) => panic!("worker bridge IO EOF produced unexpected frame {frame:?}"),
        };
        let quic::StreamError::Connection { source } = eof else {
            panic!("worker frame EOF should be a connection error");
        };

        assert_eq!(
            transport_reason(&source),
            "typed frame stream ended before operation completed"
        );
        assert_eq!(
            transport_reason(&source),
            transport_reason(&quic::Lifecycle::closed(&lifecycle).await)
        );
    }

    #[tokio::test]
    async fn memory_worker_writer_pair_transfers_frames() {
        let (mut worker, mut hypervisor) = worker_writer_pair::<TestFrameIoError>();

        worker
            .send(WorkerWriteOut::Flush)
            .await
            .expect("send should succeed");

        assert_eq!(hypervisor.next_frame().await, Some(Ok(HyperWriteIn::Flush)));
    }
}
