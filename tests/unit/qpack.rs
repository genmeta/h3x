use std::{
    io,
    pin::Pin,
    sync::{
        TryLockError,
        atomic::{AtomicUsize, Ordering},
        mpsc as std_mpsc,
    },
    task::{Context, Poll},
    thread,
};

use codec::instruction::DecoderInstruction;
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::*;
use crate::{
    Transport,
    qpack::codec::field::{FieldLine, FieldSectionPrefix, WriteField},
};

pub(crate) fn qpack() -> ArcQpack {
    ArcQpack::new(&super::super::connection::Settings::default()).unwrap()
}

#[derive(Default)]
pub(crate) struct TestIo;

struct FailingWriter;

struct FeedbackInterleavingWriter {
    writes: usize,
    insertion_visible: Option<std_mpsc::Sender<()>>,
    feedback_saw_lock: std_mpsc::Receiver<bool>,
}

impl AsyncWrite for FailingWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("write failed")))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("flush failed")))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("shutdown failed")))
    }
}

impl AsyncWrite for FeedbackInterleavingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes += 1;
        if self.writes == 3 {
            self.insertion_visible.take().unwrap().send(()).unwrap();
            assert!(
                self.feedback_saw_lock.recv().unwrap(),
                "QPACK feedback could acquire the state lock before the insertion was recorded"
            );
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for TestIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TestIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl StopSending for TestIo {
    fn stop(&mut self, _: u64) {}
}

impl CancelStream for TestIo {
    fn cancel(&mut self, _: u64) {}
}

impl crate::TransportError for TestIo {
    fn map_error(error: io::Error) -> crate::Error {
        crate::Error::from_stream_io(error)
    }
}

pub(crate) struct TestTransport {
    mode: u8,
    closes: AtomicUsize,
}

impl TestTransport {
    pub(crate) fn new(mode: u8) -> Self {
        Self {
            mode,
            closes: AtomicUsize::new(0),
        }
    }

    pub(crate) fn close_count(&self) -> usize {
        self.closes.load(Ordering::SeqCst)
    }
}

impl crate::Transport for TestTransport {
    type StreamReader = TestIo;
    type StreamWriter = TestIo;

    fn role(&self) -> crate::Role {
        crate::Role::Client
    }

    async fn open_bi(&self) -> Result<Option<(u64, (TestIo, TestIo))>> {
        Ok(None)
    }

    async fn accept_bi(&self) -> Result<(u64, (TestIo, TestIo))> {
        Err(ErrorCode::InternalError.connection("unused"))
    }

    async fn open_uni(&self) -> Result<Option<(u64, TestIo)>> {
        match self.mode {
            0 => Ok(None),
            1 => Ok(Some((2, TestIo))),
            _ => Err(ErrorCode::InternalError.connection("open failed")),
        }
    }

    async fn accept_uni(&self) -> Result<(u64, TestIo)> {
        Err(ErrorCode::InternalError.connection("unused"))
    }

    fn close(&self, _: String, _: u64) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn field(name: &'static [u8], value: &'static [u8], never_index: bool) -> Field {
    Field {
        name: Bytes::from_static(name),
        value: Bytes::from_static(value),
        never_index,
    }
}

#[test]
fn extracts_qpack_limits_and_classifies_sensitive_fields() {
    let settings = super::super::connection::Settings::new(1234, 5678, 9).unwrap();
    assert_eq!(
        limits(&settings.0),
        (
            Settings {
                max_table_capacity: 5678,
                blocked_streams: 9,
            },
            1234
        )
    );
    for name in [
        b"authorization".as_slice(),
        b"proxy-authorization",
        b"cookie",
        b"set-cookie",
    ] {
        assert!(should_never_index(name));
    }
    assert!(!should_never_index(b"content-type"));
}

#[tokio::test]
async fn static_and_literal_fields_round_trip_without_dynamic_state() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let fields = vec![
        field(b":method", b"GET", false),
        field(b":path", b"/custom", false),
        field(b"authorization", b"secret", true),
        field(b"x-test", b"value", false),
    ];

    let encoded = qpack.encode(0, fields.clone()).unwrap();
    let decoded = qpack.decode(0, encoded).await.unwrap();
    assert_eq!(decoded, fields);
}

#[tokio::test]
async fn connection_failure_is_sticky_and_wakes_existing_and_late_waiters() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let waiting = {
        let qpack = qpack.clone();
        tokio::spawn(async move { qpack.failed().await })
    };
    tokio::task::yield_now().await;

    let first = ErrorCode::QpackDecompressionFailed.connection("first");
    let second = ErrorCode::InternalError.connection("second");
    assert_eq!(qpack.on_connection_error(first.clone()).reason, "first");
    assert_eq!(qpack.on_connection_error(second).reason, "first");
    assert_eq!(waiting.await.unwrap().reason, "first");
    assert_eq!(qpack.failed().await.reason, "first");
}

#[test]
fn instruction_queue_errors_map_to_connection_errors() {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    sender.try_send(1).unwrap();
    assert_eq!(
        instruction_send_error(sender.try_send(2).unwrap_err()).code,
        ErrorCode::ExcessiveLoad
    );
    drop(receiver);
    assert_eq!(
        instruction_send_error(sender.try_send(3).unwrap_err()).code,
        ErrorCode::ClosedCriticalStream
    );
}

#[test]
fn caller_selects_error_scope_independently_of_the_code() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let stream_error = ErrorCode::InternalError.stream("stream");
    let stream_error = qpack.on_stream_error(0, stream_error.clone());
    assert!(matches!(stream_error, Error::Stream(_)));
    assert!(qpack.error().is_none());

    let connection_error = ErrorCode::InternalError.connection("connection");
    let connection_error = qpack.on_connection_error(connection_error);
    assert!(matches!(connection_error, Error::Connection(_)));
    assert_eq!(qpack.error(), Some(connection_error));
}

#[tokio::test]
async fn instruction_writers_process_batches_and_report_critical_close() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let (encoder_tx, encoder_rx) = tokio::sync::mpsc::channel(2);
    encoder_tx
        .send(vec![
            EncoderInstruction::SetDynamicTableCapacity(0),
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x"),
                value: Bytes::from_static(b"y"),
            },
        ])
        .await
        .unwrap();
    drop(encoder_tx);
    assert_eq!(
        qpack
            .write_encoder(encoder_rx, &mut tokio::io::sink())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );

    let (mut writer, mut reader) = tokio::io::duplex(128);
    qpack.cancel_decode(vec![4]).unwrap();
    let writing = {
        let qpack = qpack.clone();
        tokio::spawn(async move { qpack.write_decoder(&mut writer).await })
    };
    let mut wire = [0; 2];
    tokio::io::AsyncReadExt::read_exact(&mut reader, &mut wire)
        .await
        .unwrap();
    assert_eq!(wire, [StreamType::QpackDecoder as u8, 0x44]);
    let failed = ErrorCode::InternalError.connection("already failed");
    qpack.on_connection_error(failed.clone());
    assert_eq!(writing.await.unwrap().unwrap_err(), failed);
    let (_, encoder_rx) = tokio::sync::mpsc::channel(1);
    assert_eq!(
        qpack
            .write_encoder(encoder_rx, &mut tokio::io::sink())
            .await
            .unwrap_err(),
        failed
    );
}

#[tokio::test]
async fn insertion_write_and_completion_are_ordered_before_decoder_feedback() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let queued = Arc::new(Mutex::new(Vec::new()));
    let captured = queued.clone();
    qpack
        .with_state(|state| {
            state.encoder.on_instruction(move |batch| {
                captured.lock().unwrap().push(batch);
                Ok(())
            });
            Ok(())
        })
        .unwrap();
    qpack
        .configure(
            Settings {
                max_table_capacity: 128,
                blocked_streams: 1,
            },
            4096,
        )
        .unwrap();
    qpack
        .encode(0, vec![field(b"x-interleaved", b"value", false)])
        .unwrap();

    let (instruction_tx, instruction_rx) = tokio::sync::mpsc::channel(2);
    let batches = std::mem::take(&mut *queued.lock().unwrap());
    assert_eq!(batches.len(), 2);
    for batch in batches {
        instruction_tx.send(batch).await.unwrap();
    }
    drop(instruction_tx);

    let (visible_tx, visible_rx) = std_mpsc::channel();
    let (lock_tx, lock_rx) = std_mpsc::channel();
    let feedback_qpack = qpack.clone();
    let feedback = thread::spawn(move || {
        visible_rx.recv().unwrap();
        let apply = |state: &mut Qpack| {
            state
                .encoder
                .on_decoder_instruction(DecoderInstruction::InsertCountIncrement(1))?;
            state
                .encoder
                .on_decoder_instruction(DecoderInstruction::SectionAcknowledgment(0))
        };
        match feedback_qpack.try_lock() {
            Ok(mut shared) => {
                lock_tx.send(false).unwrap();
                apply(shared.as_mut().unwrap())
            }
            Err(TryLockError::WouldBlock) => {
                lock_tx.send(true).unwrap();
                feedback_qpack.with_state(apply)
            }
            Err(TryLockError::Poisoned(_)) => panic!("QPACK state lock was poisoned"),
        }
    });
    let mut writer = FeedbackInterleavingWriter {
        writes: 0,
        insertion_visible: Some(visible_tx),
        feedback_saw_lock: lock_rx,
    };

    assert_eq!(
        qpack
            .write_encoder(instruction_rx, &mut writer)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
    feedback.join().unwrap().unwrap();
}

#[tokio::test]
async fn instruction_receivers_apply_valid_input_then_map_eof() {
    let settings = super::super::connection::Settings::new(4096, 128, 1).unwrap();
    let qpack = ArcQpack::new(&settings).unwrap();
    let mut encoder_wire = Vec::new();
    encoder_wire
        .put_encoder_instruction(&EncoderInstruction::SetDynamicTableCapacity(128))
        .unwrap();
    encoder_wire
        .put_encoder_instruction(&EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x-received"),
            value: Bytes::from_static(b"yes"),
        })
        .unwrap();
    assert_eq!(
        qpack
            .receive_encoder(&mut encoder_wire.as_slice())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
    assert!(matches!(
        qpack
            .with_state(|state| Ok(state.decoder.take_feedback().0))
            .unwrap()
            .as_slice(),
        [DecoderInstruction::InsertCountIncrement(1)]
    ));

    let mut decoder_wire = Vec::new();
    decoder_wire
        .put_decoder_instruction(&DecoderInstruction::StreamCancellation(7))
        .unwrap();
    assert_eq!(
        qpack
            .receive_decoder(&mut decoder_wire.as_slice())
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
}

#[tokio::test]
async fn malformed_field_section_fails_qpack_connection() {
    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    let error = qpack
        .decode(0, Bytes::from_static(&[0xff]))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::QpackDecompressionFailed);
    assert_eq!(qpack.error(), Some(error.clone()));
}

#[tokio::test]
async fn qpack_stream_sync_maps_open_failures_and_closes_transport() {
    let smoke = TestTransport::new(0);
    assert_eq!(smoke.role(), crate::Role::Client);
    assert!(smoke.open_bi().await.unwrap().is_none());
    assert!(smoke.accept_bi().await.is_err());
    assert!(smoke.accept_uni().await.is_err());
    let mut io = TestIo;
    let mut byte = [0];
    assert_eq!(
        tokio::io::AsyncReadExt::read(&mut io, &mut byte)
            .await
            .unwrap(),
        0
    );
    tokio::io::AsyncWriteExt::write_all(&mut io, b"x")
        .await
        .unwrap();
    tokio::io::AsyncWriteExt::flush(&mut io).await.unwrap();
    tokio::io::AsyncWriteExt::shutdown(&mut io).await.unwrap();
    io.stop(1);
    io.cancel(2);

    for mode in [0, 1, 2] {
        let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
        let transport = Arc::new(TestTransport::new(mode));
        let (_, encoder_rx) = tokio::sync::mpsc::channel(1);
        assert!(
            qpack
                .sync_encoder_with(transport.clone(), encoder_rx)
                .await
                .is_err()
        );
        assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
    }
    for mode in [0, 1, 2] {
        let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
        let transport = Arc::new(TestTransport::new(mode));
        if mode == 1 {
            qpack.on_connection_error(
                ErrorCode::ClosedCriticalStream.connection("test peer closed"),
            );
        }
        assert!(qpack.sync_decoder_with(transport.clone()).await.is_err());
        assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn configure_cancel_waiters_and_writer_io_errors_are_propagated() {
    let settings = super::super::connection::Settings::new(4096, 128, 1).unwrap();
    let qpack = ArcQpack::new(&settings).unwrap();
    qpack
        .with_state(|state| {
            state.encoder.on_instruction(|_| Ok(()));
            Ok(())
        })
        .unwrap();
    qpack
        .configure(
            Settings {
                max_table_capacity: 128,
                blocked_streams: 1,
            },
            4096,
        )
        .unwrap();

    let mut wire = Vec::new();
    wire.put_field_section_prefix(
        &FieldSectionPrefix {
            required_insert_count: 1,
            base: 0,
        },
        128,
    )
    .unwrap();
    wire.put_field_line(&FieldLine::IndexedPostBase { index: 0 })
        .unwrap();
    let decoding = {
        let qpack = qpack.clone();
        tokio::spawn(async move { qpack.decode(4, wire.into()).await })
    };
    tokio::task::yield_now().await;
    qpack.cancel_decode(vec![4]).unwrap();
    assert_eq!(
        decoding.await.unwrap().unwrap_err().code,
        ErrorCode::RequestCancelled
    );

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    drop(tx);
    assert_eq!(
        qpack
            .write_encoder(rx, &mut FailingWriter)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
    assert_eq!(
        qpack
            .write_decoder(&mut FailingWriter)
            .await
            .unwrap_err()
            .code,
        ErrorCode::ClosedCriticalStream
    );
    assert!(
        tokio::io::AsyncWriteExt::flush(&mut FailingWriter)
            .await
            .is_err()
    );
    assert!(
        tokio::io::AsyncWriteExt::shutdown(&mut FailingWriter)
            .await
            .is_err()
    );

    let qpack = ArcQpack::new(&super::super::connection::Settings::default()).unwrap();
    assert_eq!(
        qpack
            .on_stream_error(0, ErrorCode::NoError.connection("cancel"))
            .code,
        ErrorCode::NoError
    );
}

#[path = "qpack/feedback.rs"]
mod feedback;
