//! Compression state for the two independent QPACK directions.

use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use codec::instruction::{EncoderInstruction, WriteInstruction};
use qbase::varint::VARINT_MAX;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{frame, frame::StreamType};
use crate::{Error, ErrorCode, Result};

mod codec;
pub(super) mod decoder;
pub(super) mod encoder;
mod table;

pub(crate) use codec::field::Field;
use decoder::Decoder;
use encoder::Encoder;

/// Maximum queued operation batches per QPACK direction. Producers never block.
pub(super) const MAX_PENDING_INSTRUCTION: usize = 16;

/// Aggregate field bytes retained while waiting for dynamic-table insertions.
const MAX_BLOCKED_FIELD_SECTION_BYTES: usize = 64 * 1024;

/// Local policy permitted by RFC 9204 section 7.1.3; not an RFC-mandated list.
fn should_never_index(name: &[u8]) -> bool {
    matches!(
        name,
        b"authorization" | b"proxy-authorization" | b"cookie" | b"set-cookie"
    )
}

/// Decoder-advertised limits, RFC 9204 section 5. Both default to zero.
/// These are extracted from HTTP/3 SETTINGS; codec constructors validate their ranges. Remembered 0-RTT limits never carry table contents into a new connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Settings {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01), in bytes, not entries.
    pub(crate) max_table_capacity: u64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07), counting distinct streams.
    pub(crate) blocked_streams: u64,
}

/// Extract compression and field-section limits from HTTP/3 SETTINGS.
pub(crate) fn limits(settings: &frame::Settings) -> (Settings, u64) {
    let defaults = Settings::default();
    (
        Settings {
            max_table_capacity: settings.get(
                frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                defaults.max_table_capacity,
            ),
            blocked_streams: settings.get(
                frame::SETTINGS_QPACK_BLOCKED_STREAMS,
                defaults.blocked_streams,
            ),
        },
        settings.get(frame::SETTINGS_MAX_FIELD_SECTION_SIZE, VARINT_MAX),
    )
}

/// Encoder and decoder share one lock and one terminal error.
pub struct Qpack {
    pub(super) encoder: Encoder,
    pub(super) decoder: Decoder,
}

#[derive(Clone)]
pub struct ArcQpack(Arc<Mutex<Result<Qpack>>>, tokio::sync::watch::Sender<()>);

impl From<Qpack> for ArcQpack {
    fn from(qpack: Qpack) -> Self {
        Self(
            Arc::new(Mutex::new(Ok(qpack))),
            tokio::sync::watch::channel(()).0,
        )
    }
}

impl std::ops::Deref for ArcQpack {
    type Target = Mutex<Result<Qpack>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ArcQpack {
    pub(super) async fn sync_encoder_with<T: crate::Transport>(
        &self,
        transport: Arc<T>,
        instructions: encoder::Instructions,
    ) -> Result<()> {
        tokio::select! {
            biased;
            error = self.failed() => Err(error),
            result = async {
                let (_, mut send) = transport.open_uni().await?.ok_or_else(|| {
                    ErrorCode::StreamCreationError.reason("unable to create the required stream")
                })?;
                self.write_encoder(instructions, &mut send).await
            } => result,
        }
        .map_err(|error| {
            let error = self.on_connection_error(error);
            let _ = transport.close(error.reason.clone(), error.code.as_u64());
            error
        })
    }

    pub(super) async fn sync_decoder_with<T: crate::Transport>(
        &self,
        transport: Arc<T>,
        instructions: decoder::Instructions,
    ) -> Result<()> {
        tokio::select! {
            biased;
            error = self.failed() => Err(error),
            result = async {
                let (_, mut send) = transport.open_uni().await?.ok_or_else(|| {
                    ErrorCode::StreamCreationError.reason("unable to create the required stream")
                })?;
                self.write_decoder(instructions, &mut send).await
            } => result,
        }
        .map_err(|error| {
            let error = self.on_connection_error(error);
            let _ = transport.close(error.reason.clone(), error.code.as_u64());
            error
        })
    }

    /// Run a synchronous operation while holding the shared state lock.
    pub(super) fn with_state<T>(&self, f: impl FnOnce(&mut Qpack) -> Result<T>) -> Result<T> {
        let mut shared = self.lock().unwrap();
        f(shared.as_mut().map_err(|error| error.clone())?)
    }

    fn with_scoped_state<T>(&self, f: impl FnOnce(&mut Qpack) -> Result<T>) -> Result<T> {
        let mut shared = self.lock().unwrap();
        match &mut *shared {
            Ok(state) => f(state),
            Err(error) => Err(error.clone().connection()),
        }
    }

    pub(crate) fn error(&self) -> Option<Error> {
        self.lock().unwrap().as_ref().err().cloned()
    }

    fn critical_stream_error(&self) -> Error {
        self.error().unwrap_or_else(|| {
            ErrorCode::ClosedCriticalStream.reason("critical HTTP/3 stream closed")
        })
    }

    /// Construct compression state. Register instruction callbacks before use.
    pub(super) fn new(settings: &super::connection::Settings) -> Result<Self> {
        let (local, max_fields) = limits(&settings.0);
        Ok(Qpack {
            encoder: Encoder::new(Settings::default())?,
            decoder: Decoder::new(local, MAX_BLOCKED_FIELD_SECTION_BYTES, max_fields)?,
        }
        .into())
    }

    /// Observe the first failure, including failures before subscription.
    pub(crate) async fn failed(&self) -> Error {
        let mut failure = self.1.subscribe();
        loop {
            if let Some(error) = self.error() {
                return error;
            }
            failure
                .changed()
                .await
                .expect("QPACK retains the failure sender");
        }
    }

    pub(crate) fn configure(&self, peer: Settings, max_fields: u64) -> Result<()> {
        self.with_state(|state| state.encoder.configure(peer, max_fields))
    }

    /// Cancel only the affected request's QPACK decoding state.
    ///
    /// Error scope is selected by the caller from the context in which the
    /// error occurred; an HTTP/3 error code alone does not determine it.
    pub fn on_stream_error(&self, id: u64, error: Error) -> Error {
        if let Err(cancel_error) = self.cancel(id) {
            return self.on_connection_error(cancel_error);
        }
        error.stream()
    }

    /// Atomically fail both directions, preserving the first error.
    pub(crate) fn on_connection_error(&self, error: Error) -> Error {
        let error = error.connection();
        let mut qpack = {
            let mut shared = self.lock().unwrap();
            if let Err(error) = &*shared {
                return error.clone();
            }
            let Ok(qpack) = std::mem::replace(&mut *shared, Err(error.clone())) else {
                unreachable!()
            };
            qpack
        };
        let wakes = qpack.decoder.take_waiters();
        self.1.send_replace(());
        // Releasing callbacks closes the instruction queues. Wake outside the shared lock.
        drop(qpack);
        for wake in wakes {
            wake.wake();
        }
        error
    }

    pub(crate) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        let result = self.with_scoped_state(|state| state.encoder.encode(id, fields));
        result.map_err(|error| {
            if error.is_connection() {
                self.on_connection_error(error)
            } else {
                error
            }
        })
    }

    pub(crate) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        self.decode_fields(id, payload).await.map_err(|error| {
            if error.is_connection() {
                self.on_connection_error(error)
            } else {
                error
            }
        })
    }

    async fn decode_fields(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        let (offset, prefix) =
            self.with_scoped_state(|state| state.decoder.begin_decode(id, &payload))?;
        let _decoding = StreamDecoder {
            qpack: self,
            stream_id: id,
        };
        poll_fn(|cx| {
            let mut shared = self.lock().unwrap();
            match &mut *shared {
                Ok(state) => {
                    state
                        .decoder
                        .poll_registered_decode(id, prefix, &payload[offset..], cx)
                }
                Err(error) => Poll::Ready(Err(error.clone().connection())),
            }
        })
        .await
    }

    pub fn cancel(&self, id: u64) -> Result<()> {
        let wakes = self.with_state(|state| state.decoder.cancel(id))?;
        for wake in wakes {
            wake.wake();
        }
        Ok(())
    }

    pub(crate) async fn receive_encoder<R: tokio::io::AsyncRead + Unpin>(
        &self,
        recv: &mut R,
    ) -> Result<()> {
        loop {
            let instruction = codec::instruction::be_encoder_instruction(recv).await?;
            let wakes =
                self.with_state(|state| state.decoder.on_encoder_instruction(instruction))?;
            for wake in wakes {
                wake.wake();
            }
        }
    }

    pub(crate) async fn receive_decoder<R: tokio::io::AsyncRead + Unpin>(
        &self,
        recv: &mut R,
    ) -> Result<()> {
        loop {
            let instruction = codec::instruction::be_decoder_instruction(recv).await?;
            self.with_state(|state| state.encoder.on_decoder_instruction(instruction))?;
        }
    }

    pub(crate) async fn write_encoder<W: AsyncWrite + Unpin>(
        &self,
        mut instructions: encoder::Instructions,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackEncoder as u8])
            .await
            .map_err(|error| crate::Error::from_io(error, ErrorCode::ClosedCriticalStream))?;
        let mut buf = Vec::new();
        while let Some(batch) = instructions.recv().await {
            for instruction in batch {
                buf.clear();
                buf.put_encoder_instruction(&instruction)?;
                writer.write_all(&buf).await.map_err(|error| {
                    crate::Error::from_io(error, ErrorCode::ClosedCriticalStream)
                })?;
                if !matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
                    self.with_state(|state| {
                        state.encoder.record_insert_written();
                        Ok(())
                    })?;
                }
            }
        }
        Err(self.critical_stream_error())
    }

    pub(crate) async fn write_decoder<W: AsyncWrite + Unpin>(
        &self,
        mut receiver: decoder::Instructions,
        writer: &mut W,
    ) -> Result<()> {
        writer
            .write_all(&[StreamType::QpackDecoder as u8])
            .await
            .map_err(|error| crate::Error::from_io(error, ErrorCode::ClosedCriticalStream))?;
        let mut buf = Vec::new();
        while let Some(batch) = receiver.recv().await {
            for instruction in batch {
                buf.clear();
                buf.put_decoder_instruction(&instruction)?;
                writer.write_all(&buf).await.map_err(|error| {
                    crate::Error::from_io(error, ErrorCode::ClosedCriticalStream)
                })?;
            }
        }
        Err(self.critical_stream_error())
    }
}

/// Only a registered decode owns cancellation; rejected and unpolled futures do not.
struct StreamDecoder<'a> {
    qpack: &'a ArcQpack,
    stream_id: u64,
}

impl Drop for StreamDecoder<'_> {
    fn drop(&mut self) {
        let result = {
            let mut shared = self.qpack.lock().unwrap();
            let Ok(qpack) = &mut *shared else {
                return;
            };
            qpack.decoder.cancel_registered(self.stream_id)
        };
        match result {
            Ok(wakes) => {
                for wake in wakes {
                    wake.wake();
                }
            }
            Err(error) => {
                self.qpack.on_connection_error(error);
            }
        }
    }
}

/// Channel producers run under QPACK state locks and must never block.
pub(super) fn instruction_send_error<T>(error: tokio::sync::mpsc::error::TrySendError<T>) -> Error {
    match error {
        tokio::sync::mpsc::error::TrySendError::Full(_) => {
            ErrorCode::ExcessiveLoad.reason("QPACK instruction queue is full")
        }
        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
            ErrorCode::ClosedCriticalStream.reason("QPACK instruction receiver is closed")
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
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

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::other("write failed")))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("flush failed")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("shutdown failed")))
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
            Err(ErrorCode::InternalError.reason("unused"))
        }

        async fn open_uni(&self) -> Result<Option<(u64, TestIo)>> {
            match self.mode {
                0 => Ok(None),
                1 => Ok(Some((2, TestIo))),
                _ => Err(ErrorCode::InternalError.reason("open failed")),
            }
        }

        async fn accept_uni(&self) -> Result<(u64, TestIo)> {
            Err(ErrorCode::InternalError.reason("unused"))
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

        let first = ErrorCode::QpackDecompressionFailed.reason("first");
        let second = ErrorCode::InternalError.reason("second");
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
        qpack
            .with_state(|state| {
                state.decoder.on_instruction(|_| Ok(()));
                Ok(())
            })
            .unwrap();
        let stream_error = ErrorCode::InternalError.reason("stream").stream();
        let stream_error = qpack.on_stream_error(0, stream_error.clone());
        assert!(matches!(stream_error, Error::Stream(_)));
        assert!(qpack.error().is_none());

        let connection_error = ErrorCode::InternalError.reason("connection");
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

        let (decoder_tx, decoder_rx) = tokio::sync::mpsc::channel(2);
        decoder_tx
            .send(vec![
                DecoderInstruction::SectionAcknowledgment(0),
                DecoderInstruction::StreamCancellation(4),
                DecoderInstruction::InsertCountIncrement(1),
            ])
            .await
            .unwrap();
        drop(decoder_tx);
        assert_eq!(
            qpack
                .write_decoder(decoder_rx, &mut tokio::io::sink())
                .await
                .unwrap_err()
                .code,
            ErrorCode::ClosedCriticalStream
        );

        let failed = ErrorCode::InternalError.reason("already failed");
        qpack.on_connection_error(failed.clone());
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
    async fn instruction_receivers_apply_valid_input_then_map_eof() {
        let settings = super::super::connection::Settings::new(4096, 128, 1).unwrap();
        let qpack = ArcQpack::new(&settings).unwrap();
        let feedback = Arc::new(Mutex::new(Vec::new()));
        let captured = feedback.clone();
        qpack
            .with_state(|state| {
                state.decoder.on_instruction(move |batch| {
                    captured.lock().unwrap().push(batch);
                    Ok(())
                });
                Ok(())
            })
            .unwrap();

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
            feedback.lock().unwrap()[0].as_slice(),
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
            let (_, decoder_rx) = tokio::sync::mpsc::channel(1);
            assert!(
                qpack
                    .sync_decoder_with(transport.clone(), decoder_rx)
                    .await
                    .is_err()
            );
            assert_eq!(transport.closes.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn configure_cancel_waiters_and_writer_io_errors_are_propagated() {
        let settings = super::super::connection::Settings::new(4096, 128, 1).unwrap();
        let qpack = ArcQpack::new(&settings).unwrap();
        qpack
            .with_state(|state| {
                state.decoder.on_instruction(|_| Ok(()));
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
        qpack.cancel(4).unwrap();
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
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(tx);
        assert_eq!(
            qpack
                .write_decoder(rx, &mut FailingWriter)
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
                .on_stream_error(0, ErrorCode::NoError.reason("cancel"))
                .code,
            ErrorCode::InternalError
        );
    }
}
