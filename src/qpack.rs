//! Compression state for the two independent QPACK directions.

use std::{
    future::poll_fn,
    io,
    pin::Pin,
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
            ErrorCode::ClosedCriticalStream.connection("critical HTTP/3 stream closed")
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
        if let Err(cancel_error) = self.cancel_decode(vec![id]) {
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

    pub fn cancel_decode(&self, ids: Vec<u64>) -> Result<()> {
        let wakes = self.with_state(|state| state.decoder.cancel(ids))?;
        for wake in wakes {
            wake.wake();
        }
        Ok(())
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
                    ErrorCode::StreamCreationError.connection("unable to create the required stream")
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
                    ErrorCode::StreamCreationError.connection("unable to create the required stream")
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
                if matches!(instruction, EncoderInstruction::SetDynamicTableCapacity(_)) {
                    writer.write_all(&buf).await.map_err(|error| {
                        crate::Error::from_io(error, ErrorCode::ClosedCriticalStream)
                    })?;
                } else {
                    self.write_insert(writer, &buf).await?;
                }
            }
        }
        Err(self.critical_stream_error())
    }

    /// Make the final bytes of an insertion and its completion count visible in
    /// the same order to decoder feedback. The lock is released whenever the
    /// transport cannot accept more bytes immediately.
    async fn write_insert<W: AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
        bytes: &[u8],
    ) -> Result<()> {
        let mut offset = 0;
        poll_fn(|cx| {
            let mut shared = self.lock().unwrap();
            let state = match &mut *shared {
                Ok(state) => state,
                Err(error) => return Poll::Ready(Err(error.clone())),
            };
            match Pin::new(&mut *writer).poll_write(cx, &bytes[offset..]) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(crate::Error::from_io(
                    error,
                    ErrorCode::ClosedCriticalStream,
                ))),
                Poll::Ready(Ok(0)) => Poll::Ready(Err(crate::Error::from_io(
                    io::ErrorKind::WriteZero.into(),
                    ErrorCode::ClosedCriticalStream,
                ))),
                Poll::Ready(Ok(written)) => {
                    offset += written;
                    if offset == bytes.len() {
                        state.encoder.record_insert_written();
                        Poll::Ready(Ok(()))
                    } else {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
        })
        .await
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
            ErrorCode::ExcessiveLoad.connection("QPACK instruction queue is full")
        }
        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
            ErrorCode::ClosedCriticalStream.connection("QPACK instruction receiver is closed")
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/qpack.rs"]
pub(crate) mod tests;
