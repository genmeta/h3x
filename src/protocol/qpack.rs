//! Shared QPACK and instruction I/O. Encoder/Decoder own their directional protocol state.

use std::{
    collections::{HashSet, VecDeque},
    future::poll_fn,
    sync::Mutex,
    task::Poll,
};

use bytes::Bytes;
use instruction::{DecoderInstruction, EncoderInstruction};
use qbase::varint::VARINT_MAX;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Notify,
};

use super::frame;
use crate::{Error, Result};

mod decoder;
mod encoder;
mod field;
mod instruction;
mod table;

#[cfg(test)]
mod tests;

use decoder::Decoder;
use encoder::Encoder;
pub(crate) use field::Field;
use field::should_never_index;
#[cfg(test)]
pub(crate) use field::{WriteFieldSection, be_field_section};

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

/// Shared compression state only; no HTTP request lifecycle or decoded results.
pub struct Qpack {
    state: Mutex<State>,
    encoder_ready: Notify,
    decoder_ready: Notify,
    closed: Notify,
}

struct State {
    encoder: Encoder,
    decoder: Decoder,
    decoding: HashSet<u64>,
    error: Option<Error>,
    // Feedback can arrive while an encoder instruction is partially written.
    writing: Option<VecDeque<DecoderInstruction>>,
}

/// Release a decode registration if its future exits before normal cleanup.
struct DecodeGuard<'a> {
    qpack: &'a Qpack,
    stream_id: u64,
}

impl Drop for DecodeGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.qpack.state.lock().unwrap();
        // Completion or explicit cancellation already released this decode.
        if !state.decoding.remove(&self.stream_id) {
            return;
        }
        if state.error.is_some() {
            state.decoder.finish(self.stream_id);
        } else {
            let _ = state.decoder.cancel_stream(self.stream_id);
            self.qpack.decoder_ready.notify_one();
        }
    }
}

impl Qpack {
    pub(crate) fn new(local: Settings, peer: Settings, max_blocked_bytes: usize) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                encoder: Encoder::new(peer)?,
                decoder: Decoder::new(local, max_blocked_bytes)?,
                decoding: HashSet::new(),
                error: None,
                writing: None,
            }),
            encoder_ready: Notify::new(),
            decoder_ready: Notify::new(),
            closed: Notify::new(),
        })
    }

    pub(crate) fn configure(&self, peer: Settings, max_fields: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.encoder.apply_peer_settings(peer)?;
        state.encoder.max_field_section_size =
            max_fields.min(super::frame::MAX_BUFFERED_FRAME_PAYLOAD as u64);
        if peer.max_table_capacity != 0 {
            state
                .encoder
                .queue_instruction(EncoderInstruction::SetDynamicTableCapacity(
                    peer.max_table_capacity
                        .min(super::frame::MAX_BUFFERED_FRAME_PAYLOAD as u64),
                ))?;
        }
        self.encoder_ready.notify_one();
        Ok(())
    }

    pub(crate) fn local_limit(&self, limit: u64) {
        self.state.lock().unwrap().decoder.max_field_section_size = limit;
    }

    pub(crate) fn error(&self) -> Option<Error> {
        self.state.lock().unwrap().error
    }

    pub(crate) fn close(&self, error: Error) {
        let mut state = self.state.lock().unwrap();
        if state.error.is_none() {
            state.error = Some(error);
        }
        state.decoder.wake_all();
        self.closed.notify_waiters();
        self.encoder_ready.notify_one();
        self.decoder_ready.notify_one();
    }

    pub(crate) async fn terminated(&self) -> Error {
        loop {
            let changed = self.closed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(error) = self.error() {
                return error;
            }
            changed.await;
        }
    }

    pub(crate) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = state.error {
            return Err(error);
        }
        let result = state.encoder.encode(id, fields);
        self.encoder_ready.notify_one();
        result
    }

    pub(crate) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        if id > qbase::varint::VARINT_MAX {
            return Err(Error::H3_ID_ERROR);
        }
        let _guard = {
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.error {
                return Err(error);
            }
            if !state.decoding.insert(id) {
                return Err(Error::H3_REQUEST_CANCELLED);
            }
            DecodeGuard {
                qpack: self,
                stream_id: id,
            }
        };
        let (offset, prefix) = {
            let state = self.state.lock().unwrap();
            state
                .decoder
                .read_prefix(&payload)
                .map(|(rest, prefix)| (payload.len() - rest.len(), prefix))
        }
        .inspect_err(|error| self.close(*error))?;
        let result = poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if let Some(error) = state.error {
                return Poll::Ready(Err(error));
            }
            if !state.decoding.contains(&id) {
                return Poll::Ready(Err(Error::H3_REQUEST_CANCELLED));
            }
            let result = state
                .decoder
                .poll_decode(id, prefix, &payload[offset..], cx);
            if result.is_ready() {
                state.decoding.remove(&id);
                self.decoder_ready.notify_one();
            }
            result
        })
        .await;
        if let Err(error) = result {
            self.on_error(error);
        }
        result
    }

    /// Cancel reception on this stream and wake a pending decode.
    /// Call once when abandoning reception; dropping a pending decode future
    /// already releases its wait and queues cancellation.
    pub fn cancel(&self, stream_id: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.decoding.remove(&stream_id);
        state.decoder.cancel_stream(stream_id)?;
        self.decoder_ready.notify_one();
        Ok(())
    }

    pub(crate) fn on_error(&self, error: Error) {
        if !matches!(
            error,
            Error::H3_REQUEST_CANCELLED
                | Error::H3_REQUEST_REJECTED
                | Error::H3_REQUEST_INCOMPLETE
                | Error::H3_MESSAGE_ERROR
        ) {
            self.close(error);
        }
    }

    pub(crate) async fn receive_encoder<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = EncoderInstruction::read(recv).await?;
            self.state
                .lock()
                .unwrap()
                .decoder
                .on_encoder_instruction(instruction)?;
            self.decoder_ready.notify_one();
        }
    }

    pub(crate) async fn receive_decoder<R: AsyncRead + Unpin>(&self, recv: &mut R) -> Result<()> {
        loop {
            let instruction = DecoderInstruction::read(recv).await?;
            let mut state = self.state.lock().unwrap();
            if let Some(feedback) = &mut state.writing {
                if feedback.len()
                    >= crate::protocol::frame::MAX_BUFFERED_FRAME_PAYLOAD
                        / std::mem::size_of::<DecoderInstruction>()
                {
                    return Err(Error::H3_EXCESSIVE_LOAD);
                }
                feedback.push_back(instruction);
            } else {
                state.encoder.on_decoder_instruction(instruction)?;
            }
        }
    }

    pub(crate) async fn send_encoder<W: AsyncWrite + Unpin>(&self, send: &mut W) -> Result<()> {
        send.write_all(&[2])
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        loop {
            let ready = self.encoder_ready.notified();
            let next = {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.error {
                    return Err(error);
                }
                let next = state.encoder.next_instruction();
                if next.is_some() {
                    state.writing = Some(Default::default());
                }
                next
            };
            let Some(instruction) = next else {
                ready.await;
                continue;
            };
            send.write_all(&instruction.encode()?)
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            send.flush()
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            let mut state = self.state.lock().unwrap();
            state.encoder.on_instruction_sent(&instruction)?;
            for feedback in state.writing.take().unwrap() {
                state.encoder.on_decoder_instruction(feedback)?;
            }
        }
    }

    pub(crate) async fn send_decoder<W: AsyncWrite + Unpin>(&self, send: &mut W) -> Result<()> {
        send.write_all(&[3])
            .await
            .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        loop {
            let ready = self.decoder_ready.notified();
            let next = {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.error {
                    return Err(error);
                }
                state.decoder.next_instruction()
            };
            let Some(instruction) = next else {
                ready.await;
                continue;
            };
            send.write_all(&instruction.encode()?)
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
            send.flush()
                .await
                .map_err(|_| Error::H3_CLOSED_CRITICAL_STREAM)?;
        }
    }
}

impl Default for Qpack {
    fn default() -> Self {
        Self::new(Settings::default(), Settings::default(), 0).unwrap()
    }
}
