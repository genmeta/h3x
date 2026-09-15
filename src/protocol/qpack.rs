//! Shared QPACK state. Encoder/Decoder own their directional protocol state.

use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

use bytes::Bytes;
use instruction::EncoderInstruction;
use qbase::varint::VARINT_MAX;
use tokio::sync::mpsc;

use super::frame;
use crate::{Error, Result, Transport};

mod decoder;
mod encoder;
mod field;
pub(super) mod instruction;
mod string_literal;
mod table;

#[cfg(test)]
pub(crate) mod tests;

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

/// Directional compression resources and the transport they belong to.
pub struct Qpack<T: Transport> {
    pub(crate) transport: Arc<T>,
    pub(super) encoder: Mutex<Result<Encoder>>,
    pub(super) decoder: Mutex<Result<Decoder>>,
}

/// Release a decode registration if its future exits before normal cleanup.
struct DecodeGuard<'a, T: Transport> {
    qpack: &'a Qpack<T>,
    stream_id: u64,
}

impl<T: Transport> Drop for DecodeGuard<'_, T> {
    fn drop(&mut self) {
        let wakes = {
            let mut state = self.qpack.decoder.lock().unwrap();
            let Ok(decoder) = state.as_mut() else {
                return;
            };
            if !decoder.decoding.remove(&self.stream_id) {
                return;
            }
            decoder.cancel_stream(self.stream_id)
        };
        match wakes {
            Ok(wakes) => {
                for wake in wakes {
                    wake.wake();
                }
            }
            Err(error) => self.qpack.on_error(error),
        }
    }
}

impl<T: Transport> Qpack<T> {
    pub(crate) fn new(
        transport: Arc<T>,
        settings: &super::connection::Settings,
        bi: Arc<super::stream::bi::BiStreams<T::Recv, T::Send>>,
    ) -> Result<Arc<Self>> {
        let (local, max_fields) = limits(&settings.local);
        let (sender, receiver) = mpsc::channel(16);
        let mut decoder = Decoder::new(local, frame::MAX_BUFFERED_FRAME_PAYLOAD)?;
        decoder.max_field_section_size = max_fields;
        let qpack = Arc::new(Self {
            transport,
            encoder: Mutex::new(Ok(Encoder::new(Settings::default(), sender)?)),
            decoder: Mutex::new(Ok(decoder)),
        });
        tokio::spawn({
            let (qpack, bi) = (qpack.clone(), bi.clone());
            async move { qpack.send_encoder(receiver, &bi).await }
        });
        tokio::spawn({
            let qpack = qpack.clone();
            async move { qpack.send_decoder(&bi).await }
        });
        Ok(qpack)
    }

    pub(crate) fn configure(&self, peer: Settings, max_fields: u64) -> Result<()> {
        let mut state = self.encoder.lock().unwrap();
        let encoder = state.as_mut().map_err(|error| *error)?;
        encoder.apply_peer_settings(peer)?;
        encoder.max_field_section_size = max_fields.min(frame::MAX_BUFFERED_FRAME_PAYLOAD as u64);
        if peer.max_table_capacity != 0 {
            encoder.queue_instruction(EncoderInstruction::SetDynamicTableCapacity(
                peer.max_table_capacity
                    .min(frame::MAX_BUFFERED_FRAME_PAYLOAD as u64),
            ))?;
        }
        Ok(())
    }

    pub(crate) fn error(&self) -> Option<Error> {
        self.encoder.lock().unwrap().as_ref().err().copied()
    }

    pub(crate) fn close(&self, error: Error) -> Error {
        let (error, wakes) = {
            let mut encoder = self.encoder.lock().unwrap();
            let error = match *encoder {
                Err(error) => error,
                Ok(_) => {
                    *encoder = Err(error);
                    error
                }
            };
            let mut decoder = self.decoder.lock().unwrap();
            let wakes = match decoder.as_mut() {
                Ok(decoder) => decoder.take_waiters(),
                Err(_) => Vec::new(),
            };
            *decoder = Err(error);
            (error, wakes)
        };
        for wake in wakes {
            wake.wake();
        }
        error
    }

    pub(crate) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        let result = {
            let mut state = self.encoder.lock().unwrap();
            state.as_mut().map_err(|error| *error)?.encode(id, fields)
        };
        if let Err(error) = result {
            self.on_error(error);
        }
        result
    }

    pub(crate) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        let prefix = {
            let mut state = self.decoder.lock().unwrap();
            let decoder = state.as_mut().map_err(|error| *error)?;
            if !decoder.decoding.insert(id) {
                return Err(Error::H3_REQUEST_CANCELLED);
            }
            decoder
                .read_prefix(&payload)
                .map(|(rest, prefix)| (payload.len() - rest.len(), prefix))
        };
        let _guard = DecodeGuard {
            qpack: self,
            stream_id: id,
        };
        let (offset, prefix) = prefix.inspect_err(|error| self.on_error(*error))?;
        poll_fn(|cx| {
            let (result, wake) = {
                let mut state = self.decoder.lock().unwrap();
                let decoder = match state.as_mut() {
                    Ok(decoder) => decoder,
                    Err(error) => return Poll::Ready(Err(*error)),
                };
                if !decoder.decoding.contains(&id) {
                    return Poll::Ready(Err(Error::H3_REQUEST_CANCELLED));
                }
                let result = decoder.poll_decode(id, prefix, &payload[offset..], cx);
                if result.is_ready() {
                    decoder.decoding.remove(&id);
                }
                (result, decoder.take_writer())
            };
            if let Some(wake) = wake {
                wake.wake();
            }
            if let Poll::Ready(Err(error)) = result {
                self.on_error(error);
            }
            result
        })
        .await
    }

    /// Cancel reception and synchronously submit any required QPACK feedback.
    pub fn cancel(&self, stream_id: u64) -> Result<()> {
        let wakes = {
            let mut state = self.decoder.lock().unwrap();
            state
                .as_mut()
                .map_err(|error| *error)?
                .cancel_stream(stream_id)
        };
        match wakes {
            Ok(wakes) => {
                for wake in wakes {
                    wake.wake();
                }
                Ok(())
            }
            Err(error) => {
                self.on_error(error);
                Err(error)
            }
        }
    }

    pub(crate) fn on_error(&self, error: Error) {
        if !matches!(
            error,
            Error::H3_REQUEST_CANCELLED
                | Error::H3_REQUEST_REJECTED
                | Error::H3_REQUEST_INCOMPLETE
                | Error::H3_MESSAGE_ERROR
        ) {
            let error = self.close(error);
            let _ = self.transport.close(error.to_string(), error.as_u64());
        }
    }
}
