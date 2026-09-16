//! Compression state for the two independent QPACK directions.

use std::sync::Arc;

use bytes::Bytes;
use qbase::varint::VARINT_MAX;

use super::frame;
use crate::{ErrorCode, Result};

mod codec;
pub(super) mod decoder;
pub(super) mod encoder;
mod table;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) use codec::field::Field;
#[cfg(test)]
pub(crate) use codec::field::{WriteFieldSection, be_field_section};
use decoder::Decoder;
use encoder::Encoder;

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

/// Owns the outgoing encoder and incoming decoder state.
pub struct Qpack {
    encoder: Encoder,
    decoder: Decoder,
}

impl Qpack {
    pub(super) fn new(
        settings: &super::connection::Settings,
    ) -> Result<(Arc<Self>, encoder::InstructionSource, decoder::Instructions)> {
        let (local, max_fields) = limits(&settings.local);
        let (encoder, instruction) = Encoder::new(Settings::default())?;
        let (decoder, feedback) =
            Decoder::new(local, frame::MAX_BUFFERED_FRAME_PAYLOAD, max_fields)?;
        Ok((Arc::new(Self { encoder, decoder }), instruction, feedback))
    }

    pub(super) async fn receive_encoder<R: tokio::io::AsyncRead + Unpin>(
        &self,
        recv: &mut R,
    ) -> Result<()> {
        self.decoder.receive(recv).await
    }

    pub(super) async fn receive_decoder<R: tokio::io::AsyncRead + Unpin>(
        &self,
        recv: &mut R,
    ) -> Result<()> {
        self.encoder.receive(recv).await
    }

    pub(crate) fn configure(&self, peer: Settings, max_fields: u64) -> Result<()> {
        self.encoder.configure(peer, max_fields)
    }

    #[cfg(test)]
    pub(crate) fn error(&self) -> Option<ErrorCode> {
        self.encoder.error()
    }

    pub(crate) fn close(&self, error: ErrorCode) -> ErrorCode {
        let error = self.encoder.close(error);
        self.decoder.close(error);
        error
    }

    pub(crate) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        self.encoder.encode(id, fields)
    }

    pub(crate) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        self.decoder.decode(id, payload).await
    }

    /// Cancel reception and synchronously submit any required QPACK feedback.
    pub fn cancel(&self, stream_id: u64) -> Result<()> {
        self.decoder.cancel(stream_id)
    }
}
