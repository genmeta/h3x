//! Connection-level coordination for the two independent QPACK directions.

use std::sync::Arc;

use bytes::Bytes;
use qbase::varint::VARINT_MAX;

use super::frame;
use crate::{Error, Result, Transport};

mod codec;
mod decoder;
mod encoder;
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

/// Owns the outgoing encoder and incoming decoder; each direction drives its own I/O.
pub struct Qpack<T: Transport> {
    transport: Arc<T>,
    encoder: Encoder,
    decoder: Decoder,
}

impl<T: Transport> Qpack<T> {
    pub(crate) fn new(
        transport: Arc<T>,
        settings: &super::connection::Settings,
        bi: Arc<super::stream::bi::BiStreams<T::StreamReader, T::StreamWriter>>,
    ) -> Result<Arc<Self>> {
        let (local, max_fields) = limits(&settings.local);
        let (encoder, receiver, completed) = Encoder::new(Settings::default())?;
        let (decoder, feedback, insert_count) =
            Decoder::new(local, frame::MAX_BUFFERED_FRAME_PAYLOAD, max_fields)?;
        let qpack = Arc::new(Self {
            transport,
            encoder,
            decoder,
        });
        qpack.encoder.start(&qpack, receiver, completed, bi.clone());
        qpack.decoder.start(&qpack, feedback, insert_count, bi);
        Ok(qpack)
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
    pub(crate) fn error(&self) -> Option<Error> {
        self.encoder.error()
    }

    pub(crate) fn close(&self, error: Error) -> Error {
        let error = self.encoder.close(error);
        self.decoder.close(error);
        error
    }

    pub(crate) fn encode(&self, id: u64, fields: Vec<Field>) -> Result<Bytes> {
        self.encoder
            .encode(id, fields)
            .inspect_err(|error| self.on_error(*error))
    }

    pub(crate) async fn decode(&self, id: u64, payload: Bytes) -> Result<Vec<Field>> {
        self.decoder
            .decode(id, payload)
            .await
            .inspect_err(|error| self.on_error(*error))
    }

    /// Cancel reception and synchronously submit any required QPACK feedback.
    pub fn cancel(&self, stream_id: u64) -> Result<()> {
        self.decoder
            .cancel(stream_id)
            .inspect_err(|error| self.on_error(*error))
    }

    fn fail(
        &self,
        error: Error,
        bi: &super::stream::bi::BiStreams<T::StreamReader, T::StreamWriter>,
    ) {
        let error = self.close(error);
        let _ = self.transport.close(error.to_string(), error.as_u64());
        bi.close(error);
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
