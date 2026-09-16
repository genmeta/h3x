use std::sync::Arc;

use qrecovery::{recv::StopSending, send::CancelStream};

use super::{
    qpack::{MAX_PENDING_INSTRUCTION, Qpack},
    stream::{H3ReadStream, H3WriteStream, bi::BiStreams},
};
use crate::{ErrorCode, Result, Transport};

mod control;
mod settings;
mod stream_cursor;
pub use settings::Settings;
pub(crate) use stream_cursor::StreamCursor;

use crate::ErrorCode::H3_NO_ERROR;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// Only an explicit goaway() drains requests and closes the transport.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack>,
    cursor: Arc<StreamCursor>,
    bi_streams: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

impl<T: Transport> H3Connection<T> {
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());
        let qpack = Qpack::new(&settings)?;

        let (tx, rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        qpack
            .encoder
            .on_instruction(move |batch| tx.try_send(batch).map_err(instruction_send_error));
        tokio::spawn(qpack.encoder.sync(transport.clone(), rx));

        let (tx, rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        qpack
            .decoder
            .on_instruction(move |batch| tx.try_send(batch).map_err(instruction_send_error));
        tokio::spawn(qpack.decoder.sync(transport.clone(), rx));

        let cursor = Arc::new(StreamCursor::new(transport.role()));
        let connection = Self {
            transport,
            settings,
            qpack,
            cursor,
            bi_streams: bi,
        };

        tokio::spawn(connection.clone().sync_settings_and_goaway());
        tokio::spawn(connection.clone().accept_and_process_uni());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &Arc<Qpack> {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    /// Admission stops on peer GOAWAY or connection close, not local GOAWAY.
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        self.cursor.remote.lock().unwrap().not_goaway()?;
        let (id, (recv, send)) = self
            .transport
            .open_bi()
            .await?
            .ok_or(ErrorCode::H3_STREAM_CREATION_ERROR)?;
        self.bi_streams.insert(id, recv, send)
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// The control task writes GOAWAY, waits for the peer and admitted requests, then closes QUIC.
    /// Waits for transport termination; H3_NO_ERROR is success.
    /// Cancelling this wait does not cancel the triggered drain.
    pub async fn goaway(self) -> Result<()> {
        self.cursor.goaway()?;
        self.transport.close("".to_string(), H3_NO_ERROR.as_u64())?;
        Ok(())
    }
}

impl<T: Transport> H3Connection<T> {
    /// Accept and register one peer bidirectional stream, returning (write, read).
    /// Admission stops on local GOAWAY or connection close, not peer GOAWAY.
    /// The application drives acceptance; no background request queue is maintained.
    pub async fn accept_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::StreamWriter>,
        H3ReadStream<T::StreamReader>,
    )> {
        let (id, (mut read, mut write)) = self.transport.accept_bi().await?;
        let stream_id = qbase::varint::VarInt::try_from(id)
            .map(qbase::sid::StreamId::from)
            .map_err(|_| ErrorCode::H3_ID_ERROR);
        if let Err(error) = stream_id.and_then(|id| self.cursor.local.lock().unwrap().accept(id)) {
            read.stop(ErrorCode::H3_REQUEST_REJECTED.as_u64());
            write.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64());
            return Err(error);
        }
        // Keep admission and registration atomic with respect to local GOAWAY.
        self.bi_streams.insert(id, read, write)
    }
}

impl<T: Transport> Clone for H3Connection<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            settings: self.settings.clone(),
            qpack: self.qpack.clone(),
            cursor: self.cursor.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}

/// Channel producers run under QPACK state locks and must never block.
pub(super) fn instruction_send_error<T>(
    error: tokio::sync::mpsc::error::TrySendError<T>,
) -> ErrorCode {
    match error {
        tokio::sync::mpsc::error::TrySendError::Full(_) => ErrorCode::H3_EXCESSIVE_LOAD,
        tokio::sync::mpsc::error::TrySendError::Closed(_) => ErrorCode::H3_CLOSED_CRITICAL_STREAM,
    }
}
