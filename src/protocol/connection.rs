use std::sync::Arc;

use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::BiStreams};
use crate::{ErrorCode, Result, Transport, protocol::qpack::ArcQpack};

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
    pub(crate) transport: Arc<T>,
    local_settings: Arc<Settings>,
    qpack: ArcQpack,
    cursor: Arc<StreamCursor<T::StreamWriter>>,
    bi_streams: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

impl<T: Transport> H3Connection<T> {
    /// Open the control stream and start SETTINGS and connection tasks.
    pub async fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());
        let (qpack, encoder_rx, decoder_rx) = ArcQpack::new(&settings, transport.clone())?;

        let control_stream = control::open_uni(transport.as_ref()).await?;
        let cursor = Arc::new(StreamCursor::new(transport.role(), control_stream));
        let control_stream = cursor.control_stream.clone().lock_owned().await;

        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { qpack.sync_encoder(transport, encoder_rx).await }
        });
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { qpack.sync_decoder(transport, decoder_rx).await }
        });

        let connection = Self {
            transport,
            local_settings: settings,
            qpack,
            cursor,
            bi_streams: bi,
        };

        tokio::spawn(connection.clone().send_settings(control_stream));
        tokio::spawn(connection.clone().accept_and_process_uni());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &ArcQpack {
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
        let (id, (mut recv, mut send)) = self.transport.open_bi().await?.ok_or_else(|| {
            ErrorCode::H3_STREAM_CREATION_ERROR
                .with_reason("transport cannot open a bidirectional stream")
        })?;
        // Recheck after the await and hold admission through registration.
        if let Err(error) = self.cursor.remote.lock().unwrap().not_goaway() {
            recv.stop(error.code.as_u64());
            send.cancel(error.code.as_u64());
            return Err(error);
        }
        self.bi_streams.insert(id, recv, send)
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// Wait for GOAWAY to be flushed, the peer GOAWAY, and admitted requests before closing QUIC.
    /// This future is not cancellation-safe during GOAWAY writes; await it to completion.
    pub async fn goaway(self) -> Result<()> {
        if let Err(error) = self.send_goaway().await {
            let _ = self
                .transport
                .close(error.reason.clone(), error.code.as_u64());
            return Err(error);
        }
        self.cursor.remote_goaway().await?;
        self.bi_streams.drained().await;
        self.transport.close(String::new(), H3_NO_ERROR.as_u64())
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
        self.cursor.local.lock().unwrap().not_goaway()?;
        let (id, (mut read, mut write)) = self.transport.accept_bi().await?;
        let stream_id = qbase::varint::VarInt::try_from(id)
            .map(qbase::sid::StreamId::from)
            .map_err(|error| {
                ErrorCode::H3_ID_ERROR
                    .with_reason(format!("invalid stream or push identifier: {error}"))
            });
        let mut admission = self.cursor.local.lock().unwrap();
        if let Err(error) = stream_id.and_then(|id| admission.accept(id)) {
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
            local_settings: self.local_settings.clone(),
            qpack: self.qpack.clone(),
            cursor: self.cursor.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}
