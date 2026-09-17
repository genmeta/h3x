use std::sync::Arc;

use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::BiStreams};
use crate::{
    ErrorCode, Result, Transport,
    protocol::qpack::{ArcQpack, MAX_PENDING_INSTRUCTION, instruction_send_error},
};

mod control;
mod settings;
mod stream_cursor;
pub use settings::Settings;
pub(crate) use stream_cursor::StreamCursor;

use crate::ErrorCode::H3_NO_ERROR;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// `goaway()` or a managing pool can drain requests and close the transport.
pub struct H3Connection<T: Transport> {
    pub(crate) transport: Arc<T>,
    pub(crate) cursor: Arc<StreamCursor>,
    local_settings: Arc<Settings>,
    // remote_settings
    // control {
    //   stetings
    //   cursor,
    //}
    // control.sync_control_with(transport);
    qpack: ArcQpack,
    control_stream: Arc<tokio::sync::Mutex<T::StreamWriter>>,
    bi_streams: Arc<BiStreams<T::StreamReader, T::StreamWriter>>,
}

impl<T: Transport> H3Connection<T> {
    /// Open the control stream and start SETTINGS and connection tasks.
    /// On failure or cancellation, transport cleanup follows its own drop semantics.
    pub async fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());

        let qpack = ArcQpack::new(&settings)?;
        let (encoder_tx, encoder_rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        let (decoder_tx, decoder_rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        qpack.with_state(|state| {
            state.encoder.on_instruction(move |batch| {
                encoder_tx.try_send(batch).map_err(instruction_send_error)
            });
            state.decoder.on_instruction(move |batch| {
                decoder_tx.try_send(batch).map_err(instruction_send_error)
            });
            Ok(())
        })?;
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { sync_encoder(&qpack, transport, encoder_rx).await }
        });
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            // qpack.sync_decoder_with(transport, decoder_rx)
            // setting.sync_setting()
            async move { sync_decoder(&qpack, transport, decoder_rx).await }
        });

        let control_stream = control::open_uni(transport.as_ref()).await?;
        let cursor = Arc::new(StreamCursor::new(transport.role()));
        let control = Arc::new(tokio::sync::Mutex::new(control_stream));

        let connection = Self {
            transport,
            local_settings: settings,
            qpack,
            cursor,
            control_stream: control.clone(),
            bi_streams: bi,
        };
        let control_stream = control.clone().lock_owned().await;
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
        {
            // TODDO: 原子处理这两行
            let (id, (mut recv, mut send)) = self.transport.open_bi().await?.ok_or_else(|| {
                ErrorCode::H3_STREAM_CREATION_ERROR
                    .reason("transport cannot open a bidirectional stream")
            })?;
            // Keep admission and registration atomic with respect to peer GOAWAY.
            // let cursor_remote = self.cursor.remote.lock().unwrap();
            // if let Err(error) = cursor_remote.not_goaway() {
            //     recv.stop(error.code.as_u64());
            //     send.cancel(error.code.as_u64());
            //     return Err(error);
            // }
            self.bi_streams.insert(id, recv, send)
        }
    }

    /// Exchange GOAWAY and wait for admitted requests before closing the transport.
    /// This future is not cancellation-safe during GOAWAY writes; await completion.
    pub async fn goaway(self) -> Result<()> {
        if let Err(error) = self.send_goaway().await {
            let _ = self
                .transport
                .close(error.reason.clone(), error.code.as_u64());
            return Err(error);
        }
        tokio::select! {
            biased;
            // 移除，通过流读写感知
            error = self.transport.terminated() => return Err(error),
            result = async {
                self.cursor.remote_goaway().await?;
                self.bi_streams.drained().await;
                Ok::<_, crate::Error>(())
            } => result?,
        }
        self.transport.close(String::new(), H3_NO_ERROR.as_u64())
    }

    pub(crate) fn is_reusable(&self) -> bool {
        self.cursor.local.lock().unwrap().not_goaway().is_ok()
            && self.cursor.remote.lock().unwrap().not_goaway().is_ok()
            && self.qpack.error().is_none()
    }

    pub(crate) async fn unusable(&self) {
        if !self.is_reusable() {
            return;
        }
        tokio::select! {
            _ = self.cursor.draining() => {},
            _ = self.cursor.remote_goaway() => {},
            _ = self.transport.terminated() => {},
            _ = self.qpack.failed() => {},
        }
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
        // 同 open_bi
        self.cursor.local.lock().unwrap().not_goaway()?;
        let (id, (mut read, mut write)) = self.transport.accept_bi().await?;
        let stream_id = qbase::varint::VarInt::try_from(id)
            .map(qbase::sid::StreamId::from)
            .map_err(|error| {
                ErrorCode::H3_ID_ERROR.reason(format!("invalid stream or push identifier: {error}"))
            });
        let mut local_cursor = self.cursor.local.lock().unwrap();
        if let Err(error) = stream_id.and_then(|id| local_cursor.accept(id)) {
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
            control_stream: self.control_stream.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}

pub(super) async fn sync_encoder<T: crate::Transport>(
    qpack: &ArcQpack,
    transport: Arc<T>,
    instructions: super::qpack::encoder::Instructions,
) -> Result<()> {
    tokio::select! {
        biased;
        error = qpack.failed() => Err(error),
        error = transport.terminated() => Err(error),
        result = async {
            let (_, mut send) = transport.open_uni().await?.ok_or_else(|| {
                ErrorCode::H3_STREAM_CREATION_ERROR.reason("unable to create the required stream")
            })?;
            qpack.write_encoder(instructions, &mut send).await
        } => result,
    }
    .map_err(|error| {
        let error = qpack.on_error(error);
        let _ = transport.close(error.reason.clone(), error.code.as_u64());
        error
    })
}

pub(super) async fn sync_decoder<T: crate::Transport>(
    qpack: &ArcQpack,
    transport: Arc<T>,
    instructions: super::qpack::decoder::Instructions,
) -> Result<()> {
    tokio::select! {
        biased;
        error = qpack.failed() => Err(error),
        error = transport.terminated() => Err(error),
        result = async {
            let (_, mut send) = transport.open_uni().await?.ok_or_else(|| {
                ErrorCode::H3_STREAM_CREATION_ERROR.reason("unable to create the required stream")
            })?;
            qpack.write_decoder(instructions, &mut send).await
        } => result,
    }
    .map_err(|error| {
        let error = qpack.on_error(error);
        let _ = transport.close(error.reason.clone(), error.code.as_u64());
        error
    })
}
