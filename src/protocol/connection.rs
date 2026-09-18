use std::{
    future::poll_fn,
    pin::pin,
    sync::{Arc, Mutex},
    task::{Poll, ready},
};

use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::BiStreams};
use crate::{
    ErrorCode, Result, Transport,
    protocol::qpack::{ArcQpack, MAX_PENDING_INSTRUCTION, instruction_send_error},
};

mod control;
mod settings;
mod uni;
pub use settings::Settings;

use crate::ErrorCode::H3_NO_ERROR;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// `goaway()` can drain requests and close the transport.
pub struct H3Connection<T: Transport> {
    pub(crate) transport: Arc<T>,
    qpack: ArcQpack,
    control: Arc<control::Control>,
    bi_streams: Arc<Mutex<BiStreams<T::StreamReader, T::StreamWriter>>>,
}

impl<T: Transport> H3Connection<T> {
    /// Start the control, SETTINGS, and connection tasks.
    /// On failure or cancellation, transport cleanup follows its own drop semantics.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(Mutex::new(BiStreams::new(transport.role())));

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
            async move { qpack.sync_encoder_with(transport, encoder_rx).await }
        });
        tokio::spawn({
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { qpack.sync_decoder_with(transport, decoder_rx).await }
        });

        let control = Arc::new(control::Control::new(settings));
        tokio::spawn({
            let control = control.clone();
            let qpack = qpack.clone();
            let transport = transport.clone();
            let local_goaway = bi.lock().unwrap().send_goaway();
            async move {
                control
                    .sync_control_with(transport, qpack, local_goaway)
                    .await
            }
        });
        let connection = Self {
            transport,
            qpack,
            control,
            bi_streams: bi,
        };
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
        let mut opening = pin!(self.transport.open_bi());
        // Pending releases the lock; Ready registers the stream before GOAWAY can run.
        poll_fn(|cx| {
            let mut guard = self.bi_streams.lock().unwrap();
            guard.can_open()?;
            let (id, (recv, send)) = ready!(opening.as_mut().poll(cx))?.ok_or_else(|| {
                ErrorCode::H3_STREAM_CREATION_ERROR
                    .reason("transport cannot open a bidirectional stream")
            })?;
            Poll::Ready(Ok(guard.insert(id, recv, send)))
        })
        .await
    }

    /// Exchange GOAWAY and wait for admitted requests before closing the transport.
    /// Admission freezes immediately; await the returned future to complete shutdown.
    /// Submitted writes continue in the control task if this future is dropped.
    /// Await completion to finish the exchange and drain requests.
    pub fn goaway(self) -> impl Future<Output = Result<()>> + Send {
        let qpack = self.qpack.clone();
        let _ = self.bi_streams.lock().unwrap().local_goaway(&qpack);
        async move {
            tokio::select! {
                biased;
                error = self.qpack.failed() => return Err(error),
                result = async {
                    let remote_goaway = self.bi_streams.lock().unwrap().recv_goway();
                    remote_goaway.await.map_err(|error| {
                        ErrorCode::H3_INTERNAL_ERROR.reason(format!("GOAWAY wait cancelled: {error}"))
                    })?;
                    let drained = self.bi_streams.lock().unwrap().drained();
                    drained.await;
                    self.bi_streams.lock().unwrap().cleanup();
                    Ok::<_, crate::Error>(())
                } => result?,
            }
            self.transport.close(String::new(), H3_NO_ERROR.as_u64())
        }
    }

    pub(crate) async fn terminated(&self) {
        let (local_goaway, remote_goaway) = {
            let guard = self.bi_streams.lock().unwrap();
            (guard.send_goaway(), guard.recv_goway())
        };
        tokio::select! {
            _ = local_goaway => {},
            _ = remote_goaway => {},
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
        let mut accepting = pin!(self.transport.accept_bi());
        poll_fn(|cx| {
            let mut guard = self.bi_streams.lock().unwrap();
            guard.can_accept()?;
            let (id, (mut recv, mut send)) = ready!(accepting.as_mut().poll(cx))?;
            let stream_id = qbase::varint::VarInt::try_from(id)
                .map(qbase::sid::StreamId::from)
                .map_err(|error| {
                    ErrorCode::H3_ID_ERROR
                        .reason(format!("invalid stream or push identifier: {error}"))
                });
            if let Err(error) = stream_id.and_then(|id| guard.accept(id)) {
                recv.stop(ErrorCode::H3_REQUEST_REJECTED.as_u64());
                send.cancel(ErrorCode::H3_REQUEST_REJECTED.as_u64());
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(guard.insert(id, recv, send)))
        })
        .await
    }
}

impl<T: Transport> Clone for H3Connection<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            qpack: self.qpack.clone(),
            control: self.control.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}
