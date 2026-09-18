use std::{
    future::poll_fn,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Poll, ready},
};

use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::ArcBiStreams};
use crate::{
    Error, ErrorCode, Result, Transport,
    frame::{self, StreamType},
    qpack::{ArcQpack, MAX_PENDING_INSTRUCTION, instruction_send_error},
};

mod control;
mod settings;
pub use settings::Settings;

use crate::ErrorCode::H3_NO_ERROR;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// `goaway()` can drain requests and close the transport.
pub struct H3Connection<T: Transport> {
    pub(crate) transport: Arc<T>,
    qpack: ArcQpack,
    control: Arc<control::Control>,
    bi_streams: ArcBiStreams<T::StreamReader, T::StreamWriter>,
}

impl<T: Transport> H3Connection<T> {
    /// Start the control, SETTINGS, and connection tasks.
    /// On failure or cancellation, transport cleanup follows its own drop semantics.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = ArcBiStreams::new(transport.role());

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
            guard.remote_no_goway()?;
            let (id, (recv, send)) = ready!(opening.as_mut().poll(cx))?.ok_or_else(|| {
                ErrorCode::H3_STREAM_CREATION_ERROR
                    .reason("transport cannot open a bidirectional stream")
            })?;
            let (read, write) = self.bi_streams.insert(&mut guard, id, recv, send);
            Poll::Ready(Ok((write, read)))
        })
        .await
    }

    /// Exchange GOAWAY and wait for admitted requests before closing the transport.
    /// Admission freezes immediately; await the returned future to complete shutdown.
    /// Submitted writes continue in the control task if this future is dropped.
    /// Await completion to finish the exchange and drain requests.
    pub fn goaway(self) -> impl Future<Output = Result<()>> + Send {
        let qpack = self.qpack.clone();
        let _ = self.bi_streams.lock().unwrap().goaway(&qpack);
        async move {
            tokio::select! {
                biased;
                error = self.qpack.failed() => return Err(error),
                result = async {
                    let remote_goaway = self.bi_streams.lock().unwrap().recv_goway();
                    remote_goaway.await.map_err(|error| {
                        ErrorCode::H3_INTERNAL_ERROR.reason(format!("GOAWAY wait cancelled: {error}"))
                    })?;
                    let drained = self.bi_streams.drain();
                    drained.await;
                    Ok::<_, crate::Error>(())
                } => result?,
            }
            self.transport.close(String::new(), H3_NO_ERROR.as_u64())
        }
    }

    pub(crate) fn local_goaway(&self) -> impl Future<Output = ()> + Send + use<T> {
        let notification = self.bi_streams.lock().unwrap().send_goaway();
        async move {
            notification.await;
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
            guard.local_not_goway()?;
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
            let (read, write) = self.bi_streams.insert(&mut guard, id, recv, send);
            Poll::Ready(Ok((write, read)))
        })
        .await
    }
}

impl<T: Transport> H3Connection<T> {
    async fn accept_and_process_uni(self) {
        let peer_critical_streams = Arc::new(AtomicU8::new(0));
        let error = loop {
            tokio::select! {
                biased;
                error = self.qpack.failed() => break error,
                accepted = self.transport.accept_uni() => match accepted {
                    Ok((_, recv)) => {
                        tokio::spawn(self.clone().receive_uni(recv, peer_critical_streams.clone()));
                    }
                    Err(error) => break error,
                },
            }
        };
        let error = self.qpack.on_connection_error(error);
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        self.on_terminated(error);
    }

    async fn receive_uni(self, mut recv: T::StreamReader, peer_critical_streams: Arc<AtomicU8>) {
        let result = async {
            let Some(stream_type) = frame::be_stream_type(&mut recv).await? else {
                return Ok(());
            };
            if matches!(
                stream_type,
                StreamType::Control | StreamType::QpackEncoder | StreamType::QpackDecoder
            ) {
                // Claim before reading any payload. Receive tasks share this atomic
                // bitset for the connection's lifetime; claims are never released.
                let bit = 1 << (stream_type as u8);
                if peer_critical_streams.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
                    return Err(ErrorCode::H3_STREAM_CREATION_ERROR
                        .reason(format!("duplicate peer {stream_type:?} stream")));
                }
            }
            match stream_type {
                StreamType::Control => {
                    self.control
                        .receive_control(
                            &mut recv,
                            self.transport.role(),
                            |settings| {
                                let (peer, max_fields) = crate::qpack::limits(settings);
                                self.qpack.configure(peer, max_fields)
                            },
                            |id| {
                                self.bi_streams
                                    .lock()
                                    .unwrap()
                                    .on_goaway(id, self.qpack.clone())
                            },
                        )
                        .await
                }
                StreamType::Push => {
                    Err(ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier"))
                }
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.qpack.failed() => Err(error),
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            let error = self.qpack.on_connection_error(error);
            let _ = self.transport.close(error.reason, error.code.as_u64());
        }
    }

    /// Apply the failure observed by stream I/O and wake H3-level waiters.
    fn on_terminated(&self, error: Error) {
        let error = self.qpack.on_connection_error(error);
        self.bi_streams.lock().unwrap().close(error);
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
