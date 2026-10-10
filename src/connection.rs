use std::{
    future::poll_fn,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::{Poll, ready},
};

use qbase::varint::VarInt;
use qrecovery::{recv::StopSending, send::CancelStream};

use super::stream::{H3ReadStream, H3WriteStream, bi::ArcBiStreams};
use crate::{
    Error, ErrorCode, Result, Role, Transport,
    frame::{self, StreamType},
    qpack::{ArcQpack, MAX_PENDING_INSTRUCTION, instruction_send_error},
};

mod control;

use crate::ErrorCode::NoError;

fn reject_push_stream(role: Role) -> Error {
    match role {
        Role::Client => ErrorCode::IdError.connection("push received without MAX_PUSH_ID"),
        Role::Server => ErrorCode::StreamCreationError.connection("client created a push stream"),
    }
}

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// `goaway()` can drain requests and close the transport.
pub struct H3Connection<T: Transport> {
    pub(crate) transport: Arc<T>,
    qpack: ArcQpack,
    control: Arc<control::Control<T::StreamWriter>>,
    pub(crate) bi_streams: ArcBiStreams<T::StreamReader, T::StreamWriter>,
}

/// Called when a connection stops accepting new requests or its background driver exits.
/// The connection driver calls the callback once; it must not block or panic.
pub type UnreusableCallback<T> = Box<dyn Fn(&H3Connection<T>) + Send + 'static>;

impl<T: Transport> H3Connection<T> {
    /// Borrow the underlying transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Close the underlying transport immediately. Use `goaway` to drain
    /// admitted requests before closing.
    pub fn close(&self, reason: impl Into<String>, code: u64) -> Result<()> {
        self.transport.close(reason.into(), code)
    }

    /// Install the reuse-removal callback before starting the connection tasks.
    /// The driver invokes it on local/peer GOAWAY or connection termination.
    /// Pass `|_| {}` for a connection without a reuse pool.
    /// On failure or cancellation, transport cleanup follows its own drop semantics.
    pub fn new(
        transport: T,
        settings: Settings,
        on_unreusable: impl Fn(&Self) + Send + 'static,
    ) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = ArcBiStreams::new(transport.role());

        let qpack = ArcQpack::new(&settings)?;
        let (encoder_tx, encoder_rx) = tokio::sync::mpsc::channel(MAX_PENDING_INSTRUCTION);
        qpack.with_state(|state| {
            state.encoder.on_instruction(move |batch| {
                encoder_tx.try_send(batch).map_err(instruction_send_error)
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
            async move { qpack.sync_decoder_with(transport).await }
        });

        let control = Arc::new(control::Control::new(settings));
        tokio::spawn({
            let control = control.clone();
            let qpack = qpack.clone();
            let transport = transport.clone();
            async move { control.open_uni_and_send_setting(transport, qpack).await }
        });
        let connection = Self {
            transport,
            qpack,
            control,
            bi_streams: bi,
        };
        tokio::spawn({
            let connection = connection.clone();
            async move {
                let mut processing = pin!(connection.clone().accept_and_process_uni());
                let terminated = tokio::select! {
                    _ = &mut processing => true,
                    _ = connection.local_goaway() => false,
                    _ = connection.peer_goaway() => false,
                };
                on_unreusable(&connection);
                if !terminated {
                    processing.await;
                }
            }
        });
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &ArcQpack {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    /// Admission stops on local or peer GOAWAY and connection close.
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
            guard.local_not_goway()?;
            let (id, (mut recv, mut send)) =
                ready!(opening.as_mut().poll(cx))?.ok_or_else(|| {
                    ErrorCode::StreamCreationError
                        .connection("transport cannot open a bidirectional stream")
                })?;
            if let Err(error) = guard.remote_no_goway() {
                recv.stop(ErrorCode::RequestRejected.as_u64());
                send.cancel(ErrorCode::RequestRejected.as_u64());
                return Poll::Ready(Err(error));
            }
            let (read, write) =
                self.bi_streams
                    .insert(&mut guard, id, recv, send, self.qpack.clone());
            Poll::Ready(Ok((write, read)))
        })
        .await
    }

    /// Send GOAWAY and wait for admitted requests before closing the transport.
    /// Admission freezes immediately; the returned future writes and flushes GOAWAY,
    /// then waits for admitted requests without requiring a peer GOAWAY.
    /// Dropping the future leaves admission frozen without completing shutdown.
    pub fn goaway(self) -> impl Future<Output = Result<()>> + Send {
        let qpack = self.qpack.clone();
        let local_goaway = self.bi_streams.lock().unwrap().goaway(&qpack);
        async move {
            let _control_stream = tokio::select! {
                biased;
                error = self.qpack.failed() => return Err(error),
                result = async {
                    let local_goaway = local_goaway?;
                    let control_stream = self.control
                        .write_goaway(local_goaway, |error| self.fail_connection(error))
                        .await?;
                    let drained = self.bi_streams.drain();
                    drained.await;
                    Ok::<_, crate::Error>(control_stream)
                } => result?,
            };
            let result = self.transport.close(String::new(), NoError.as_u64());
            self.control.close();
            result
        }
    }

    pub(crate) fn local_goaway(&self) -> impl Future<Output = ()> + Send + use<T> {
        let notification = self.bi_streams.lock().unwrap().local_goaway();
        async move {
            notification.await;
        }
    }

    fn peer_goaway(&self) -> impl Future<Output = ()> + Send + use<T> {
        let notification = self.bi_streams.lock().unwrap().recv_goway();
        async move {
            let _ = notification.await;
        }
    }
}

impl<T: Transport> H3Connection<T> {
    /// Accept and register one peer bidirectional stream, returning (write, read).
    /// Admission stops on local GOAWAY or connection close; peer GOAWAY does not
    /// affect peer-initiated streams.
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
                    ErrorCode::InternalError
                        .connection(format!("transport returned an invalid stream ID: {error}"))
                });
            if let Err(error) = stream_id.and_then(|id| guard.accept(id)) {
                recv.stop(ErrorCode::RequestRejected.as_u64());
                send.cancel(ErrorCode::RequestRejected.as_u64());
                return Poll::Ready(Err(error));
            }
            let (read, write) =
                self.bi_streams
                    .insert(&mut guard, id, recv, send, self.qpack.clone());
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
        self.control.close();
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
                    return Err(ErrorCode::StreamCreationError
                        .connection(format!("duplicate peer {stream_type:?} stream")));
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
                StreamType::Push => Err(reject_push_stream(self.transport.role())),
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
            let _ = self
                .transport
                .close(error.reason.clone(), error.code.as_u64());
        }
    }

    /// Apply the failure observed by stream I/O and wake H3-level waiters.
    fn on_terminated(&self, error: Error) {
        let error = self.qpack.on_connection_error(error);
        self.bi_streams.lock().unwrap().close(error);
    }

    /// Apply a locally observed connection failure before transport termination is observed.
    fn fail_connection(&self, error: Error) -> Error {
        let error = self.qpack.on_connection_error(error);
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        self.bi_streams.lock().unwrap().close(error.clone());
        error
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

#[cfg(test)]
#[path = "../tests/unit/connection.rs"]
mod tests;

// Local connection settings.

/// Local settings advertised when constructing an HTTP/3 connection.
/// Extended CONNECT support is always advertised.
#[derive(Clone, Debug)]
pub struct Settings(pub(crate) frame::Settings);

impl Settings {
    pub fn new(
        max_field_section_size: u64,
        max_table_capacity: u64,
        blocked_streams: u64,
    ) -> Result<Self> {
        let values = [
            (frame::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1),
            (frame::SETTINGS_QPACK_MAX_TABLE_CAPACITY, max_table_capacity),
            (
                frame::SETTINGS_MAX_FIELD_SECTION_SIZE,
                max_field_section_size,
            ),
            (frame::SETTINGS_QPACK_BLOCKED_STREAMS, blocked_streams),
        ]
        .into_iter()
        .map(|(id, value)| {
            Ok((
                VarInt::from_u32(id),
                VarInt::try_from(value).map_err(|error| {
                    ErrorCode::SettingsError.connection(format!(
                        "SETTINGS value exceeds the QUIC variable-integer range: {error}"
                    ))
                })?,
            ))
        })
        .collect::<Result<_>>()?;
        Ok(Self(frame::Settings { values }))
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new(64 * 1024, 4096, 16).unwrap()
    }
}

#[cfg(test)]
#[path = "../tests/unit/connection/settings.rs"]
mod settings_tests;
