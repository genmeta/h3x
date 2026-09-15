use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use qrecovery::{recv::StopSending, send::CancelStream};

use super::{
    frame,
    qpack::Qpack,
    stream::{H3ReadStream, H3WriteStream, bi::BiStreams, control},
};
use crate::{Error, Result, Transport};

mod goaway;
mod settings;

pub(crate) use goaway::StreamCursor;
pub use settings::Settings;

/// An HTTP/3 connection whose control and QPACK streams are driven automatically.
/// Construct inside a Tokio runtime. Tasks run until the transport terminates.
/// Only an explicit goaway() drains requests and closes the transport.
pub struct H3Connection<T: Transport> {
    transport: Arc<T>,
    settings: Arc<Settings>,
    qpack: Arc<Qpack<T>>,
    cursor: Arc<StreamCursor>,
    goaway_write: qbase::ArcReceiving<Result<()>>,
    bi_streams: Arc<BiStreams<T::Recv, T::Send>>,
}

impl<T: Transport> H3Connection<T> {
    /// Start HTTP/3 using the supplied settings and the transport's endpoint role.
    /// Panics if called outside a Tokio runtime.
    pub fn new(transport: T, settings: Settings) -> Result<Self> {
        let transport = Arc::new(transport);
        let settings = Arc::new(settings);
        let bi = Arc::new(BiStreams::new());
        let qpack = Qpack::new(transport.clone(), &settings, bi.clone())?;
        let (cursor, goaway_write) = StreamCursor::new(
            transport.clone(),
            settings.clone(),
            qpack.clone(),
            bi.clone(),
        );
        let connection = Self {
            transport,
            settings,
            qpack,
            cursor,
            goaway_write,
            bi_streams: bi,
        };
        tokio::spawn(connection.clone().accept_uni());
        tokio::spawn(connection.clone().accept_bi());
        Ok(connection)
    }

    /// Compression state shared by messages on this connection.
    pub fn qpack(&self) -> &Arc<Qpack<T>> {
        &self.qpack
    }

    /// Open a bidirectional stream, returning (send, receive).
    pub async fn open_bi(
        &self,
    ) -> Result<(
        H3WriteStream<T::Send, T::Recv>,
        H3ReadStream<T::Recv, T::Send>,
    )> {
        let (id, (recv, send)) = self
            .transport
            .open_bi_stream()
            .await?
            .ok_or(Error::H3_STREAM_CREATION_ERROR)?;
        self.bi_streams.insert(id, recv, send)
    }

    /// Consume this connection and exchange GOAWAY with the peer.
    /// Writes GOAWAY, waits for the peer and admitted requests, then closes QUIC.
    pub async fn goaway(self) -> Result<()> {
        self.bi_streams.release_incoming();
        self.cursor.goaway()?;
        let transport = self.transport.as_ref();
        tokio::select! {
            biased;
            result = async {
                self.goaway_write.clone().await
                    .map_err(|_| Error::H3_INTERNAL_ERROR)?
                    .ok_or(Error::H3_INTERNAL_ERROR)??;
                self.cursor.peer_goaway().await?;
                self.bi_streams.drained(self.bi_streams.running()).await;
                transport.close(Error::H3_NO_ERROR.to_string(), Error::H3_NO_ERROR.as_u64())?;
                Ok::<_, Error>(())
            } => result?,
            error = transport.terminated() => return Err(error),
        }
        Ok(())
    }
}

impl<T: Transport> H3Connection<T> {
    async fn accept_uni(self) {
        let critical = Arc::new([
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicBool::new(false),
        ]);
        loop {
            let (_, mut recv) = match self.transport.accept_uni_stream().await {
                Ok(stream) => stream,
                Err(error) => {
                    let error = self.qpack.close(error);
                    self.bi_streams.close(error);
                    return;
                }
            };
            let connection = self.clone();
            let critical = critical.clone();
            tokio::spawn(async move {
                let [control_seen, encoder_seen, decoder_seen] = critical.as_ref();
                tokio::select! {
                    biased;
                    result = async {
                        // FIN/RESET is stream-local until its full type is known.
                        let stream_type = match frame::be_varint_or_eof(&mut recv).await {
                            Ok(Some(ty)) => ty.into_u64(),
                            Ok(None) => return Ok(()),
                            Err(error) if error.get_ref().is_some_and(|source| {
                                source.is::<qbase::frame::ResetStreamError>()
                            }) => return Ok(()),
                            Err(error) => return Err(Error::from(error)),
                        };
                        let seen = match stream_type {
                            0 => control_seen,
                            2 => encoder_seen,
                            3 => decoder_seen,
                            1 => return Err(Error::H3_ID_ERROR),
                            _ => { recv.stop(Error::H3_NO_ERROR.as_u64()); return Ok(()); }
                        };
                        if seen.swap(true, Ordering::AcqRel) { return Err(Error::H3_STREAM_CREATION_ERROR); }
                        match stream_type {
                            0 => control::receive_control(&mut recv, connection.transport.as_ref(), &connection.settings, &connection.qpack, &connection.cursor, &connection.bi_streams).await,
                            2 => connection.qpack.receive_encoder(&mut recv).await,
                            3 => connection.qpack.receive_decoder(&mut recv).await,
                            _ => unreachable!(),
                        }
                    } => if let Err(error) = result {
                        // Prefer an existing transport result over a new protocol error.
                        // The half stays alive throughout this task's failure handling.
                        tokio::select! {
                            biased;
                            ended = connection.transport.terminated() => {
                                let error = connection.qpack.close(ended);
                                connection.bi_streams.close(error);
                            },
                            _ = std::future::ready(()) => {
                                let error = connection.qpack.close(error);
                                let _ = connection.transport.close(error.to_string(), error.as_u64());
                                connection.bi_streams.close(error);
                            },
                        }
                    },
                    error = connection.transport.terminated() => {
                        let error = connection.qpack.close(error);
                        connection.bi_streams.close(error);
                    },
                }
            });
        }
    }

    async fn accept_bi(self) {
        loop {
            let (id, (mut recv, mut send)) = match self.transport.accept_bi_stream().await {
                Ok(stream) => stream,
                Err(error) => {
                    self.bi_streams.close_incoming(error);
                    return;
                }
            };
            let mut state = self.cursor.local.lock().unwrap();
            let stream_id = qbase::varint::VarInt::try_from(id)
                .map(qbase::sid::StreamId::from)
                .map_err(|_| Error::H3_ID_ERROR);
            if let Err(error) = stream_id.and_then(|id| state.accept(id)) {
                drop(state);
                recv.stop(Error::H3_REQUEST_REJECTED.as_u64());
                send.cancel(Error::H3_REQUEST_REJECTED.as_u64());
                self.bi_streams.close_incoming(error);
                return;
            }
            // Admission, registration, and delivery share the cursor lock with GOAWAY.
            if let Err(error) = self.bi_streams.insert_incoming(id, recv, send) {
                self.bi_streams.close_incoming(error);
                return;
            }
        }
    }
}

impl<T: Transport> Clone for H3Connection<T> {
    fn clone(&self) -> Self {
        Self {
            transport: self.transport.clone(),
            settings: self.settings.clone(),
            qpack: self.qpack.clone(),
            cursor: self.cursor.clone(),
            goaway_write: self.goaway_write.clone(),
            bi_streams: self.bi_streams.clone(),
        }
    }
}
