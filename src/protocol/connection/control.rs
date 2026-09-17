//! Peer unidirectional stream admission, dispatch, and task lifetime.
use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use qbase::sid::{Dir, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::H3Connection;
use crate::{
    Error, ErrorCode, Result, Transport,
    protocol::{
        frame::{self, Control, Frame, StreamType, WriteControl as _, be_control},
        qpack,
    },
};

pub(super) async fn open_uni<T: Transport>(transport: &T) -> Result<T::StreamWriter> {
    transport
        .open_uni()
        .await?
        .map(|(_, send)| send)
        .ok_or_else(|| {
            ErrorCode::H3_STREAM_CREATION_ERROR.with_reason("unable to open control stream")
        })
}

fn control_error(error: std::io::Error) -> Error {
    let error = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
        .map_or(&error, std::sync::Arc::as_ref);
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Error>())
        .cloned()
        .unwrap_or_else(|| ErrorCode::H3_CLOSED_CRITICAL_STREAM.with_reason(error.to_string()))
}

impl<T: Transport> H3Connection<T> {
    pub(super) async fn send_settings(
        self,
        mut send: tokio::sync::OwnedMutexGuard<T::StreamWriter>,
    ) {
        let result = async {
            let mut bytes = vec![StreamType::Control as u8];
            bytes.put_control(&Control::Settings(Frame::new(
                self.local_settings.0.clone(),
            )?));
            send.write_all(&bytes).await.map_err(control_error)?;
            send.flush().await.map_err(control_error)
        }
        .await;
        if let Err(error) = result {
            let _ = self.transport.close(error.reason, error.code.as_u64());
        }
    }

    pub(super) async fn send_goaway(&self) -> Result<()> {
        let id = self.cursor.local_goaway();
        let mut send = self.control_stream.lock().await;
        let mut bytes = Vec::new();
        bytes.put_control(&Control::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        send.write_all(&bytes).await.map_err(control_error)?;
        send.flush().await.map_err(control_error)
    }

    pub(super) async fn accept_and_process_uni(self) {
        let peer_critical_streams = Arc::new(AtomicU8::new(0));
        let error = loop {
            tokio::select! {
                biased;
                error = self.qpack.failed() => break error,
                error = self.transport.terminated() => break error,
                accepted = self.transport.accept_uni() => match accepted {
                    Ok((_, recv)) => {
                        tokio::spawn(self.clone().receive(recv, peer_critical_streams.clone()));
                    }
                    Err(error) => {
                        let _ = self.transport.close(error.reason, error.code.as_u64());
                        break self.transport.terminated().await;
                    }
                },
            }
        };
        let error = self.qpack.on_error(error);
        let _ = self
            .transport
            .close(error.reason.clone(), error.code.as_u64());
        self.on_terminated(error);
    }

    async fn receive(self, mut recv: T::StreamReader, peer_critical_streams: Arc<AtomicU8>) {
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
                        .with_reason(format!("duplicate peer {stream_type:?} stream")));
                }
            }
            match stream_type {
                StreamType::Control => self.receive_control(&mut recv).await,
                StreamType::Push => {
                    Err(ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier"))
                }
                StreamType::QpackEncoder => self.qpack.receive_encoder(&mut recv).await,
                StreamType::QpackDecoder => self.qpack.receive_decoder(&mut recv).await,
            }
        };
        let result = tokio::select! {
            biased;
            error = self.qpack.failed() => Err(error),
            error = self.transport.terminated() => Err(error),
            result = result => result,
        };
        // Retain the half until failure handling completes, including transport close.
        if let Err(error) = result {
            let error = self.qpack.on_error(error);
            let _ = self.transport.close(error.reason, error.code.as_u64());
        }
    }

    /// Apply the transport terminal reason and wake all H3-level waiters.
    pub(crate) fn on_terminated(&self, error: Error) {
        let error = self.qpack.on_error(error);
        self.bi_streams.close(error);
    }
}

impl<T: Transport> H3Connection<T> {
    async fn receive_control(&self, recv: &mut T::StreamReader) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(Control::Settings(frame)) => frame.payload,
            Err(error) if error.code != ErrorCode::H3_FRAME_UNEXPECTED => return Err(error),
            Err(error) => {
                return Err(ErrorCode::H3_MISSING_SETTINGS.with_reason(format!(
                    "control stream did not start with SETTINGS: {error}"
                )));
            }
            _ => {
                return Err(ErrorCode::H3_MISSING_SETTINGS
                    .with_reason("control stream did not start with SETTINGS"));
            }
        };
        let (peer, max_fields) = qpack::limits(&settings);
        self.qpack.configure(peer, max_fields)?;

        let role = self.transport.role();
        let mut last_goaway_id = None;
        loop {
            match be_control(recv).await? {
                Control::Goaway(frame) => {
                    let id = StreamId::from(frame.payload.id);
                    if id.role() != role
                        || id.dir() != Dir::Bi
                        || last_goaway_id.is_some_and(|previous| id > previous)
                    {
                        return Err(
                            ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                        );
                    }
                    last_goaway_id = Some(id);
                    // Freeze opens before scanning: registration uses the same lock.
                    self.cursor.receive_goaway(id);
                    for id in self.bi_streams.goaway(u64::from(id)) {
                        self.qpack.cancel(id)?;
                    }
                }
                // Server push is not supported.
                Control::MaxPushId(_) | Control::CancelPush(_) => {
                    return Err(
                        ErrorCode::H3_ID_ERROR.with_reason("invalid stream or push identifier")
                    );
                }
                Control::Unknown { length, .. } => {
                    let mut payload = (&mut *recv).take(length.into_u64());
                    tokio::io::copy(&mut payload, &mut tokio::io::sink())
                        .await
                        .map_err(|error| {
                            let error = error
                                .get_ref()
                                .and_then(|error| {
                                    error.downcast_ref::<std::sync::Arc<std::io::Error>>()
                                })
                                .map_or(&error, std::sync::Arc::as_ref);
                            error
                                .get_ref()
                                .and_then(|error| error.downcast_ref::<crate::Error>())
                                .cloned()
                                .unwrap_or_else(|| {
                                    let code = ErrorCode::H3_CLOSED_CRITICAL_STREAM;
                                    code.with_reason(error.to_string())
                                })
                        })?;
                    if payload.limit() != 0 {
                        return Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM
                            .with_reason("control stream ended while skipping an unknown frame"));
                    }
                }
                _ => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .with_reason("frame is not allowed in this context"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod admission_tests;

#[cfg(test)]
mod qpack_writer_tests;
