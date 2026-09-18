//! SETTINGS and GOAWAY state and independent control-stream I/O.
use std::sync::{Arc, OnceLock};

use qbase::sid::{Dir, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Error, ErrorCode, Result,
    protocol::frame::{
        self, Control as ControlFrame, Frame, StreamType, WriteControl as _, be_control,
    },
};

fn control_error(error: std::io::Error) -> Error {
    let error = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<std::sync::Arc<std::io::Error>>())
        .map_or(&error, std::sync::Arc::as_ref);
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Error>())
        .cloned()
        .unwrap_or_else(|| ErrorCode::H3_CLOSED_CRITICAL_STREAM.reason(error.to_string()))
}

/// Local and peer connection settings.
pub(super) struct Control {
    local_settings: Arc<super::Settings>,
    peer_settings: OnceLock<super::Settings>,
}

impl Control {
    pub(super) async fn sync_control_with<T: crate::Transport>(
        &self,
        transport: Arc<T>,
        local_goaway: impl Future<Output = qbase::sid::StreamId> + Send,
        on_written: impl Fn(Result<()>) + Send,
    ) -> Result<()> {
        let mut send = None;
        let mut written = false;
        let result = tokio::select! {
            biased;
            error = transport.terminated() => Err(error),
            result = async {
                send = Some(transport.open_uni().await?.map(|(_, send)| send).ok_or_else(|| {
                    ErrorCode::H3_STREAM_CREATION_ERROR.reason("unable to open control stream")
                })?);
                let send = send.as_mut().unwrap();
                self.write_settings(send).await?;
                let id = local_goaway.await;
                self.write_goaway(send, id).await?;
                written = true;
                on_written(Ok(()));
                Err(transport.terminated().await)
            } => result,
        };
        // Retain the critical stream until transport close completes.
        result.inspect_err(|error| {
            if !written {
                on_written(Err(error.clone()));
            }
            let _ = transport.close(error.reason.clone(), error.code.as_u64());
        })
    }

    pub(super) fn new(local_settings: Arc<super::Settings>) -> Self {
        Self {
            local_settings,
            peer_settings: OnceLock::new(),
        }
    }

    pub(super) async fn write_settings<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        send: &mut W,
    ) -> Result<()> {
        let mut bytes = vec![StreamType::Control as u8];
        bytes.put_control(&ControlFrame::Settings(Frame::new(
            self.local_settings.0.clone(),
        )?));
        send.write_all(&bytes).await.map_err(control_error)?;
        send.flush().await.map_err(control_error)
    }

    pub(super) async fn write_goaway<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        send: &mut W,
        id: StreamId,
    ) -> Result<()> {
        let mut bytes = Vec::new();
        bytes.put_control(&ControlFrame::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        send.write_all(&bytes).await.map_err(control_error)?;
        send.flush().await.map_err(control_error)
    }

    pub(super) async fn receive_control<R: tokio::io::AsyncRead + Unpin>(
        &self,
        recv: &mut R,
        role: crate::Role,
        on_settings: impl Fn(&frame::Settings) -> Result<()>,
        on_goaway: impl Fn(StreamId) -> Result<()>,
    ) -> Result<()> {
        let settings = match be_control(recv).await {
            Ok(ControlFrame::Settings(frame)) => frame.payload,
            Err(error) if error.code != ErrorCode::H3_FRAME_UNEXPECTED => return Err(error),
            Err(error) => {
                return Err(ErrorCode::H3_MISSING_SETTINGS.reason(format!(
                    "control stream did not start with SETTINGS: {error}"
                )));
            }
            _ => {
                return Err(ErrorCode::H3_MISSING_SETTINGS
                    .reason("control stream did not start with SETTINGS"));
            }
        };
        on_settings(&settings)?;
        self.peer_settings
            .set(super::Settings(settings))
            .map_err(|_| ErrorCode::H3_SETTINGS_ERROR.reason("peer settings already received"))?;

        let mut last_goaway_id = None;
        loop {
            match be_control(recv).await? {
                ControlFrame::Goaway(frame) => {
                    let id = StreamId::from(frame.payload.id);
                    if id.role() != role
                        || id.dir() != Dir::Bi
                        || last_goaway_id.is_some_and(|previous| id > previous)
                    {
                        return Err(
                            ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier")
                        );
                    }
                    last_goaway_id = Some(id);
                    on_goaway(id)?;
                }
                // Server push is not supported.
                ControlFrame::MaxPushId(_) | ControlFrame::CancelPush(_) => {
                    return Err(ErrorCode::H3_ID_ERROR.reason("invalid stream or push identifier"));
                }
                ControlFrame::Unknown { length, .. } => {
                    let mut payload = (&mut *recv).take(length.into_u64());
                    tokio::io::copy(&mut payload, &mut tokio::io::sink())
                        .await
                        .map_err(|error| {
                            crate::Error::from_io(error, ErrorCode::H3_CLOSED_CRITICAL_STREAM)
                        })?;
                    if payload.limit() != 0 {
                        return Err(ErrorCode::H3_CLOSED_CRITICAL_STREAM
                            .reason("control stream ended while skipping an unknown frame"));
                    }
                }
                _ => {
                    return Err(ErrorCode::H3_FRAME_UNEXPECTED
                        .reason("frame is not allowed in this context"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
