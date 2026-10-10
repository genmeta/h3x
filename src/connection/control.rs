//! SETTINGS and GOAWAY state and independent control-stream I/O.
use std::sync::{Arc, OnceLock};

use qbase::{
    ArcReceiving,
    sid::{Dir, StreamId},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

use crate::{
    Error, ErrorCode, Result,
    frame::{self, Control as ControlFrame, Frame, StreamType, WriteControl as _, be_control},
};

/// Local and peer connection settings.
pub(super) struct Control<W = tokio::io::Sink> {
    local_settings: Arc<super::Settings>,
    peer_settings: OnceLock<super::Settings>,
    settings_received: tokio::sync::Notify,
    stream: ArcReceiving<Arc<Mutex<W>>>,
}

impl<W> Control<W> {
    pub(super) async fn open_uni_and_send_setting<T: crate::Transport<StreamWriter = W>>(
        &self,
        transport: Arc<T>,
        qpack: crate::ArcQpack,
    ) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        async {
            let mut send = transport
                .open_uni()
                .await?
                .map(|(_, send)| send)
                .ok_or_else(|| {
                    ErrorCode::StreamCreationError.connection("unable to open control stream")
                })?;
            self.write_settings(&mut send).await?;
            self.stream.obtain(Arc::new(Mutex::new(send)));
            Ok::<_, Error>(())
        }
        .await
        .inspect_err(|error| {
            qpack.on_connection_error(error.clone());
            let _ = transport.close(error.reason.clone(), error.code.as_u64());
        })
    }

    pub(super) fn new(local_settings: Arc<super::Settings>) -> Self {
        Self {
            local_settings,
            peer_settings: OnceLock::new(),
            settings_received: tokio::sync::Notify::new(),
            stream: ArcReceiving::default(),
        }
    }

    pub(super) async fn write_goaway(
        &self,
        id: StreamId,
        mut on_io_failure: impl FnMut(Error) -> Error,
    ) -> Result<Arc<Mutex<W>>>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let stream = self
            .stream
            .clone()
            .await
            .map_err(|error| {
                ErrorCode::InternalError
                    .connection(format!("control stream wait cancelled: {error}"))
            })?
            .ok_or_else(|| {
                ErrorCode::InternalError.connection("local GOAWAY has already been sent")
            })?;

        let mut writer = stream.lock().await;
        let mut bytes = Vec::new();
        bytes.put_control(&ControlFrame::Goaway(Frame::new(frame::Goaway {
            id: id.into(),
        })?));
        writer
            .write_all(&bytes)
            .await
            .map_err(|error| Error::from_io(error, ErrorCode::ClosedCriticalStream).connection())
            .map_err(&mut on_io_failure)?;
        // Wait for transport acknowledgement before shutdown can close the
        // connection, even if the request drain is already done.
        writer
            .flush()
            .await
            .map_err(|error| Error::from_io(error, ErrorCode::ClosedCriticalStream).connection())
            .map_err(on_io_failure)?;
        Ok(Arc::clone(&stream))
    }

    pub(super) async fn peer_settings(&self) -> super::Settings {
        loop {
            // Construct before checking so notify_waiters cannot race with registration.
            let notified = self.settings_received.notified();
            if let Some(settings) = self.peer_settings.get() {
                return settings.clone();
            }
            notified.await;
        }
    }

    pub(super) fn close(&self) {
        self.stream.cancel();
    }

    pub(super) async fn write_settings<S: tokio::io::AsyncWrite + Unpin>(
        &self,
        send: &mut S,
    ) -> Result<()> {
        let mut bytes = vec![StreamType::Control as u8];
        bytes.put_control(&ControlFrame::Settings(Frame::new(
            self.local_settings.0.clone(),
        )?));
        // Transport writes drive transmission without a flush. SETTINGS only
        // needs to precede subsequent control frames, not wait for an ACK.
        send.write_all(&bytes)
            .await
            .map_err(|error| Error::from_io(error, ErrorCode::ClosedCriticalStream).connection())
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
            Err(error) if error.code != ErrorCode::FrameUnexpected => return Err(error),
            Err(error) => {
                return Err(ErrorCode::MissingSettings.connection(format!(
                    "control stream did not start with SETTINGS: {error}"
                )));
            }
            _ => {
                return Err(ErrorCode::MissingSettings
                    .connection("control stream did not start with SETTINGS"));
            }
        };
        on_settings(&settings)?;
        self.peer_settings
            .set(super::Settings(settings))
            .map_err(|_| ErrorCode::SettingsError.connection("peer settings already received"))?;

        self.settings_received.notify_waiters();

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
                            ErrorCode::IdError.connection("invalid stream or push identifier")
                        );
                    }
                    last_goaway_id = Some(id);
                    on_goaway(id)?;
                }
                // Server push is not supported.
                ControlFrame::MaxPushId(_) | ControlFrame::CancelPush(_) => {
                    return Err(ErrorCode::IdError.connection("invalid stream or push identifier"));
                }
                ControlFrame::Unknown { length, .. } => {
                    let mut payload = (&mut *recv).take(length.into_u64());
                    tokio::io::copy(&mut payload, &mut tokio::io::sink())
                        .await
                        .map_err(|error| {
                            crate::Error::from_io(error, ErrorCode::ClosedCriticalStream)
                        })?;
                    if payload.limit() != 0 {
                        return Err(ErrorCode::ClosedCriticalStream
                            .connection("control stream ended while skipping an unknown frame"));
                    }
                }
                _ => {
                    return Err(ErrorCode::FrameUnexpected
                        .connection("frame is not allowed in this context"));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/connection/control.rs"]
mod tests;
