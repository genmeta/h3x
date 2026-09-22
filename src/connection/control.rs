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
        writer
            .flush()
            .await
            .map_err(|error| Error::from_io(error, ErrorCode::ClosedCriticalStream).connection())
            .map_err(on_io_failure)?;
        Ok(Arc::clone(&stream))
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
        send.write_all(&bytes)
            .await
            .map_err(|error| Error::from_io(error, ErrorCode::ClosedCriticalStream).connection())?;
        send.flush()
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
mod tests {
    use std::sync::{Arc, Mutex};

    use qbase::varint::VarInt;

    use super::*;

    fn vi(value: u64) -> VarInt {
        VarInt::try_from(value).unwrap()
    }

    fn settings_frame() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.put_control(&ControlFrame::Settings(
            Frame::new(super::super::Settings::default().0).unwrap(),
        ));
        bytes
    }

    #[tokio::test]
    async fn writes_settings_and_goaway_and_maps_closed_writer() {
        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
        control
            .write_settings(&mut tokio::io::sink())
            .await
            .unwrap();
        control
            .stream
            .obtain(Arc::new(tokio::sync::Mutex::new(tokio::io::sink())));
        control
            .write_goaway(StreamId::from(vi(4)), |error| error)
            .await
            .unwrap();

        let (mut writer, reader) = tokio::io::duplex(1);
        drop(reader);
        assert_eq!(
            control.write_settings(&mut writer).await.unwrap_err().code,
            ErrorCode::ClosedCriticalStream
        );

        let protocol = ErrorCode::InternalError.connection("embedded");
        assert_eq!(
            Error::from_io(
                std::io::Error::other(protocol.clone()),
                ErrorCode::ClosedCriticalStream,
            )
            .connection(),
            protocol
        );
        let wrapped = std::io::Error::other(Arc::new(std::io::Error::other(protocol.clone())));
        assert_eq!(
            Error::from_io(wrapped, ErrorCode::ClosedCriticalStream).connection(),
            protocol
        );
    }

    #[tokio::test]
    async fn receive_control_accepts_settings_unknown_and_decreasing_goaway() {
        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
        let mut wire = settings_frame();
        wire.put_control(&ControlFrame::Unknown {
            ty: vi(42),
            length: vi(3),
        });
        wire.extend_from_slice(b"ext");
        for id in [8, 4] {
            wire.put_control(&ControlFrame::Goaway(
                Frame::new(frame::Goaway { id: vi(id) }).unwrap(),
            ));
        }
        let seen_settings = Arc::new(Mutex::new(0));
        let seen_goaway = Arc::new(Mutex::new(Vec::new()));
        let settings_count = seen_settings.clone();
        let goaway_ids = seen_goaway.clone();
        let error = control
            .receive_control(
                &mut wire.as_slice(),
                crate::Role::Client,
                move |_| {
                    *settings_count.lock().unwrap() += 1;
                    Ok(())
                },
                move |id| {
                    goaway_ids.lock().unwrap().push(u64::from(id));
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ClosedCriticalStream);
        assert_eq!(*seen_settings.lock().unwrap(), 1);
        assert_eq!(*seen_goaway.lock().unwrap(), vec![8, 4]);
    }

    #[tokio::test]
    async fn receive_control_rejects_missing_duplicate_and_invalid_frames() {
        for wire in [vec![7, 1, 0], vec![0, 0], vec![42, 0]] {
            let control =
                Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
            assert_eq!(
                control
                    .receive_control(
                        &mut wire.as_slice(),
                        crate::Role::Client,
                        |_| Ok(()),
                        |_| Ok(()),
                    )
                    .await
                    .unwrap_err()
                    .code,
                ErrorCode::MissingSettings
            );
        }

        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
        let wire = settings_frame();
        assert_eq!(
            control
                .receive_control(
                    &mut wire.as_slice(),
                    crate::Role::Client,
                    |_| Err(ErrorCode::SettingsError.connection("callback")),
                    |_| Ok(()),
                )
                .await
                .unwrap_err()
                .reason,
            "callback"
        );

        let mut first = settings_frame();
        first.put_control(&ControlFrame::Goaway(
            Frame::new(frame::Goaway { id: vi(0) }).unwrap(),
        ));
        control
            .receive_control(
                &mut first.as_slice(),
                crate::Role::Client,
                |_| Ok(()),
                |_| Err(ErrorCode::IdError.connection("goaway callback")),
            )
            .await
            .unwrap_err();
        assert_eq!(
            control
                .receive_control(
                    &mut settings_frame().as_slice(),
                    crate::Role::Client,
                    |_| Ok(()),
                    |_| Ok(()),
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::SettingsError
        );

        for invalid in [
            ControlFrame::Goaway(Frame::new(frame::Goaway { id: vi(1) }).unwrap()),
            ControlFrame::MaxPushId(Frame::new(frame::MaxPushId { push_id: vi(0) }).unwrap()),
            ControlFrame::CancelPush(
                Frame::new(frame::CancelPush {
                    push_id: StreamId::from(vi(0)),
                })
                .unwrap(),
            ),
            ControlFrame::Settings(Frame::new(frame::Settings::default()).unwrap()),
        ] {
            let control =
                Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
            let mut wire = settings_frame();
            wire.put_control(&invalid);
            assert!(
                control
                    .receive_control(
                        &mut wire.as_slice(),
                        crate::Role::Client,
                        |_| Ok(()),
                        |_| Ok(()),
                    )
                    .await
                    .is_err()
            );
        }

        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
        let mut truncated_unknown = settings_frame();
        truncated_unknown.put_control(&ControlFrame::Unknown {
            ty: vi(42),
            length: vi(2),
        });
        truncated_unknown.push(1);
        assert_eq!(
            control
                .receive_control(
                    &mut truncated_unknown.as_slice(),
                    crate::Role::Client,
                    |_| Ok(()),
                    |_| Ok(()),
                )
                .await
                .unwrap_err()
                .code,
            ErrorCode::ClosedCriticalStream
        );
    }

    #[tokio::test]
    async fn control_stream_initialization_stores_writer_and_maps_failures() {
        use crate::qpack::tests::{TestIo, TestTransport};

        let control = Arc::new(Control::<TestIo>::new(Arc::new(
            super::super::Settings::default(),
        )));
        let writing = tokio::spawn({
            let control = control.clone();
            async move {
                control
                    .write_goaway(StreamId::from(vi(0)), |error| error)
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!writing.is_finished());

        let qpack = crate::ArcQpack::new(&super::super::Settings::default()).unwrap();
        let transport = Arc::new(TestTransport::new(1));
        control
            .open_uni_and_send_setting(transport.clone(), qpack)
            .await
            .unwrap();
        writing.await.unwrap().unwrap();
        assert_eq!(transport.close_count(), 0);

        let control = Control::new(Arc::new(super::super::Settings::default()));
        let qpack = crate::ArcQpack::new(&super::super::Settings::default()).unwrap();
        let transport = Arc::new(TestTransport::new(0));
        assert_eq!(
            control
                .open_uni_and_send_setting(transport.clone(), qpack)
                .await
                .unwrap_err()
                .code,
            ErrorCode::StreamCreationError
        );
        assert_eq!(transport.close_count(), 1);
    }
}
