//! SETTINGS and GOAWAY state and independent control-stream I/O.
use std::sync::{Arc, OnceLock};

use qbase::sid::{Dir, StreamId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    Error, ErrorCode, Result,
    frame::{self, Control as ControlFrame, Frame, StreamType, WriteControl as _, be_control},
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
        qpack: crate::ArcQpack,
        local_goaway: impl Future<Output = qbase::sid::StreamId> + Send,
    ) -> Result<()> {
        let mut send = None;
        // Retain the critical stream until transport close completes.
        tokio::select! {
            biased;
            error = qpack.failed() => Err(error),
            result = async {
                send = Some(transport.open_uni().await?.map(|(_, send)| send).ok_or_else(|| {
                    ErrorCode::H3_STREAM_CREATION_ERROR.reason("unable to open control stream")
                })?);
                let send = send.as_mut().unwrap();
                self.write_settings(send).await?;
                let id = local_goaway.await;
                self.write_goaway(send, id).await?;
                Err(qpack.failed().await)
            } => result,
        }
        .inspect_err(|error| {
            qpack.on_connection_error(error.clone());
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
        let control = Control::new(Arc::new(super::super::Settings::default()));
        control
            .write_settings(&mut tokio::io::sink())
            .await
            .unwrap();
        control
            .write_goaway(&mut tokio::io::sink(), StreamId::from(vi(4)))
            .await
            .unwrap();

        let (mut writer, reader) = tokio::io::duplex(1);
        drop(reader);
        assert_eq!(
            control.write_settings(&mut writer).await.unwrap_err().code,
            ErrorCode::H3_CLOSED_CRITICAL_STREAM
        );

        let protocol = ErrorCode::H3_INTERNAL_ERROR.reason("embedded");
        assert_eq!(
            control_error(std::io::Error::other(protocol.clone())),
            protocol
        );
        let wrapped = std::io::Error::other(Arc::new(std::io::Error::other(protocol.clone())));
        assert_eq!(control_error(wrapped), protocol);
    }

    #[tokio::test]
    async fn receive_control_accepts_settings_unknown_and_decreasing_goaway() {
        let control = Control::new(Arc::new(super::super::Settings::default()));
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
        assert_eq!(error.code, ErrorCode::H3_CLOSED_CRITICAL_STREAM);
        assert_eq!(*seen_settings.lock().unwrap(), 1);
        assert_eq!(*seen_goaway.lock().unwrap(), vec![8, 4]);
    }

    #[tokio::test]
    async fn receive_control_rejects_missing_duplicate_and_invalid_frames() {
        for wire in [vec![7, 1, 0], vec![0, 0], vec![42, 0]] {
            let control = Control::new(Arc::new(super::super::Settings::default()));
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
                ErrorCode::H3_MISSING_SETTINGS
            );
        }

        let control = Control::new(Arc::new(super::super::Settings::default()));
        let wire = settings_frame();
        assert_eq!(
            control
                .receive_control(
                    &mut wire.as_slice(),
                    crate::Role::Client,
                    |_| Err(ErrorCode::H3_SETTINGS_ERROR.reason("callback")),
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
                |_| Err(ErrorCode::H3_ID_ERROR.reason("goaway callback")),
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
            ErrorCode::H3_SETTINGS_ERROR
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
            let control = Control::new(Arc::new(super::super::Settings::default()));
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

        let control = Control::new(Arc::new(super::super::Settings::default()));
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
            ErrorCode::H3_CLOSED_CRITICAL_STREAM
        );
    }

    #[tokio::test]
    async fn control_stream_sync_writes_until_qpack_failure_and_closes_transport() {
        use crate::qpack::tests::TestTransport;

        let control = Control::new(Arc::new(super::super::Settings::default()));
        let qpack = crate::ArcQpack::new(&super::super::Settings::default()).unwrap();
        let failer = qpack.clone();
        tokio::spawn(async move {
            tokio::task::yield_now().await;
            failer.on_connection_error(ErrorCode::H3_INTERNAL_ERROR.reason("stop"));
        });
        let transport = Arc::new(TestTransport::new(1));
        assert_eq!(
            control
                .sync_control_with(transport.clone(), qpack, async { StreamId::from(vi(0)) })
                .await
                .unwrap_err()
                .code,
            ErrorCode::H3_INTERNAL_ERROR
        );
        assert_eq!(transport.close_count(), 1);

        let qpack = crate::ArcQpack::new(&super::super::Settings::default()).unwrap();
        let transport = Arc::new(TestTransport::new(0));
        assert_eq!(
            control
                .sync_control_with(transport.clone(), qpack, async { StreamId::from(vi(0)) })
                .await
                .unwrap_err()
                .code,
            ErrorCode::H3_STREAM_CREATION_ERROR
        );
        assert_eq!(transport.close_count(), 1);
    }
}
