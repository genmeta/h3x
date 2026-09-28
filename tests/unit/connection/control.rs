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
        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
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
        let control = Control::<tokio::io::Sink>::new(Arc::new(super::super::Settings::default()));
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
