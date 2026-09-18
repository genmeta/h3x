use std::{future::poll_fn, pin::pin, task::Poll};

use super::*;

fn boundary() -> StreamId {
    StreamId::new(crate::Role::Server, Dir::Bi, 0)
}

#[tokio::test]
async fn writes_settings_then_goaway_and_keeps_stream_open() {
    let (mut send, mut peer) = tokio::io::duplex(1);
    let control = Control::new(Arc::new(super::super::Settings::default()));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let writing = async {
            control.write_settings(&mut send).await.unwrap();
            control.write_goaway(&mut send, boundary()).await.unwrap();
        };
        let reading = async {
            assert_eq!(peer.read_u8().await.unwrap(), StreamType::Control as u8);
            assert!(matches!(
                be_control(&mut peer).await.unwrap(),
                ControlFrame::Settings(_)
            ));
            let ControlFrame::Goaway(frame) = be_control(&mut peer).await.unwrap() else {
                panic!("expected GOAWAY")
            };
            assert_eq!(frame.payload.id.into_u64(), 1);
        };
        tokio::join!(writing, reading);
        let mut next = pin!(peer.read_u8());
        poll_fn(|cx| {
            assert!(next.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receive_processes_settings_and_validates_goaway_without_send_lock() {
    let control = Control::new(Arc::new(super::super::Settings::default()));
    let (mut recv, mut peer_send) = tokio::io::duplex(1024);
    let settings = super::super::Settings::default().0;
    let mut bytes = Vec::new();
    bytes.put_control(&ControlFrame::Settings(
        Frame::new(settings.clone()).unwrap(),
    ));
    for id in [4, 8] {
        bytes.put_control(&ControlFrame::Goaway(
            Frame::new(frame::Goaway {
                id: qbase::varint::VarInt::from_u32(id),
            })
            .unwrap(),
        ));
    }
    peer_send.write_all(&bytes).await.unwrap();
    let received = std::sync::Mutex::new(Vec::new());
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        control.receive_control(
            &mut recv,
            crate::Role::Client,
            |peer| {
                assert_eq!(peer, &settings);
                Ok(())
            },
            |id| {
                received.lock().unwrap().push(u64::from(id));
                Ok(())
            },
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::H3_ID_ERROR);
    assert_eq!(*received.lock().unwrap(), vec![4]);
    assert_eq!(control.peer_settings.get().unwrap().0, settings);
}

#[tokio::test]
async fn write_goaway_propagates_failure() {
    let (mut send, peer) = tokio::io::duplex(64);
    let control = Control::new(Arc::new(super::super::Settings::default()));
    control.write_settings(&mut send).await.unwrap();
    drop(peer);
    assert_eq!(
        control
            .write_goaway(&mut send, boundary())
            .await
            .unwrap_err()
            .code,
        ErrorCode::H3_CLOSED_CRITICAL_STREAM
    );
}
