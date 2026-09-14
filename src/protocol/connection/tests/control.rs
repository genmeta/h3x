use super::*;

#[tokio::test]
async fn invalid_control_frames_close_with_the_exact_protocol_error() {
    for (wire, expected) in [
        (vec![0, 7, 1, 0], Error::H3_MISSING_SETTINGS),
        (vec![0, 4, 2, 2, 0], Error::H3_SETTINGS_ERROR),
        (vec![0, 4, 0, 4, 0], Error::H3_FRAME_UNEXPECTED),
    ] {
        let (a, b) = pair();
        let connection = H3Connection::new(a);
        let (_, mut send) = b.open_uni_stream().await.unwrap().unwrap();
        let peer = async {
            // The autonomous driver may reject the frame before the peer finishes writing it.
            let _ = send.write_all(&wire).await;
            std::future::pending::<()>().await
        };
        tokio::pin!(peer);
        let error = tokio::select! { result=connection.closed()=>result.unwrap_err(), _=&mut peer=>unreachable!() };
        assert_eq!(error, expected, "control bytes: {wire:?}");
        assert_eq!(connection.error(), Some(expected));
        assert_eq!(connection.qpack().error(), Some(expected));
    }
}

#[tokio::test]
async fn duplicate_control_stream_closes_connection() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let peer = async {
        let (_, mut one) = b.open_uni_stream().await.unwrap().unwrap();
        one.write_all(&[0, 4, 0]).await.unwrap();
        let (_, mut two) = b.open_uni_stream().await.unwrap().unwrap();
        two.write_all(&[0]).await.unwrap();
        std::future::pending::<()>().await
    };
    tokio::pin!(peer);
    assert_eq!(
        tokio::select! { result=connection.closed()=>result, _=&mut peer=>unreachable!() },
        Err(Error::H3_STREAM_CREATION_ERROR)
    );
}

#[tokio::test]
async fn construction_drives_settings_without_any_connection_future() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    for _ in 0..1000 {
        if client.peer_settings_received() && server.peer_settings_received() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(client.peer_settings_received());
    assert!(server.peer_settings_received());
    // Exercise the public handle from a Send task, without polling closed/run.
    tokio::spawn(async move {
        let (send, recv) = client.open_bi().await.unwrap();
        let (peer_send, peer_recv) = server.accept_bi().await.unwrap();
        assert_eq!(send.stream_id(), peer_recv.stream_id());
        assert_eq!(recv.stream_id(), peer_send.stream_id());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn transport_role_selects_control_frame_rules() {
    for (role, frames, expected) in [
        (Role::Client, vec![7, 1, 3], Error::H3_ID_ERROR),
        // A client GOAWAY carries a push ID, so 3 is valid. A subsequent DATA is not.
        (
            Role::Server,
            vec![7, 1, 3, 0, 0],
            Error::H3_FRAME_UNEXPECTED,
        ),
        (Role::Server, vec![13, 1, 5, 13, 1, 4], Error::H3_ID_ERROR),
        (Role::Client, vec![13, 1, 5], Error::H3_FRAME_UNEXPECTED),
    ] {
        let (a, b) = pair();
        a.next_uni.set(if role == Role::Client { 2 } else { 3 });
        let connection = H3Connection::new(a);
        let peer = async {
            let (_, mut send) = b.open_uni_stream().await.unwrap().unwrap();
            let wire = [&[0, 4, 0][..], &frames].concat();
            let _ = send.write_all(&wire).await;
            std::future::pending::<()>().await;
        };
        let error = tokio::select! {
            result = connection.closed() => result.unwrap_err(),
            _ = peer => unreachable!(),
        };
        assert_eq!(error, expected, "role {role:?}");
    }
}
