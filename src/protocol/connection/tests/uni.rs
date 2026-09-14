use super::*;

#[tokio::test]
async fn slow_unclassified_stream_does_not_block_control_and_wrong_goaway_is_rejected() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let peer = async {
        let (_, mut slow) = b.open_uni_stream().await.unwrap().unwrap();
        slow.write_all(&[0x40]).await.unwrap();
        let (_, mut control) = b.open_uni_stream().await.unwrap().unwrap();
        control.write_all(&[0, 4, 0, 7, 1, 1]).await.unwrap();
        std::future::pending::<()>().await
    };
    tokio::pin!(peer);
    assert_eq!(
        tokio::select! { result=connection.closed()=>result, _=&mut peer=>unreachable!() },
        Err(Error::H3_ID_ERROR)
    );
    assert!(connection.peer_settings_received());
}
