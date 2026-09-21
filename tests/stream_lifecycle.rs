mod support;

use std::time::Duration;

use qrecovery::recv::StopSending;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn drain_waits_for_read_after_write_shutdown() {
    let (client, server) = support::connection_pair();
    let (mut cw, mut cr) = client.open_bi().await.unwrap();
    let (mut sw, mut sr) = server.accept_bi().await.unwrap();
    cw.shutdown().await.unwrap();
    assert_eq!(sr.read(&mut [0]).await.unwrap(), 0);
    let mut drain = tokio::spawn(client.goaway());
    let peer_drain = tokio::spawn(server.goaway());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut drain)
            .await
            .is_err()
    );
    sw.write_all(b"response").await.unwrap();
    sw.shutdown().await.unwrap();
    let mut body = Vec::new();
    cr.read_to_end(&mut body).await.unwrap();
    assert_eq!(body, b"response");
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer_drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn read_cancel_also_cancels_write_and_completes_drain() {
    let (client, server) = support::connection_pair();
    let (_cw, mut cr) = client.open_bi().await.unwrap();
    let (sw, sr) = server.accept_bi().await.unwrap();
    cr.stop(0);
    let drain = tokio::spawn(client.goaway());
    let peer_drain = tokio::spawn(server.goaway());
    drop((sw, sr));
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer_drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn dropping_both_directions_wakes_drain() {
    let (client, server) = support::connection_pair();
    let local = client.open_bi().await.unwrap();
    let peer = server.accept_bi().await.unwrap();
    let mut drain = tokio::spawn(client.goaway());
    let peer_drain = tokio::spawn(server.goaway());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut drain)
            .await
            .is_err()
    );
    drop((local, peer));
    tokio::time::timeout(Duration::from_secs(1), drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer_drain)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
