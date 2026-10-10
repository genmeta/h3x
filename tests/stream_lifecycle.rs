mod support;

use std::time::Duration;

use h3x::{ErrorCode, ReadResponse};
use qrecovery::{recv::StopSending, send::CancelStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn peer_goaway_evicts_connection_and_preserves_incoming_streams() {
    let pool = h3x::Pool::new(|_: u8, _callback| async {
        Err::<h3x::H3Connection<support::Connection>, h3x::Error>(
            ErrorCode::InternalError.connection("factory should not run"),
        )
    });
    let callback = pool.on_unreusable(1);
    let (removed, mut removal) = tokio::sync::watch::channel(false);
    let (client, server) = support::connection_pair_with_callbacks(
        |_| {},
        move |connection| {
            callback(connection);
            removed.send_replace(true);
        },
    );
    assert!(pool.insert(1, server.clone()).is_ok());
    let (mut writer, _reader) = client.open_bi().await.unwrap();
    let client_drain = tokio::spawn(client.goaway());
    tokio::time::timeout(Duration::from_secs(1), removal.wait_for(|removed| *removed))
        .await
        .unwrap()
        .unwrap();
    assert!(!pool.remove(&1));
    assert_eq!(
        server.open_bi().await.err().unwrap().code,
        ErrorCode::RequestRejected
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        writer.write_all(b"still usable").await.unwrap();
        let (_writer, mut reader) = server.accept_bi().await.unwrap();
        let mut bytes = [0; 12];
        reader.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still usable");
    })
    .await
    .unwrap();
    client_drain.abort();
}

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
async fn no_error_stop_allows_an_early_response() {
    let (client, server) = support::connection_pair();
    let (_cw, mut cr) = client.open_bi().await.unwrap();
    let (mut sw, mut sr) = server.accept_bi().await.unwrap();

    sr.stop(ErrorCode::NoError.as_u64());
    sw.write_all(b"early response").await.unwrap();
    sw.shutdown().await.unwrap();

    let mut response = Vec::new();
    cr.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"early response");
}

#[tokio::test]
async fn no_error_cancel_allows_reading_the_response() {
    let (client, server) = support::connection_pair();
    let (cw, mut cr) = client.open_bi().await.unwrap();
    let (mut sw, _sr) = server.accept_bi().await.unwrap();

    (&cw).cancel(ErrorCode::NoError.as_u64());
    sw.write_all(b"response after upload cancellation")
        .await
        .unwrap();
    sw.shutdown().await.unwrap();

    let mut response = Vec::new();
    cr.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response after upload cancellation");
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

#[tokio::test]
async fn cancelling_response_headers_after_no_error_upload_stop_still_stops_peer_writer() {
    for poll_before_drop in [false, true] {
        let (client, server) = support::connection_pair();
        let (mut request_writer, response_reader) = client.open_bi().await.unwrap();
        let (mut response_writer, mut request_reader) = server.accept_bi().await.unwrap();
        request_reader.stop(ErrorCode::NoError.as_u64());
        let error = request_writer.write_all(b"upload").await.unwrap_err();
        assert_eq!(h3x::Error::from(error).code, ErrorCode::NoError);

        let mut reading =
            Box::pin(response_reader.read_response(http::Method::POST, client.qpack().clone()));
        if poll_before_drop {
            std::future::poll_fn(|cx| {
                assert!(reading.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        drop(reading);
        let error = response_writer.write_all(b"headers").await.unwrap_err();
        assert_eq!(h3x::Error::from(error).code, ErrorCode::RequestCancelled);
    }
}
