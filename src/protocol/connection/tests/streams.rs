use super::*;

#[tokio::test]
async fn next_stream_reaps_completed_streams_while_handles_remain_alive() {
    use tokio::io::AsyncReadExt;
    for receive_first in [false, true] {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
        if !receive_first {
            send.shutdown().await.unwrap();
            // AsyncRead permits empty reads without having reached EOF.
            assert_eq!(recv.read(&mut []).await.unwrap(), 0);
            tokio::task::yield_now().await;
            assert_eq!(client.bi.len(), 1);
        }
        peer_send.write_all(b"ok").await.unwrap();
        peer_send.shutdown().await.unwrap();
        let mut response = Vec::new();
        recv.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"ok");
        if receive_first {
            tokio::task::yield_now().await;
            assert_eq!(client.bi.len(), 1);
            send.shutdown().await.unwrap();
        }
        let mut request = Vec::new();
        peer_recv.read_to_end(&mut request).await.unwrap();
        assert_eq!(client.bi.len(), 1);
        assert_eq!(server.bi.len(), 1);
        let next = client.open_bi().await.unwrap();
        let peer_next = server.accept_bi().await.unwrap();
        assert_eq!(client.bi.len(), 1);
        assert_eq!(server.bi.len(), 1);

        // Retained handles keep their terminal results; completion is idempotent.
        assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(peer_recv.read(&mut [0]).await.unwrap(), 0);
        send.shutdown().await.unwrap();
        peer_send.shutdown().await.unwrap();
        send.flush().await.unwrap();
        assert_eq!(
            send.write_all(b"x").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        drop((send, recv, peer_send, peer_recv, next, peer_next));
        client.bi.cleanup();
        server.bi.cleanup();
        tokio::task::yield_now().await;
        assert_eq!(client.bi.len(), 0);
        assert_eq!(server.bi.len(), 0);
    }
}

#[tokio::test]
async fn releasing_one_handle_preserves_the_other_half() {
    use tokio::io::AsyncReadExt;
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (send, mut recv) = client.open_bi().await.unwrap();
    let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
    drop(send);
    assert_eq!(client.bi.len(), 1);
    let mut bytes = [0; 2];
    assert_eq!(peer_recv.read(&mut bytes).await.unwrap(), 0);
    peer_send.write_all(b"ok").await.unwrap();
    recv.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ok");
    drop(recv);
    assert_eq!(client.bi.len(), 1);
    client.bi.cleanup();
    assert_eq!(client.bi.len(), 0);
    assert!(peer_send.write_all(b"x").await.is_err());
    drop((peer_recv, peer_send));
    server.bi.cleanup();
    assert_eq!(server.bi.len(), 0);
}

#[tokio::test]
async fn accept_returns_halves_before_any_http_bytes_arrive() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let halves = client.open_bi().await.unwrap();
    let id = halves.0.stream_id();
    let accept = server.accept_bi();
    tokio::pin!(accept);
    let peer_halves = poll_fn(|cx| match accept.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => panic!("accept must not parse a Request"),
    })
    .await
    .unwrap();
    assert_eq!(id, peer_halves.0.stream_id());
    assert_eq!(
        server.uni.goaway.state.lock().unwrap().accepted_boundary,
        id + 4
    );
    drop((halves, peer_halves));
}
