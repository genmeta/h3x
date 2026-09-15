use super::*;

#[tokio::test]
async fn peer_stop_is_consumed_when_the_message_future_starts() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut request_send, _response_recv) = client.open_bi().await.unwrap();
        let (response_send, mut request_recv) = server.accept_bi().await.unwrap();
        let (stop, stopped) = oneshot::channel();
        let response_send = response_send.with_stop_signal(async move { stopped.await.unwrap() });
        let response = server::Response::<Bytes>::default().streaming(1);
        let mut producer = response.clone();
        producer.write(b"x").await.unwrap();
        let sending = server::respond(
            response,
            response_send,
            server.qpack().clone(),
            &http::Method::GET,
        );
        stop.send(Error::H3_REQUEST_REJECTED).unwrap();
        tokio::task::yield_now().await;
        let mut pending_write = Box::pin(producer.write(b"y"));
        poll_fn(|cx| {
            assert!(pending_write.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(sending.await, Err(Error::H3_REQUEST_REJECTED));
        assert_eq!(pending_write.await, Err(Error::H3_REQUEST_REJECTED));
        assert_eq!(producer.finish().await, Err(Error::H3_REQUEST_REJECTED));
        request_send.write_all(b"ok").await.unwrap();
        let mut bytes = [0; 2];
        request_recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
        assert!(server.error().is_none());
    })
    .await
    .unwrap();
}

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
    let peer_halves = tokio::time::timeout(std::time::Duration::from_secs(1), server.accept_bi())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(id, peer_halves.0.stream_id());
    assert!(matches!(
        *server.cursor.lock().unwrap(),
        StreamCursor { local: StreamView::Max(max), .. } if max == id
    ));
    drop((halves, peer_halves));
}

#[tokio::test]
async fn transport_failure_prevents_opening_and_registering_a_stream() {
    let (transport, _peer) = pair();
    let connection = H3Connection::new(transport);
    super::super::close_connection(
        connection.transport().as_ref(),
        connection.qpack(),
        &connection.bi,
        Error::H3_INTERNAL_ERROR,
    );
    assert_eq!(
        connection.open_bi().await.err(),
        Some(Error::H3_INTERNAL_ERROR)
    );
    assert_eq!(connection.bi.len(), 0);
}

#[tokio::test]
async fn rejected_accept_closes_both_transport_halves_without_registering_stream() {
    use tokio::io::AsyncReadExt;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (_, (mut recv, mut send)) = peer.open_bi_stream().await.unwrap().unwrap();
    // Exercise accept_bi itself before the background rejection loop can run.
    connection.cursor.lock().unwrap().local = StreamView::Gone(0);
    assert_eq!(
        connection.accept_bi().await.err(),
        Some(Error::H3_REQUEST_REJECTED)
    );
    assert_eq!(connection.bi.len(), 0);
    assert_eq!(recv.read(&mut [0]).await.unwrap(), 0);
    assert!(send.write_all(b"rejected").await.is_err());
    assert_eq!(connection.error(), None);
    assert_eq!(connection.cursor.lock().unwrap().sent(), Some(0));
}

#[tokio::test]
async fn background_accept_delivers_queued_streams_then_rejects_once() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let mut peers = Vec::new();
        for _ in 0..3 {
            peers.push(peer.open_bi_stream().await.unwrap().unwrap());
        }
        while connection.bi.len() != 3 {
            tokio::task::yield_now().await;
        }
        assert_eq!(connection.cursor.lock().unwrap().local, StreamView::Max(8));
        let wake = connection.cursor.lock().unwrap().goaway().unwrap();
        if let Some(wake) = wake {
            wake.wake();
        }
        let (_, (mut rejected_recv, mut rejected_send)) =
            peer.open_bi_stream().await.unwrap().unwrap();
        // Rejection closes the producer but must preserve the already admitted queue.
        assert_eq!(rejected_recv.read(&mut [0]).await.unwrap(), 0);
        assert!(rejected_send.write_all(b"late").await.is_err());
        let calls = connection.transport().accept_bi_calls.get();
        assert_eq!(calls, 4);
        let mut accepted = Vec::new();
        for id in [0, 4, 8] {
            let stream = connection.accept_bi().await.unwrap();
            assert_eq!(stream.0.stream_id(), id);
            accepted.push(stream);
        }
        assert_eq!(
            connection.accept_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        assert_eq!(
            connection.accept_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        let _later = peer.open_bi_stream().await.unwrap().unwrap();
        tokio::task::yield_now().await;
        assert_eq!(connection.transport().accept_bi_calls.get(), calls);
        assert_eq!(connection.bi.len(), 3);
        assert_eq!(connection.error(), None);
        drop((accepted, peers));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_unpolled_response_cancels_body_without_consuming_stop() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let _peer = client.open_bi().await.unwrap();
    let (send, _recv) = server.accept_bi().await.unwrap();
    let (stop, stopped) = oneshot::channel();
    let send = send.with_stop_signal(async move { stopped.await.unwrap() });
    let response = server::Response::<Bytes>::default().streaming(1);
    let mut producer = response.clone();
    let sending = server::respond(response, send, server.qpack().clone(), &http::Method::GET);
    drop(sending);
    assert!(stop.send(Error::H3_REQUEST_REJECTED).is_err());
    assert_eq!(producer.write(b"x").await, Err(Error::H3_REQUEST_CANCELLED));
}
