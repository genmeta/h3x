use std::{sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
use futures::{FutureExt, SinkExt};
use h3x::{Code, Settings, transport};
use http_body_util::{BodyExt, Full};

mod support;
use support::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn request_response_body_and_stream_id_round_trip() {
    let (requester, responder) = connection_pair().await;
    let responder_keepalive = responder.clone();
    let responder_task = tokio::spawn(async move {
        let (request, sender) = read_next_request(&responder)
            .await
            .expect("accept request")
            .expect("one request");
        let accepted_id = sender.stream_id();
        assert_eq!(
            request.extensions().get::<h3x::StreamId>(),
            Some(&accepted_id)
        );
        assert_eq!(request.uri(), "https://example.test/echo");
        assert_eq!(
            request.headers()[http::header::COOKIE],
            "session=abc; theme=dark"
        );
        assert_eq!(
            request.headers().get_all(http::header::COOKIE).iter().count(),
            1
        );
        let body = request.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, Bytes::from_static(b"ping"));

        sender
            .send(
                http::Response::builder()
                    .status(201)
                    .header("content-length", "4")
                    .body(Full::new(Bytes::from_static(b"pong")))
                    .unwrap(),
            )
            .await
            .expect("send response");
    });

    let (head, body) = http::Request::builder()
        .method("POST")
        .uri("https://example.test/echo")
        .header("content-length", "4")
        .header("cookie", "session=abc")
        .header("cookie", "theme=dark")
        .body(Bytes::from_static(b"ping"))
        .unwrap()
        .into_parts();
    let (mut writer, response) = requester
        .request_streaming(head)
        .await
        .expect("open request");
    writer.write_all(&body).await.expect("write request body");
    writer.finish().await.expect("finish request body");
    let response = response.await.expect("receive response");
    let response_id = *response
        .extensions()
        .get::<h3x::StreamId>()
        .expect("response stream ID");
    assert_eq!(response.status(), 201);
    assert_eq!(response_id.as_u64(), 0);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"pong")
    );
    responder_task.await.unwrap();
    drop(responder_keepalive);
}

#[tokio::test]
async fn both_peers_can_initiate_requests_on_the_same_connection() {
    let (a, b) = connection_pair().await;
    let a_accept = a.clone();
    let b_accept = b.clone();

    let handle_a = tokio::spawn(async move {
        let (request, sender) = read_next_request(&a_accept).await.unwrap().unwrap();
        assert_eq!(request.uri(), "https://a.test/from-b");
        sender
            .send(http::Response::new(Full::new(Bytes::from_static(b"a"))))
            .await
            .unwrap();
    });
    let handle_b = tokio::spawn(async move {
        let (request, sender) = read_next_request(&b_accept).await.unwrap().unwrap();
        assert_eq!(request.uri(), "https://b.test/from-a");
        sender
            .send(http::Response::new(Full::new(Bytes::from_static(b"b"))))
            .await
            .unwrap();
    });

    let (from_a, from_b) = tokio::join!(
        a.request(
            http::Request::builder()
                .uri("https://b.test/from-a")
                .body(Full::new(Bytes::new()))
                .unwrap()
        ),
        b.request(
            http::Request::builder()
                .uri("https://a.test/from-b")
                .body(Full::new(Bytes::new()))
                .unwrap()
        )
    );
    assert_eq!(
        from_a
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        Bytes::from_static(b"b")
    );
    assert_eq!(
        from_b
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
        Bytes::from_static(b"a")
    );
    handle_a.await.unwrap();
    handle_b.await.unwrap();
}

#[tokio::test]
async fn dynamic_qpack_state_is_shared_across_request_streams() {
    let mut left_settings = Settings::default();
    left_settings.set_qpack_max_table_capacity(512);
    left_settings.set_qpack_blocked_streams(8);
    let mut right_settings = left_settings.clone();
    right_settings.set_qpack_max_table_capacity(512);
    let (left, right) = connection_pair_with_settings(left_settings, right_settings).await;
    let right_keepalive = right.clone();

    let responder = tokio::spawn(async move {
        for _ in 0..4 {
            let (request, sender) = read_next_request(&right).await.unwrap().unwrap();
            assert_eq!(request.headers()["x-repeated"], "same-value");
            sender
                .send(
                    http::Response::builder()
                        .header("x-repeated-response", "same-value")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
    });

    for _ in 0..4 {
        let response = left
            .request(
                http::Request::builder()
                    .uri("https://example.test/qpack")
                    .header("x-repeated", "same-value")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["x-repeated-response"], "same-value");
        response.into_body().collect().await.unwrap();
    }
    responder.await.unwrap();
    drop(right_keepalive);
}

#[tokio::test]
async fn stalled_request_headers_do_not_block_a_later_request() {
    let (raw_a, raw_b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(
        new_connection(raw_a.clone(), Settings::default()),
        new_connection(raw_b, Settings::default())
    );
    let (_id, (_recv, _send)) = transport::Connection::open_bi(&raw_a)
        .await
        .expect("open raw request stream without writing headers");

    let a = a.unwrap();
    let _a_keepalive = a.clone();
    let b = b.unwrap();
    let send = tokio::spawn(async move {
        a.request(
            http::Request::builder()
                .uri("https://example.test/not-blocked")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });
    let mut tasks = tokio::task::JoinSet::new();
    let (request, response) = tokio::time::timeout(Duration::from_millis(100), async {
        loop {
            tokio::select! {
                incoming = transport::Connection::accept_bi(b.transport()) => {
                    let (id, (recv, send)) = incoming.unwrap();
                    let b = b.clone();
                    tasks.spawn(async move { b.read_request(id, recv, send).await });
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    break result.unwrap().unwrap().unwrap().unwrap();
                }
            }
        }
    })
    .await
    .expect("later request must not be head-of-line blocked");
    assert_eq!(response.stream_id().as_u64(), 4);
    response
        .send(http::Response::new(Full::new(Bytes::new())))
        .await
        .unwrap();
    drop(request);
    send.await.unwrap().unwrap();
}

#[tokio::test]
async fn malformed_frame_in_resolver_closes_the_connection() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let (client, server) = tokio::join!(
        new_connection(raw_client.clone(), Settings::default()),
        new_connection(raw_server, Settings::default())
    );
    let client = client.expect("client connection");
    let server = server.expect("server connection");

    let (_id, (_reader, mut writer)) = transport::Connection::open_bi(&raw_client)
        .await
        .expect("open raw request stream");
    writer
        .send(Bytes::from_static(&[0x01, 0x05, 0x00]))
        .await
        .expect("send truncated HEADERS frame");
    writer.close().await.expect("finish raw request stream");

    let error = read_next_request(&server)
        .await
        .expect_err("truncated frame must fail");
    assert!(matches!(&error, h3x::Error::Connection { .. }));
    assert_eq!(error.code(), Some(Code::H3_FRAME_ERROR));

    let error = server
        .closed()
        .await
        .expect_err("a connection-level frame error must close HTTP/3");
    assert!(matches!(&error, h3x::Error::Connection { .. }));
    assert_eq!(error.code(), Some(Code::H3_FRAME_ERROR));
    drop(client);
}

#[tokio::test]
async fn dropping_an_accepted_request_cancels_the_exchange() {
    let (requester, responder) = connection_pair().await;
    let send = tokio::spawn(async move {
        requester
            .request(
                http::Request::builder()
                    .uri("https://example.test/rejected")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
    });

    let accepted = read_next_request(&responder).await.unwrap().unwrap();
    drop(accepted);

    let error = send.await.unwrap().expect_err("request must be cancelled");
    assert!(matches!(&error, h3x::Error::Stream { .. }));
    assert_eq!(error.code(), Some(Code::H3_REQUEST_CANCELLED));
}

#[tokio::test]
async fn response_headers_can_arrive_before_request_body_finishes() {
    let (requester, responder) = connection_pair().await;
    let _responder_keepalive = responder.clone();
    let responder_task = tokio::spawn(async move {
        let (request, sender) = read_next_request(&responder).await.unwrap().unwrap();
        sender
            .send(http::Response::new(Full::new(Bytes::new())))
            .await
            .unwrap();
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"after-headers")
        );
    });

    let (head, ()) = http::Request::builder()
        .uri("https://example.test/early-response")
        .body(())
        .unwrap()
        .into_parts();
    let (mut writer, response) = requester.request_streaming(head).await.unwrap();
    let response = tokio::time::timeout(Duration::from_millis(100), response)
        .await
        .expect("response must not wait for the request body")
        .expect("response headers");

    writer.write_all(b"after-headers").await.unwrap();
    writer.finish().await.unwrap();
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    responder_task.await.unwrap();
}

#[tokio::test]
async fn content_length_mismatch_is_rejected_locally() {
    let (requester, responder) = connection_pair().await;
    let responder_task = tokio::spawn(async move {
        let (_request, _sender) = read_next_request(&responder).await.unwrap().unwrap();
        futures::future::pending::<()>().await;
    });

    let error = requester
        .request(
            http::Request::builder()
                .uri("https://example.test/wrong-length")
                .header("content-length", "4")
                .body(Full::new(Bytes::from_static(b"abc")))
                .unwrap(),
        )
        .await
        .expect_err("short body must fail");
    assert!(matches!(&error, h3x::Error::InvalidMessage { .. }));
    responder_task.abort();
}

#[tokio::test]
async fn peer_goaway_rejects_new_sends_but_does_not_close_accept() {
    let (raw_a, raw_b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(
        new_connection(raw_a.clone(), Settings::default()),
        new_connection(raw_b, Settings::default())
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    let _a_keepalive = a.clone();
    raw_a.inject_control(Bytes::from_static(&[7, 1, 0]));
    tokio::time::timeout(Duration::from_millis(100), async {
        while !b.is_draining() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/rejected")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert!(matches!(
        b.request_streaming(parts).await,
        Err(h3x::Error::Goaway { .. })
    ));
    let request = tokio::spawn(async move {
        a.request(
            http::Request::builder()
                .uri("https://example.test/accepted")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });
    let (incoming, sender) = read_next_request(&b).await.unwrap().unwrap();
    drop(incoming);
    sender
        .send(http::Response::new(Full::new(Bytes::new())))
        .await
        .unwrap();
    request
        .await
        .unwrap()
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
}

#[tokio::test]
async fn peer_goaway_does_not_cover_an_earlier_request() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let client = new_connection(raw_client, Settings::default())
        .await
        .unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (writer, response) = client.request_streaming(parts).await.unwrap();
    writer.finish().await.unwrap();
    let (_id, (_upload, mut reply)) = transport::Connection::accept_bi(&raw_server).await.unwrap();
    let (_id, mut control) = transport::Connection::open_uni(&raw_server).await.unwrap();
    control
        .send(Bytes::from_static(&[0, 4, 0, 7, 1, 4]))
        .await
        .unwrap();
    reply
        .send(Bytes::from_static(&[1, 3, 0, 0, 0xd9]))
        .await
        .unwrap();
    reply.close().await.unwrap();
    assert_eq!(response.await.unwrap().status(), 200);
}

#[tokio::test]
async fn explicit_close_marks_both_ends_closed_without_an_error() {
    let (a, b) = connection_pair().await;
    a.close(Code::H3_NO_ERROR, b"done");
    let (local, peer) = tokio::join!(a.closed(), b.closed());
    local.unwrap();
    peer.unwrap();
    assert!(a.is_draining());
}

fn raw_get_headers() -> Vec<u8> {
    let mut section = vec![0, 0, 0xd1, 0xd7, 0x50, 12];
    section.extend_from_slice(b"example.test");
    section.push(0xc1);
    let mut bytes = vec![1, section.len() as u8];
    bytes.extend_from_slice(&section);
    bytes
}

#[tokio::test]
async fn a_partial_data_frame_is_delivered_before_its_tail_arrives() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let server = new_connection(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
    let mut first = vec![0x21, 2, 99, 99]; // Unknown before initial HEADERS.
    first.extend_from_slice(&raw_get_headers());
    first.extend_from_slice(&[0, 4, b'a', b'b']);
    send.send(Bytes::from(first)).await.unwrap();
    let (request, _response) = read_next_request(&server).await.unwrap().unwrap();
    let mut body = request.into_body();
    let first = tokio::time::timeout(Duration::from_millis(100), body.frame())
        .await
        .expect("must not wait for the complete DATA frame")
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), &b"ab"[..]);
    // The tail, trailers, and an unknown frame share a single transport chunk.
    send.send(Bytes::from_static(&[b'c', b'd', 1, 2, 0, 0, 0x21, 1, 42]))
        .await
        .unwrap();
    send.close().await.unwrap();
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        &b"cd"[..]
    );
    assert!(body.frame().await.unwrap().unwrap().is_trailers());
    assert!(body.frame().await.is_none());
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn forbidden_initial_frames_fail_before_reading_their_payload() {
    for frame_type in [0, 2, 4, 7, 0x0d] {
        let (raw_client, raw_server) = MemoryTransport::pair();
        let server = new_connection(raw_server, Settings::default())
            .await
            .unwrap();
        let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
        // A legal length varint declaring 16384 bytes; no payload ever arrives.
        let _ = send
            .send(Bytes::from(vec![frame_type, 0x80, 0, 0x40, 0]))
            .await;
        let error = tokio::time::timeout(Duration::from_millis(100), read_next_request(&server))
            .await
            .expect("invalid location must fail without reading payload")
            .unwrap_err();
        assert_eq!(error.code(), Some(Code::H3_FRAME_UNEXPECTED));
        assert!(matches!(error, h3x::Error::Connection { .. }));
    }
}

#[tokio::test]
async fn cancelled_response_read_stops_its_stream_but_upload_can_continue() {
    for prefix in [&[1, 0x40][..], &[1, 4, 0][..]] {
        let (raw_client, raw_server) = MemoryTransport::pair();
        let client = new_connection(raw_client, Settings::default())
            .await
            .unwrap();
        let (mut writer, waiting) = client
            .request_streaming(
                http::Request::builder()
                    .method("POST")
                    .uri("https://example.test/")
                    .body(())
                    .unwrap()
                    .into_parts()
                    .0,
            )
            .await
            .unwrap();
        let (_id, (_upload, mut response)) =
            transport::Connection::accept_bi(&raw_server).await.unwrap();
        response.send(Bytes::copy_from_slice(prefix)).await.unwrap();
        let mut waiting = Box::pin(waiting);
        assert!(waiting.as_mut().now_or_never().is_none());
        drop(waiting);
        tokio::task::yield_now().await;
        assert!(
            response
                .send(Bytes::from_static(b"cancelled"))
                .await
                .is_err()
        );
        writer.write_all(b"still uploading").await.unwrap();
        writer.finish().await.unwrap();
    }
}

#[tokio::test]
async fn unknown_first_control_frame_is_not_skipped() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let server = new_connection(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, mut send) = transport::Connection::open_uni(&raw_client).await.unwrap();
    let _ = send.send(Bytes::from_static(&[0, 0x21, 1])).await;
    let error = tokio::time::timeout(Duration::from_millis(100), server.closed())
        .await
        .expect("control must begin with SETTINGS, without waiting for unknown payload")
        .unwrap_err();
    assert_eq!(error.code(), Some(Code::H3_MISSING_SETTINGS));
}

#[tokio::test]
async fn transport_failure_during_body_read_closes_the_connection_without_inventing_a_code() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let server = new_connection(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
    let mut bytes = raw_get_headers();
    bytes.extend_from_slice(&[0, 4, 1]);
    send.send(Bytes::from(bytes)).await.unwrap();
    let (request, _response) = read_next_request(&server).await.unwrap().unwrap();
    raw_client.fail();
    let error = request.into_body().collect().await.unwrap_err();
    assert!(matches!(error, h3x::Error::Transport { .. }));
    assert_eq!(error.code(), None);
    let terminal = tokio::time::timeout(Duration::from_millis(100), server.closed())
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(terminal, h3x::Error::Transport { .. }));
}

#[tokio::test]
async fn goaway_interrupts_a_partial_response_payload() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let client = new_connection(raw_client, Settings::default())
        .await
        .unwrap();
    let (_writer, waiting) = client
        .request_streaming(
            http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        )
        .await
        .unwrap();
    let (_id, (_upload, mut response)) =
        transport::Connection::accept_bi(&raw_server).await.unwrap();
    response.send(Bytes::from_static(&[1, 4, 0])).await.unwrap();
    let mut waiting = Box::pin(waiting);
    assert!(waiting.as_mut().now_or_never().is_none());
    let (_id, mut control) = transport::Connection::open_uni(&raw_server).await.unwrap();
    control
        .send(Bytes::from_static(&[0, 4, 0, 7, 1, 0]))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_millis(100), waiting)
        .await
        .expect("GOAWAY must interrupt payload and QPACK waits as well as frame headers")
        .unwrap_err();
    assert!(matches!(error, h3x::Error::Goaway { .. }));
}

#[tokio::test]
async fn control_frame_structure_and_semantic_errors_stay_distinct() {
    for (bytes, expected) in [
        (&[0, 4, 0, 7, 2, 0, 0][..], Code::H3_FRAME_ERROR), // GOAWAY trailing bytes.
        (&[0, 4, 0, 3, 1, 0][..], Code::H3_ID_ERROR),       // No promised push to cancel.
        (&[0, 4, 0, 13, 1, 1, 13, 1, 0][..], Code::H3_ID_ERROR), // Decreased MAX_PUSH_ID.
        (&[0, 4, 0, 2, 0][..], Code::H3_FRAME_UNEXPECTED),  // Forbidden HTTP/2 type.
    ] {
        let (raw_client, raw_server) = MemoryTransport::pair();
        let server = new_connection(raw_server, Settings::default())
            .await
            .unwrap();
        let (_id, mut control) = transport::Connection::open_uni(&raw_client).await.unwrap();
        let _ = control.send(Bytes::copy_from_slice(bytes)).await;
        let error = tokio::time::timeout(Duration::from_millis(100), server.closed())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), Some(expected));
    }
}

#[tokio::test]
async fn upload_remains_owned_after_response_eof() {
    let (requester, responder) = connection_pair().await;
    let _responder_keepalive = responder.clone();
    let responder_task = tokio::spawn(async move {
        let (request, sender) = read_next_request(&responder).await.unwrap().unwrap();
        sender
            .send(http::Response::new(Full::new(Bytes::new())))
            .await
            .unwrap();
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "still uploading"
        );
    });
    let parts = http::Request::builder()
        .uri("https://example.test/upload")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (mut writer, response) = requester.request_streaming(parts).await.unwrap();
    response.await.unwrap().into_body().collect().await.unwrap();
    writer.write_all(b"still uploading").await.unwrap();
    writer.finish().await.unwrap();
    responder_task.await.unwrap();
}

#[tokio::test]
async fn invalid_request_headers_are_rejected_before_opening_a_stream() {
    let (raw, peer) = MemoryTransport::pair();
    let opened = raw.next_bi.clone();
    let (requester, responder) = tokio::join!(
        new_connection(raw, Settings::default()),
        new_connection(peer, Settings::default()),
    );
    let requester = requester.unwrap();
    let _responder = responder.unwrap();
    let before = opened.load(Ordering::Relaxed);
    let parts = http::Request::builder()
        .uri("https://example.test/invalid")
        .header("connection", "close")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert!(matches!(
        requester.request_streaming(parts).await,
        Err(h3x::Error::InvalidMessage { .. })
    ));
    assert_eq!(opened.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn dropping_unpolled_initialization_closes_the_transport() {
    let (raw, _peer) = MemoryTransport::pair();
    drop(h3x::protocol::new(raw.clone(), Settings::default()));
    assert_eq!(
        transport::Connection::closed(&raw).await.code(),
        Some(Code::H3_INTERNAL_ERROR)
    );
}

#[tokio::test]
async fn dropping_streaming_handles_cancels_both_directions() {
    let (raw, peer) = MemoryTransport::pair();
    let connection = new_connection(raw, Settings::default()).await.unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (upload, response) = connection.request_streaming(parts).await.unwrap();
    let (_, (mut recv, mut send)) = transport::Connection::accept_bi(&peer).await.unwrap();
    drop((upload, response));
    use futures::StreamExt;
    let error = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(Err(error)) = recv.next().await {
                break error;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(
        transport::StreamError::from(error).code(),
        Some(Code::H3_REQUEST_CANCELLED)
    );
    assert!(send.send(Bytes::from_static(b"cancelled")).await.is_err());
}

#[tokio::test]
async fn native_stream_delivers_request_data() {
    let (raw, server) = MemoryTransport::pair();
    let server = new_connection(server, Settings::default()).await.unwrap();
    let (_id, (_reply, mut send)) = transport::Connection::open_bi(&raw).await.unwrap();
    send.send(Bytes::from(raw_get_headers())).await.unwrap();
    let data = Bytes::from_static(&[0, 5, b'h', b'e', b'l', b'l', b'o']);
    send.send(data.clone()).await.unwrap();
    send.close().await.unwrap();
    let (request, _sender) = read_next_request(&server).await.unwrap().unwrap();
    let mut body = request.into_body();
    let received = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(received, &b"hello"[..]);
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn unread_body_does_not_block_control_processing() {
    let (raw, server) = MemoryTransport::pair();
    let server = new_connection(server, Settings::default()).await.unwrap();
    let (_id, (_reply, mut send)) = transport::Connection::open_bi(&raw).await.unwrap();
    send.send(Bytes::from(raw_get_headers())).await.unwrap();
    for _ in 0..10 {
        send.send(Bytes::from_static(&[0, 1, b'x'])).await.unwrap();
    }
    let (_request, _sender) = read_next_request(&server).await.unwrap().unwrap();
    let (_id, mut control) = transport::Connection::open_uni(&raw).await.unwrap();
    let _ = control.send(Bytes::from_static(&[0, 4, 0, 4, 0])).await;
    let error = tokio::time::timeout(Duration::from_millis(100), server.closed())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), Some(Code::H3_FRAME_UNEXPECTED));
}

#[tokio::test]
async fn local_request_errors_match_across_both_entries_without_opening_streams() {
    let (raw, _peer) = MemoryTransport::pair();
    let opened = raw.next_bi.clone();
    let connection = new_connection(raw, Settings::default()).await.unwrap();
    for (method, uri, header, value) in [
        ("TRACE", "https://example.test/", "content-length", "1"),
        ("POST", "https://example.test/", "content-length", "bad"),
        ("GET", "/relative", "x-valid", "yes"),
        ("GET", "https://example.test/", "connection", "close"),
    ] {
        let request = || {
            http::Request::builder()
                .method(method)
                .uri(uri)
                .header(header, value)
                .body(Full::new(Bytes::from_static(b"x")))
                .unwrap()
        };
        assert!(matches!(
            connection.request(request()).await,
            Err(h3x::Error::InvalidMessage { .. })
        ));
        assert!(matches!(
            connection.request_streaming(request().into_parts().0).await,
            Err(h3x::Error::InvalidMessage { .. })
        ));
        assert_eq!(opened.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test]
async fn body_frames_and_streaming_writes_deliver_data_trailers_and_fin() {
    let (client, server) = connection_pair().await;
    let keepalive = server.clone();
    let peer = tokio::spawn(async move {
        for _ in 0..2 {
            let (request, response) = read_next_request(&server).await.unwrap().unwrap();
            let body = request.into_body().collect().await.unwrap();
            assert_eq!(body.trailers().unwrap()["x-done"], "yes");
            assert_eq!(body.to_bytes(), Bytes::from(vec![42; 128 * 1024]));
            response
                .send(http::Response::new(Full::new(Bytes::new())))
                .await
                .unwrap();
        }
    });
    let bytes = Bytes::from(vec![42; 128 * 1024]);
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-done", "yes".parse().unwrap());
    let body = http_body_util::StreamBody::new(futures::stream::iter([
        Ok::<_, std::io::Error>(http_body::Frame::data(bytes.clone())),
        Ok(http_body::Frame::trailers(trailers.clone())),
    ]));
    let request = http::Request::builder()
        .uri("https://example.test/")
        .body(body)
        .unwrap();
    client
        .request(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (mut writer, response) = client.request_streaming(parts).await.unwrap();
    writer.write_all(&bytes).await.unwrap();
    writer.flush().await.unwrap();
    writer.trailers(trailers).await.unwrap();
    response.await.unwrap().into_body().collect().await.unwrap();
    peer.await.unwrap();
    drop(keepalive);
}

#[tokio::test]
async fn ordinary_request_keeps_automatic_upload_after_delivering_response() {
    let (client, server) = connection_pair().await;
    let _keepalive = server.clone();
    let peer = tokio::spawn(async move {
        let (request, response) = read_next_request(&server).await.unwrap().unwrap();
        response
            .send(http::Response::new(Full::new(Bytes::new())))
            .await
            .unwrap();
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "after response"
        );
    });
    let (send, receive) = tokio::sync::mpsc::channel::<http_body::Frame<Bytes>>(1);
    let body = http_body_util::StreamBody::new(futures::stream::unfold(
        receive,
        |mut receive| async move {
            receive
                .recv()
                .await
                .map(|frame| (Ok::<_, h3x::Error>(frame), receive))
        },
    ));
    let request = http::Request::builder()
        .uri("https://example.test/")
        .body(body)
        .unwrap();
    client
        .request(request)
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
    send.send(http_body::Frame::data(Bytes::from_static(
        b"after response",
    )))
    .await
    .unwrap();
    drop(send);
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    client.shutdown().await.unwrap();
}
