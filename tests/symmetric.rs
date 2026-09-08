use std::{io, sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
#[cfg(feature = "webtransport")]
use futures::StreamExt;
use futures::{FutureExt, SinkExt};
use h3x::{Code, Settings, transport};
use http_body_util::{BodyExt, Full};
#[cfg(feature = "webtransport")]
use tokio::sync::oneshot;

mod support;
use support::*;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn request_response_body_and_stream_id_round_trip() {
    let (requester, responder) = connection_pair().await;
    let responder_keepalive = responder.clone();
    let responder_task = tokio::spawn(async move {
        let (request, sender) = responder
            .accept()
            .await
            .expect("accept request")
            .expect("one request");
        let accepted_id = sender.stream_id();
        assert_eq!(
            request.extensions().get::<h3x::StreamId>(),
            Some(&accepted_id)
        );
        assert_eq!(request.uri(), "https://example.test/echo");
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
        .body(Bytes::from_static(b"ping"))
        .unwrap()
        .into_parts();
    let (mut writer, response) = requester.request(head).await.expect("open request");
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
        let (request, sender) = a_accept.accept().await.unwrap().unwrap();
        assert_eq!(request.uri(), "https://a.test/from-b");
        sender
            .send(http::Response::new(Full::new(Bytes::from_static(b"a"))))
            .await
            .unwrap();
    });
    let handle_b = tokio::spawn(async move {
        let (request, sender) = b_accept.accept().await.unwrap().unwrap();
        assert_eq!(request.uri(), "https://b.test/from-a");
        sender
            .send(http::Response::new(Full::new(Bytes::from_static(b"b"))))
            .await
            .unwrap();
    });

    let (from_a, from_b) = tokio::join!(
        a.send(
            http::Request::builder()
                .uri("https://b.test/from-a")
                .body(Full::new(Bytes::new()))
                .unwrap()
        ),
        b.send(
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
            let (request, sender) = right.accept().await.unwrap().unwrap();
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
            .send(
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
        Connection::new(raw_a.clone(), Settings::default()),
        Connection::new(raw_b, Settings::default())
    );
    let (_id, (_recv, _send)) = transport::Connection::open_bi(&raw_a)
        .await
        .expect("open raw request stream without writing headers");

    let a = a.unwrap();
    let b = b.unwrap();
    let send = tokio::spawn(async move {
        a.send(
            http::Request::builder()
                .uri("https://example.test/not-blocked")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });
    let (request, response) = tokio::time::timeout(Duration::from_millis(100), b.accept())
        .await
        .expect("later request must not be head-of-line blocked")
        .unwrap()
        .expect("request");
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
        Connection::new(raw_client.clone(), Settings::default()),
        Connection::new(raw_server, Settings::default())
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

    let error = server
        .accept()
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
            .send(
                http::Request::builder()
                    .uri("https://example.test/rejected")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
    });

    let accepted = responder.accept().await.unwrap().unwrap();
    drop(accepted);

    let error = send.await.unwrap().expect_err("request must be cancelled");
    assert!(matches!(&error, h3x::Error::Stream { .. }));
    assert_eq!(error.code(), Some(Code::H3_REQUEST_CANCELLED));
}

#[tokio::test]
async fn response_headers_can_arrive_before_request_body_finishes() {
    let (requester, responder) = connection_pair().await;
    let responder_task = tokio::spawn(async move {
        let (request, sender) = responder.accept().await.unwrap().unwrap();
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
    let (mut writer, response) = requester.request(head).await.unwrap();
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
async fn content_length_mismatch_fails_the_request_stream() {
    let (requester, responder) = connection_pair().await;
    let responder_task = tokio::spawn(async move {
        let (_request, _sender) = responder.accept().await.unwrap().unwrap();
        futures::future::pending::<()>().await;
    });

    let error = requester
        .send(
            http::Request::builder()
                .uri("https://example.test/wrong-length")
                .header("content-length", "4")
                .body(Full::new(Bytes::from_static(b"abc")))
                .unwrap(),
        )
        .await
        .expect_err("short body must fail");
    assert!(matches!(&error, h3x::Error::Stream { .. }));
    assert_eq!(error.code(), Some(Code::H3_MESSAGE_ERROR));
    responder_task.abort();
}

#[tokio::test]
async fn peer_goaway_rejects_new_sends_but_does_not_close_accept() {
    let (raw_a, raw_b) = MemoryTransport::pair();
    let (a, b) = tokio::join!(
        Connection::new(raw_a.clone(), Settings::default()),
        Connection::new(raw_b, Settings::default())
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    raw_a.uni_writes.lock().unwrap()[0]
        .send(Ok(Bytes::from_static(&[7, 1, 0])))
        .unwrap();
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
        b.request(parts).await,
        Err(h3x::Error::Goaway { .. })
    ));
    let request = tokio::spawn(async move {
        a.send(
            http::Request::builder()
                .uri("https://example.test/accepted")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });
    let (incoming, sender) = b.accept().await.unwrap().unwrap();
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
    let client = Connection::new(raw_client, Settings::default())
        .await
        .unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (writer, response) = client.request(parts).await.unwrap();
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

#[cfg(feature = "webtransport")]
async fn webtransport_connection_pair() -> (
    Connection<MemoryTransport>,
    Connection<MemoryTransport>,
    MemoryTransport,
    MemoryTransport,
) {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let (client, server) = tokio::join!(
        Connection::new_webtransport(raw_client.clone(), Settings::default(),),
        Connection::new_webtransport(raw_server.clone(), Settings::default(),),
    );
    (
        client.expect("client WebTransport connection"),
        server.expect("server WebTransport connection"),
        raw_client,
        raw_server,
    )
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_connect_streams_datagrams_and_close_round_trip() {
    let (client, server, _, _) = webtransport_connection_pair().await;
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        assert_eq!(sender.stream_id().as_u64(), 0);
        assert!(h3x::webtransport::is_request(&request));
        assert_eq!(request.uri(), "https://example.test/session");
        let session = h3x::webtransport::accept(
            request,
            sender,
            http::Response::builder().status(200).body(()).unwrap(),
        )
        .await
        .unwrap();

        session.drained().await.unwrap();

        let (mut recv, mut send) = session.accept_bi().await.unwrap();
        assert_eq!(
            recv.next().await.unwrap().unwrap(),
            Bytes::from_static(b"ping")
        );
        assert!(recv.next().await.is_none());
        send.send(Bytes::from_static(b"pong")).await.unwrap();
        send.close().await.unwrap();

        let mut recv = session.accept_uni().await.unwrap();
        assert_eq!(
            recv.next().await.unwrap().unwrap(),
            Bytes::from_static(b"one-way")
        );
        assert!(recv.next().await.is_none());

        assert_eq!(
            session.receive_datagram().await.unwrap(),
            Bytes::from_static(b"datagram")
        );
        session
            .send_datagram(Bytes::from_static(b"reply"))
            .await
            .unwrap();

        let close = session.closed().await.unwrap();
        assert_eq!(close.code(), 7);
        assert_eq!(close.message(), "done");
    });

    let (response, session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/session")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    assert_eq!(response.status(), 200);
    assert_eq!(session.id().as_u64(), 0);
    assert_eq!(session.max_datagram_size(), 1199);
    session.drain().await.unwrap();

    let (mut recv, mut send) = session.open_bi().await.unwrap();
    send.send(Bytes::from_static(b"ping")).await.unwrap();
    send.close().await.unwrap();
    assert_eq!(
        recv.next().await.unwrap().unwrap(),
        Bytes::from_static(b"pong")
    );
    assert!(recv.next().await.is_none());

    let mut send = session.open_uni().await.unwrap();
    send.send(Bytes::from_static(b"one-way")).await.unwrap();
    send.close().await.unwrap();

    session
        .send_datagram(Bytes::from_static(b"datagram"))
        .await
        .unwrap();
    assert_eq!(
        session.receive_datagram().await.unwrap(),
        Bytes::from_static(b"reply")
    );
    session.close(7, "done").await.unwrap();
    server_task.await.unwrap();
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_rejection_preserves_status_headers_and_body() {
    let (client, server, _, _) = webtransport_connection_pair().await;
    let server_task = tokio::spawn(async move {
        let (request, response) = server.accept().await.unwrap().unwrap();
        assert!(h3x::webtransport::is_request(&request));
        response
            .send(
                http::Response::builder()
                    .status(http::StatusCode::FORBIDDEN)
                    .header("x-reason", "policy")
                    .body(Full::new(Bytes::from_static(b"denied")))
                    .unwrap(),
            )
            .await
            .unwrap();
    });

    let response = client
        .webtransport(
            http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.test/rejected")
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    let h3x::webtransport::ConnectResponse::Rejected(response) = response else {
        panic!("non-2xx WebTransport response was accepted")
    };
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["x-reason"], "policy");
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"denied")
    );
    server_task.await.unwrap();
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_reset_reliably_covers_the_stream_header() {
    let (client, server, raw_client, _) = webtransport_connection_pair().await;
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        let mut recv = session.accept_uni().await.unwrap();
        let error = recv.next().await.unwrap().expect_err("stream is reset");
        assert_eq!(
            error
                .code()
                .and_then(h3x::webtransport::application_error_code),
            Some(23)
        );
    });

    let (_, session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/reset")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    let mut send = session.open_uni().await.unwrap();
    let stream_id = send.id();
    send.reset(23).unwrap();

    let reset_seen = raw_client
        .reliable_resets
        .lock()
        .expect("reliable resets poisoned")
        .iter()
        .any(|&(id, code, reliable_size)| {
            id == stream_id
                && h3x::webtransport::application_error_code(code) == Some(23)
                && reliable_size == 3
        });
    assert!(reset_seen);
    server_task.await.unwrap();
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn a_stalled_bidi_discriminator_does_not_block_later_webtransport_connect() {
    let (client, server, raw_client, _) = webtransport_connection_pair().await;
    let server_keepalive = server.clone();
    let (_id, (_stalled_reader, _stalled_writer)) = transport::Connection::open_bi(&raw_client)
        .await
        .expect("open stalled bidi stream");
    let server_task = tokio::spawn(async move {
        let (request, sender) = tokio::time::timeout(Duration::from_millis(100), server.accept())
            .await
            .expect("later request must not be head-of-line blocked")
            .unwrap()
            .unwrap();
        assert_eq!(sender.stream_id().as_u64(), 4);
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        session.close(0, "").await.unwrap();
    });

    let (_, session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/not-blocked")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    session.closed().await.unwrap();
    server_task.await.unwrap();
    drop(server_keepalive);
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_without_session_flow_control_allows_only_one_active_session() {
    let (client, server, _, _) = webtransport_connection_pair().await;
    let server_keepalive = server.clone();
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        session.closed().await.unwrap()
    });

    let (_, first) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/first")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    let error = client
        .webtransport(
            http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.test/second")
                .body(())
                .unwrap(),
        )
        .await
        .expect_err("a second active session must be rejected locally");
    assert!(matches!(
        &error,
        h3x::Error::Stream {
            code: Code::H3_REQUEST_REJECTED,
            ..
        }
    ));
    assert_eq!(error.code(), Some(Code::H3_REQUEST_REJECTED));

    first.close(9, "finished").await.unwrap();
    assert_eq!(server_task.await.unwrap().code(), 9);
    drop(server_keepalive);
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn malformed_http3_datagram_closes_the_connection() {
    let (_client, server, raw_client, _) = webtransport_connection_pair().await;
    transport::webtransport::Connection::send_datagram(&raw_client, Bytes::new())
        .await
        .unwrap();

    let error = server
        .closed()
        .await
        .expect_err("an empty HTTP/3 datagram has no Quarter Stream ID");
    assert!(matches!(&error, h3x::Error::Connection { .. }));
    assert_eq!(error.code(), Some(Code::H3_DATAGRAM_ERROR));
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_signal_after_headers_closes_http3_without_waiting_for_a_length() {
    let (client, server, raw_client, _) = webtransport_connection_pair().await;
    let (_id, (_reader, mut writer)) = transport::Connection::open_bi(&raw_client)
        .await
        .expect("open raw request stream");

    let mut field_section = vec![0x00, 0x00, 0xd1, 0xd7, 0x50, 0x0c];
    field_section.extend_from_slice(b"example.test");
    field_section.push(0xc1);
    let mut request = vec![0x01, field_section.len() as u8];
    request.extend_from_slice(&field_section);
    request.extend_from_slice(&[0x40, 0x41]);
    writer
        .send(Bytes::from(request))
        .await
        .expect("send HEADERS followed by WT_STREAM signal");

    let (request, _response_sender) = server.accept().await.unwrap().expect("request");
    let error = request
        .into_body()
        .collect()
        .await
        .expect_err("WT_STREAM is not a length-prefixed frame");
    assert!(matches!(&error, h3x::Error::Connection { .. }));
    assert_eq!(error.code(), Some(Code::H3_FRAME_ERROR));

    let error = server
        .closed()
        .await
        .expect_err("illegal WT_STREAM placement must close HTTP/3");
    assert_eq!(error.code(), Some(Code::H3_FRAME_ERROR));
    drop(client);
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn unnegotiated_webtransport_stream_is_rejected_without_closing_http3() {
    let (raw_plain, raw_webtransport) = MemoryTransport::pair();
    let (plain, webtransport) = tokio::join!(
        Connection::new(raw_plain.clone(), Settings::default()),
        Connection::new_webtransport(raw_webtransport, Settings::default(),),
    );
    let plain = plain.unwrap();
    let webtransport = webtransport.unwrap();
    let webtransport_keepalive = webtransport.clone();

    let (mut rejected_reader, mut rejected_writer) =
        transport::Connection::open_bi(&raw_plain).await.unwrap();
    rejected_writer
        .send(Bytes::from_static(&[0x40, 0x41, 0x00]))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_millis(100), rejected_reader.next())
        .await
        .expect("the unnegotiated stream must be reset")
        .expect("the reset is delivered")
        .expect_err("the stream is rejected");
    assert_eq!(error.code(), Some(Code::WT_REQUIREMENTS_NOT_MET));

    let responder = tokio::spawn(async move {
        let (_request, sender) = webtransport.accept().await.unwrap().unwrap();
        sender
            .send(http::Response::new(Full::new(Bytes::new())))
            .await
            .unwrap();
    });
    let response = plain
        .send(
            http::Request::builder()
                .uri("https://example.test/still-http3")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect("ordinary HTTP/3 remains usable");
    response.into_body().collect().await.unwrap();
    responder.await.unwrap();
    drop(webtransport_keepalive);
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn http3_goaway_marks_the_active_webtransport_session_draining() {
    let (client, server, raw_client, _) = webtransport_connection_pair().await;
    let (session_tx, session_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        session_tx.send(session.clone()).unwrap();
        session.closed().await.unwrap()
    });

    let (_, client_session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/goaway")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    let server_session = session_rx.await.unwrap();
    raw_client.uni_writes.lock().unwrap()[0]
        .send(Ok(Bytes::from_static(&[7, 1, 0])))
        .unwrap();

    tokio::time::timeout(Duration::from_millis(100), server_session.drained())
        .await
        .expect("GOAWAY must notify the WebTransport application")
        .unwrap();
    server_session.close(0, "shutdown").await.unwrap();
    let peer_close = client_session.closed().await.unwrap();
    assert_eq!(peer_close.message(), "shutdown");
    assert_eq!(server_task.await.unwrap().message(), "shutdown");
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn webtransport_requires_an_https_uri() {
    let (client, _server, _, _) = webtransport_connection_pair().await;

    let error = client
        .webtransport(
            http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("http://example.test/session")
                .body(())
                .unwrap(),
        )
        .await
        .expect_err("WebTransport over HTTP/3 requires https");

    assert!(matches!(&error, h3x::Error::InvalidMessage { .. }));
    assert_eq!(error.code(), None);
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn dropping_the_last_session_handle_cleanly_terminates_the_session() {
    let (client, server, _, _) = webtransport_connection_pair().await;
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        session.closed().await.unwrap()
    });

    let (_, session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/drop")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    drop(session);

    let close = tokio::time::timeout(Duration::from_millis(100), server_task)
        .await
        .expect("dropping the session must close its CONNECT stream")
        .unwrap();
    assert_eq!(close.code(), 0);
    assert_eq!(close.message(), "");
}

#[cfg(feature = "webtransport")]
#[tokio::test]
async fn receiving_session_close_aborts_active_data_streams() {
    let (client, server, _, _) = webtransport_connection_pair().await;
    let (stream_ready, ready) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (request, sender) = server.accept().await.unwrap().unwrap();
        let session = h3x::webtransport::accept(request, sender, http::Response::new(()))
            .await
            .unwrap();
        let mut receive = session.accept_uni().await.unwrap();
        stream_ready.send(()).unwrap();
        let error = receive
            .next()
            .await
            .expect("session termination is delivered as a stream error")
            .expect_err("the active stream must be aborted");
        assert_eq!(error.code(), Some(Code::WT_SESSION_GONE));
        session.closed().await.unwrap()
    });

    let (_, session) = accepted(
        client
            .webtransport(
                http::Request::builder()
                    .method(http::Method::CONNECT)
                    .uri("https://example.test/close-streams")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap(),
    );
    let _send = session.open_uni().await.unwrap();
    ready.await.unwrap();
    session.close(17, "closing").await.unwrap();

    let close = server_task.await.unwrap();
    assert_eq!(close.code(), 17);
    assert_eq!(close.message(), "closing");
}

// Static QPACK GET https://example.test/ with no dynamic-table dependency.
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
    let server = Connection::new(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
    let mut first = vec![0x21, 2, 99, 99]; // Unknown before initial HEADERS.
    first.extend_from_slice(&raw_get_headers());
    first.extend_from_slice(&[0, 4, b'a', b'b']);
    send.send(Bytes::from(first)).await.unwrap();
    let (request, _response) = server.accept().await.unwrap().unwrap();
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
        let server = Connection::new(raw_server, Settings::default())
            .await
            .unwrap();
        let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
        // A legal length varint declaring 16384 bytes; no payload ever arrives.
        send.send(Bytes::from(vec![frame_type, 0x80, 0, 0x40, 0]))
            .await
            .unwrap();
        let error = tokio::time::timeout(Duration::from_millis(100), server.accept())
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
        let client = Connection::new(raw_client, Settings::default())
            .await
            .unwrap();
        let (mut writer, waiting) = client
            .request(
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
        let (_id, (_upload, mut response)) = transport::Connection::accept_bi(&raw_server).await.unwrap();
        response.send(Bytes::copy_from_slice(prefix)).await.unwrap();
        let mut waiting = waiting;
        assert!(waiting.as_mut().now_or_never().is_none());
        drop(waiting);
        tokio::task::yield_now().await;
        assert!(
            response
                .actions
                .stops
                .lock()
                .unwrap()
                .contains(&Code::H3_REQUEST_CANCELLED)
        );
        writer.write_all(b"still uploading").await.unwrap();
        writer.finish().await.unwrap();
    }
}

#[tokio::test]
async fn unknown_first_control_frame_is_not_skipped() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let server = Connection::new(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, mut send) = transport::Connection::open_uni(&raw_client).await.unwrap();
    send.send(Bytes::from_static(&[0, 0x21, 1])).await.unwrap();
    let error = tokio::time::timeout(Duration::from_millis(100), server.closed())
        .await
        .expect("control must begin with SETTINGS, without waiting for unknown payload")
        .unwrap_err();
    assert_eq!(error.code(), Some(Code::H3_MISSING_SETTINGS));
}

#[tokio::test]
async fn transport_failure_during_body_read_closes_the_connection_without_inventing_a_code() {
    let (raw_client, raw_server) = MemoryTransport::pair();
    let server = Connection::new(raw_server, Settings::default())
        .await
        .unwrap();
    let (_id, (_recv, mut send)) = transport::Connection::open_bi(&raw_client).await.unwrap();
    let mut bytes = raw_get_headers();
    bytes.extend_from_slice(&[0, 4, 1]);
    send.send(Bytes::from(bytes)).await.unwrap();
    send.sender
        .as_ref()
        .unwrap()
        .send(Err(transport::StreamError::connection(
            transport::ConnectionError::transport(io::Error::other("connection disappeared")),
        )))
        .unwrap();
    let (request, _response) = server.accept().await.unwrap().unwrap();
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
    let client = Connection::new(raw_client, Settings::default())
        .await
        .unwrap();
    let (_writer, waiting) = client
        .request(
            http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0,
        )
        .await
        .unwrap();
    let (_id, (_upload, mut response)) = transport::Connection::accept_bi(&raw_server).await.unwrap();
    response.send(Bytes::from_static(&[1, 4, 0])).await.unwrap();
    let mut waiting = waiting;
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
        let server = Connection::new(raw_server, Settings::default())
            .await
            .unwrap();
        let (_id, mut control) = transport::Connection::open_uni(&raw_client).await.unwrap();
        control.send(Bytes::copy_from_slice(bytes)).await.unwrap();
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
    let responder_task = tokio::spawn(async move {
        let (request, sender) = responder.accept().await.unwrap().unwrap();
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
    let (mut writer, response) = requester.request(parts).await.unwrap();
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
        Connection::new(raw, Settings::default()),
        Connection::new(peer, Settings::default()),
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
        requester.request(parts).await,
        Err(h3x::Error::InvalidMessage { .. })
    ));
    assert_eq!(opened.load(Ordering::Relaxed), before);
}

#[tokio::test]
async fn dropping_an_unpolled_driver_closes_the_transport() {
    let (raw, _peer) = MemoryTransport::pair();
    let (connection, driver) = h3x::Connection::new(raw.clone(), Settings::default())
        .await
        .unwrap();
    let work = driver.run(|_, _| async {});
    drop(work);
    assert!(raw.close.error.lock().unwrap().is_some());
    assert!(matches!(
        connection.closed().await,
        Err(h3x::Error::OwnerStopped)
    ));
}

#[tokio::test]
async fn dropping_unpolled_exchange_work_stops_both_directions() {
    let (raw, peer) = MemoryTransport::pair();
    let (connection, _driver) = h3x::Connection::new(raw, Settings::default())
        .await
        .unwrap();
    let parts = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let (upload, response, work) = connection.request(parts).await.unwrap();
    let (_id, (recv, send)) = transport::Connection::accept_bi(&peer).await.unwrap();
    drop(work);
    assert!(
        recv.actions
            .resets
            .lock()
            .unwrap()
            .contains(&Code::H3_REQUEST_CANCELLED)
    );
    assert!(
        send.actions
            .stops
            .lock()
            .unwrap()
            .contains(&Code::H3_REQUEST_CANCELLED)
    );
    assert!(matches!(
        upload.finish().await,
        Err(h3x::Error::OwnerStopped)
    ));
    assert!(matches!(response.await, Err(h3x::Error::OwnerStopped)));
}

#[tokio::test]
async fn receive_queue_preserves_the_transport_bytes() {
    let (raw, server) = MemoryTransport::pair();
    let server = Connection::new(server, Settings::default()).await.unwrap();
    let (_id, (_reply, mut send)) = transport::Connection::open_bi(&raw).await.unwrap();
    send.send(Bytes::from(raw_get_headers())).await.unwrap();
    let data = Bytes::from_static(&[0, 5, b'h', b'e', b'l', b'l', b'o']);
    send.send(data.clone()).await.unwrap();
    send.close().await.unwrap();
    let (request, _sender) = server.accept().await.unwrap().unwrap();
    let mut body = request.into_body();
    let received = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(received, &b"hello"[..]);
    assert_eq!(
        received.as_ptr(),
        data.slice(2..).as_ptr(),
        "queue must move Bytes, not copy it"
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn a_full_body_queue_does_not_block_control_processing() {
    let (raw, server) = MemoryTransport::pair();
    let server = Connection::new(server, Settings::default()).await.unwrap();
    let (_id, (_reply, mut send)) = transport::Connection::open_bi(&raw).await.unwrap();
    send.send(Bytes::from(raw_get_headers())).await.unwrap();
    for _ in 0..10 {
        send.send(Bytes::from_static(&[0, 1, b'x'])).await.unwrap();
    }
    let (_request, _sender) = server.accept().await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_millis(100), async {
        while send.actions.reads.load(Ordering::Relaxed) < 5 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        send.actions.reads.load(Ordering::Relaxed),
        5,
        "one HEADERS and four queued DATA chunks"
    );
    let (_id, mut control) = transport::Connection::open_uni(&raw).await.unwrap();
    control
        .send(Bytes::from_static(&[0, 4, 0, 4, 0]))
        .await
        .unwrap();
    let error = tokio::time::timeout(Duration::from_millis(100), server.closed())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.code(), Some(Code::H3_FRAME_UNEXPECTED));
}
