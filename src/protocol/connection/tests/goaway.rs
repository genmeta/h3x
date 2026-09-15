use super::*;

#[tokio::test]
async fn goaway_preserves_admitted_streams() {
    use tokio::io::AsyncReadExt;
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        let (mut send, recv) = client.open_bi().await.unwrap();
        let id = recv.stream_id();
        let (peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
        let peer_id = peer_recv.stream_id();
        assert_eq!(id, peer_id);
        while !server.peer_settings_received() {
            tokio::task::yield_now().await;
        }
        let observed = observe(&server);
        server.goaway().await.unwrap();
        let server = observed;
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        let mut byte = [0];
        let (written, read) = tokio::join!(send.write_all(b"x"), peer_recv.read_exact(&mut byte));
        written.unwrap();
        read.unwrap();
        assert_eq!(&byte, b"x");
        drop((recv, send, peer_recv, peer_send));
        server.assert_closed().await;
    };
    work.await;
}

#[tokio::test]
async fn peer_goaway_rejects_delivered_streams_and_wakes_both_halves() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Wake, Waker},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[derive(Default)]
    struct Wakes(AtomicUsize);

    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let admitted = client.open_bi().await.unwrap();
    let peer_admitted = server.accept_bi().await.unwrap();
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    assert_eq!(client.bi.len(), 2);
    send.write_all(b"abc").await.unwrap(); // Fill the transport's three-byte window.
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = std::task::Context::from_waker(&waker);
    let mut bytes = [0];
    let mut buf = ReadBuf::new(&mut bytes);
    assert!(
        std::pin::Pin::new(&mut recv)
            .poll_read(&mut cx, &mut buf)
            .is_pending()
    );
    assert!(
        std::pin::Pin::new(&mut send)
            .poll_write(&mut cx, b"d")
            .is_pending()
    );

    // The server accepted stream 0 but has not accepted stream 4, so GOAWAY excludes it.
    server.goaway().await.unwrap();
    while client.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    assert_eq!(client.received_goaway(), Some(4));
    assert!(wakes.0.load(Ordering::SeqCst) >= 2);
    let Poll::Ready(Err(error)) = std::pin::Pin::new(&mut recv).poll_read(&mut cx, &mut buf) else {
        panic!("GOAWAY must reject the pending read");
    };
    assert_eq!(Error::from(error), Error::H3_REQUEST_REJECTED);
    assert_eq!(
        Error::from(send.write_all(b"d").await.unwrap_err()),
        Error::H3_REQUEST_REJECTED
    );
    assert_eq!(
        Error::from(send.flush().await.unwrap_err()),
        Error::H3_REQUEST_REJECTED
    );
    assert_eq!(
        Error::from(send.shutdown().await.unwrap_err()),
        Error::H3_REQUEST_REJECTED
    );
    // GOAWAY ends both directions even while their handles are retained.
    tokio::task::yield_now().await;
    assert_eq!(client.bi.len(), 1);
    drop(recv);
    drop(send);
    tokio::task::yield_now().await;
    assert_eq!(client.bi.len(), 1);
    drop((admitted, peer_admitted));
}

#[tokio::test]
async fn lowering_peer_goaway_rejects_only_streams_at_or_above_the_boundary() {
    use tokio::io::AsyncReadExt;

    use crate::protocol::stream::control;
    let (transport, peer) = pair();
    let client = H3Connection::new(transport);
    let (mut send0, recv0) = client.open_bi().await.unwrap();
    let (mut send4, recv4) = client.open_bi().await.unwrap();
    let (_, (mut peer_recv0, _peer_send0)) = peer.accept_bi_stream().await.unwrap();
    let (_, (mut peer_recv4, _peer_send4)) = peer.accept_bi_stream().await.unwrap();
    let (mut response, _critical) = receive_control_stream(&peer).await;
    control::read(&mut response, true).await.unwrap();
    let mut incoming = acknowledge_goaway(&peer, 8).await;
    control::read(&mut response, false).await.unwrap();
    send4.write_all(b"a").await.unwrap();
    let mut byte = [0];
    peer_recv4.read_exact(&mut byte).await.unwrap();
    control::write(
        &mut incoming,
        &H3Frame::Goaway(
            Frame::new(frame::Goaway {
                id: VarInt::from_u32(4),
            })
            .unwrap(),
        ),
    )
    .await
    .unwrap();
    while client.received_goaway() != Some(4) {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        Error::from(send4.write_all(b"b").await.unwrap_err()),
        Error::H3_REQUEST_REJECTED
    );
    send0.write_all(b"c").await.unwrap();
    peer_recv0.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte, [b'c']);
    assert_eq!(client.error(), None);
    drop((send0, recv0, send4, recv4));
    assert_closed(&client).await;
}

#[tokio::test]
async fn client_goaway_does_not_reject_server_request_streams() {
    use tokio::io::AsyncReadExt;
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (_send, mut recv) = client.open_bi().await.unwrap();
    let (mut peer_send, _peer_recv) = server.accept_bi().await.unwrap();
    client.goaway().await.unwrap();
    while server.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    peer_send.write_all(b"ok").await.unwrap();
    let mut bytes = [0; 2];
    recv.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ok");
}

#[tokio::test]
async fn pending_accept_finishes_on_transport_termination_after_goaway() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        let admitted = client.open_bi().await.unwrap();
        let peer_admitted = server.accept_bi().await.unwrap();
        let accept = server.accept_bi();
        tokio::pin!(accept);
        poll_fn(|cx| {
            assert!(accept.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        client.goaway().await.unwrap();
        poll_fn(|cx| {
            assert!(accept.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop((admitted, peer_admitted));
        server.transport().expire();
        assert_eq!(accept.await.err(), Some(Error::H3_NO_ERROR));
    };
    let (b, ()) = tokio::join!(
        wait_for_transport(server.transport(), &server.qpack, &server.bi),
        work
    );
    b.unwrap();
}

#[tokio::test]
async fn peer_goaway_automatically_replies_before_finishing_pending_accept() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let admitted = client.open_bi().await.unwrap();
    let peer_admitted = server.accept_bi().await.unwrap();
    let mut accept = Box::pin(server.accept_bi());
    poll_fn(|cx| {
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    client.goaway().await.unwrap();
    assert!(server.received_goaway().is_some());
    assert!(server.error().is_none());
    poll_fn(|cx| {
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop((admitted, peer_admitted));
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), accept)
            .await
            .unwrap()
            .err(),
        Some(Error::H3_NO_ERROR)
    );
}

#[tokio::test]
async fn pending_transport_open_waits_until_termination_after_peer_goaway() {
    {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let work = async {
            let admitted = client.open_bi().await.unwrap();
            let peer_admitted = server.accept_bi().await.unwrap();
            client.transport().blocked_open.set(true);
            let mut open = Box::pin(client.open_bi());
            poll_fn(|cx| {
                assert!(open.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            server.goaway().await.unwrap();
            poll_fn(|cx| {
                assert!(open.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(client.transport().next_bi.get(), 4);
            client.transport().expire();
            assert_eq!(open.await.err(), Some(Error::H3_NO_ERROR));
            drop((admitted, peer_admitted));
            wait_for_drain(client).await.unwrap();
        };
        work.await;
    }
}

#[tokio::test]
async fn immediate_goaway_waits_for_initial_settings() {
    use crate::protocol::stream::control;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let observed = observe(&connection);
    let sending = connection.goaway();
    let connection = observed;
    tokio::pin!(sending);
    poll_fn(|cx| {
        assert!(sending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    // The initial SETTINGS does not fit in the tiny transport buffer yet.
    poll_fn(|cx| {
        assert!(sending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert!(matches!(
        control::read(&mut recv, true).await.unwrap(),
        H3Frame::Settings(_)
    ));
    let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
        panic!("expected GOAWAY after SETTINGS");
    };
    assert_eq!(frame.payload.id.into_u64(), 0);
    poll_fn(|cx| {
        assert!(sending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let _reply = acknowledge_goaway(&peer, 1).await;
    connection.assert_closed().await;
    // A completed exchange remains observable if the caller resumes after graceful termination.
    sending.await.unwrap();
}

#[tokio::test]
async fn cancelling_goaway_during_partial_write_closes_connection() {
    use tokio::io::AsyncReadExt;

    use crate::protocol::stream::control;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    assert!(matches!(
        control::read(&mut recv, true).await.unwrap(),
        H3Frame::Settings(_)
    ));
    connection.cursor.lock().unwrap().local = StreamView::Max(60);

    let observed = observe(&connection);
    let mut sending = Box::pin(connection.goaway());
    let connection = observed;
    poll_fn(|cx| {
        assert!(sending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // This four-byte frame cannot fit in the three-byte transport buffer.
    assert_eq!(recv.read_u8().await.unwrap(), 7);
    drop(sending);
    wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
        .await
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(connection.error(), Some(Error::H3_NO_ERROR));
}

#[tokio::test]
async fn qpack_remains_available_during_drain_and_stops_afterwards() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let halves = client.open_bi().await.unwrap();
    let peer_halves = server.accept_bi().await.unwrap();
    while !client.peer_settings_received() || !server.peer_settings_received() {
        tokio::task::yield_now().await;
    }
    let observed = observe(&server);
    server.goaway().await.unwrap();
    let server = observed;
    // Critical streams must remain open throughout the admitted requests.
    for (sender, receiver) in [
        (server.qpack(), client.qpack()),
        (client.qpack(), server.qpack()),
    ] {
        let fields = vec![qpack::Field {
            name: Bytes::from_static(b"x-after-drain"),
            value: Bytes::from_static(b"critical-streams-alive"),
            never_index: false,
        }];
        let encoded = sender.encode(0, fields.clone()).unwrap();
        assert_ne!(
            encoded[0], 0,
            "decoding must require dynamic QPACK instructions"
        );
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                receiver.decode(0, encoded)
            )
            .await
            .unwrap()
            .unwrap(),
            fields
        );
    }
    assert_eq!(client.error(), None);
    assert_eq!(server.error(), None);
    assert_eq!(client.transport().close_calls.get(), 0);
    assert_eq!(server.transport().close_calls.get(), 0);
    drop((halves, peer_halves));
    server.assert_closed().await;
    wait_for_transport(client.transport(), &client.qpack, &client.bi)
        .await
        .unwrap();
}

#[tokio::test]
async fn goaway_write_failure_closes_connection() {
    use crate::protocol::stream::control;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    control::read(&mut recv, true).await.unwrap();
    drop(recv);
    let observed = observe(&connection);
    assert_eq!(
        connection.goaway().await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
    assert_eq!(
        wait_for_transport(observed.transport(), &observed.qpack, &observed.bi).await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
}

#[tokio::test]
async fn owned_goaway_writes_once_and_terminates_quic_after_the_reply() {
    use tokio::io::AsyncReadExt;

    use crate::protocol::stream::control;
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let observed = observe(&connection);
    let sending = connection.goaway();
    let receiving = async {
        let (mut recv, _critical) = receive_control_stream(&peer).await;
        assert!(matches!(
            control::read(&mut recv, true).await.unwrap(),
            H3Frame::Settings(_)
        ));
        let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
            panic!()
        };
        assert_eq!(frame.payload.id.into_u64(), 0);
        let _reply = acknowledge_goaway(&peer, 1).await;
        let mut extra = Vec::new();
        recv.read_to_end(&mut extra).await.unwrap();
        assert!(
            extra.is_empty(),
            "write GOAWAY once and hold control until transport termination"
        );
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (sent, ()) = tokio::join!(sending, receiving);
        sent.unwrap();
    })
    .await
    .unwrap();
    observed.assert_closed().await;
    assert!(observed.transport.close_calls.get() >= 1);
}

#[tokio::test]
async fn symmetric_goaway_confirms_both_directions_and_preserves_admitted_io() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut client_send, _client_recv) = client.open_bi().await.unwrap();
        let (_server_send, mut server_recv) = server.accept_bi().await.unwrap();
        let (mut reverse_send, _reverse_recv) = server.open_bi().await.unwrap();
        let (_accepted_send, mut reverse_read) = client.accept_bi().await.unwrap();
        assert_eq!(reverse_send.stream_id(), 1);
        {
            let cursor = client.cursor.lock().unwrap();
            assert_eq!(cursor.local, StreamView::Max(1));
        }
        // Only the client initiates; the server must reply without an API call.
        let qpack = client.qpack.clone();
        let transport = client.transport().clone();
        let peer_goaway = client.cursor.clone();
        client.goaway().await.unwrap();
        assert_eq!(peer_goaway.lock().unwrap().peer(), Some(4));
        assert_eq!(qpack.error(), None);
        assert_eq!(transport.close_calls.get(), 0);
        assert_eq!(server.received_goaway(), Some(5));
        assert_eq!(server.error(), None);
        client_send.write_all(b"a").await.unwrap();
        reverse_send.write_all(b"b").await.unwrap();
        let mut byte = [0];
        server_recv.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'a']);
        reverse_read.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'b']);
    })
    .await
    .expect("GOAWAY exchange must not wait for admitted streams to finish");
}

#[tokio::test]
async fn missing_goaway_confirmation_does_not_succeed_on_transport_termination() {
    use crate::protocol::stream::control;
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let transport = connection.transport().clone();
    let mut exchange = Box::pin(connection.goaway());
    poll_fn(|cx| {
        assert!(exchange.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    control::read(&mut recv, true).await.unwrap();
    assert!(matches!(
        control::read(&mut recv, false).await.unwrap(),
        H3Frame::Goaway(_)
    ));
    poll_fn(|cx| {
        assert!(exchange.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    transport.expire();
    assert_eq!(exchange.await, Err(Error::H3_NO_ERROR));
}

#[tokio::test]
async fn dropping_owned_goaway_closes_and_aborts_before_or_during_exchange() {
    for poll in [false, true] {
        let (transport, peer) = pair();
        let connection = H3Connection::new(transport);
        let qpack = connection.qpack.clone();
        let transport = Arc::downgrade(connection.transport());
        let mut exchange = Box::pin(connection.goaway());
        if poll {
            poll_fn(|cx| {
                assert!(exchange.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        drop(exchange);
        assert_eq!(peer.terminated().await, Error::H3_NO_ERROR);
        assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
        tokio::task::yield_now().await;
        drop(qpack);
        tokio::task::yield_now().await;
        assert!(transport.upgrade().is_none());
    }
}

#[tokio::test]
async fn consumed_connections_release_task_resources_after_drain() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let admitted = client.open_bi().await.unwrap();
    let peer_admitted = server.accept_bi().await.unwrap();
    let transport = client.transport().clone();
    let client_cursor = Arc::downgrade(&client.cursor);
    let server_cursor = Arc::downgrade(&server.cursor);
    let client_qpack = Arc::downgrade(client.qpack());
    let server_qpack = Arc::downgrade(server.qpack());
    let (first, second) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::join!(client.goaway(), server.goaway())
    })
    .await
    .unwrap();
    first.unwrap();
    second.unwrap();
    assert_eq!(transport.ended.0.get(), None);
    assert!(client_cursor.upgrade().is_some());
    assert!(server_cursor.upgrade().is_some());
    drop((admitted, peer_admitted));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        assert_eq!(transport.terminated().await, Error::H3_NO_ERROR);
        while client_cursor.upgrade().is_some()
            || server_cursor.upgrade().is_some()
            || client_qpack.upgrade().is_some()
            || server_qpack.upgrade().is_some()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_confirmation_before_local_write_does_not_complete_goaway() {
    use crate::protocol::stream::control;

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let observed = observe(&connection);
        let mut exchange = Box::pin(connection.goaway());
        poll_fn(|cx| {
            assert!(exchange.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let _reply = acknowledge_goaway(&peer, 1).await;
        while observed.cursor.lock().unwrap().peer().is_none() {
            tokio::task::yield_now().await;
        }
        // The peer confirms while our control stream is still backpressured.
        poll_fn(|cx| {
            assert!(exchange.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
        control::read(&mut recv, true).await.unwrap();
        assert!(matches!(
            control::read(&mut recv, false).await.unwrap(),
            H3Frame::Goaway(_)
        ));
        exchange.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn queued_requests_are_drained_and_new_local_streams_do_not_extend_the_snapshot() {
    use crate::protocol::stream::control;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let _queued = peer.open_bi_stream().await.unwrap().unwrap();
        while connection.bi.len() != 1 {
            tokio::task::yield_now().await;
        }
        let (mut control_recv, _critical) = receive_control_stream(&peer).await;
        control::read(&mut control_recv, true).await.unwrap();
        let _goaway = acknowledge_goaway(&peer, 1).await;
        control::read(&mut control_recv, false).await.unwrap();
        assert_eq!(
            connection.transport().ended.0.get(),
            None,
            "queued requests are already admitted"
        );
        let admitted = connection.accept_bi().await.unwrap();
        // This stream opens after the first peer GOAWAY and is outside its drain snapshot.
        let late = connection.open_bi().await.unwrap();
        drop(admitted);
        assert_closed(&connection).await;
        drop(late);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn successful_goaway_releases_unclaimed_queued_requests() {
    use crate::protocol::stream::control;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (peer, transport) = pair();
        let connection = H3Connection::new(transport);
        let _queued = peer.open_bi_stream().await.unwrap().unwrap();
        while connection.bi.len() != 1 {
            tokio::task::yield_now().await;
        }
        let observed = observe(&connection);
        let sending = connection.goaway();
        let receiving = async {
            let (mut recv, _critical) = receive_control_stream(&peer).await;
            control::read(&mut recv, true).await.unwrap();
            let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
                panic!()
            };
            assert_eq!(frame.payload.id.into_u64(), 4);
            let _reply = acknowledge_goaway(&peer, 1).await;
            assert_eq!(peer.terminated().await, Error::H3_NO_ERROR);
        };
        let (sent, ()) = tokio::join!(sending, receiving);
        sent.unwrap();
        observed.assert_closed().await;
    })
    .await
    .unwrap();
}
