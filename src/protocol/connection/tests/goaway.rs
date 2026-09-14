use super::*;

#[tokio::test]
async fn goaway_stops_new_opens_and_preserves_admitted_streams() {
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
        server.goaway().await.unwrap();
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            client.open_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        let mut byte = [0];
        let (written, read) = tokio::join!(send.write_all(b"x"), peer_recv.read_exact(&mut byte));
        written.unwrap();
        read.unwrap();
        assert_eq!(&byte, b"x");
        drop((recv, send, peer_recv, peer_send));
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
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
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    assert_eq!(client.bi.len(), 1);
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

    // The server has not accepted stream 0, so GOAWAY excludes it.
    server.goaway().await.unwrap();
    while client.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    assert_eq!(client.received_goaway(), Some(0));
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
    assert_eq!(client.bi.len(), 0);
    drop(recv);
    drop(send);
    tokio::task::yield_now().await;
    assert_eq!(client.bi.len(), 0);
}

#[tokio::test]
async fn lowering_peer_goaway_rejects_only_streams_at_or_above_the_boundary() {
    use tokio::io::AsyncReadExt;
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (mut send0, recv0) = client.open_bi().await.unwrap();
    let (mut send4, recv4) = client.open_bi().await.unwrap();
    let (_peer_send0, mut peer_recv0) = server.accept_bi().await.unwrap();
    let (_peer_send4, mut peer_recv4) = server.accept_bi().await.unwrap();
    server.goaway().await.unwrap();
    while client.received_goaway() != Some(8) {
        tokio::task::yield_now().await;
    }
    send4.write_all(b"a").await.unwrap();
    let mut byte = [0];
    peer_recv4.read_exact(&mut byte).await.unwrap();
    // A peer may lower its boundary in a subsequent GOAWAY.
    let (completed, completion) = oneshot::channel();
    server
        .uni
        .control
        .sender
        .send((
            H3Frame::Goaway(
                Frame::new(frame::Goaway {
                    id: VarInt::from_u32(4),
                })
                .unwrap(),
            ),
            completed,
        ))
        .await
        .unwrap();
    completion.await.unwrap().unwrap();
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
    drop((send0, recv0, send4, recv4));
    assert_eq!(client.bi.len(), 1);
    client.bi.cleanup();
    assert_eq!(client.bi.len(), 0);
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
async fn local_goaway_wakes_pending_accept_without_message_parsing() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        let accept = server.accept_bi();
        tokio::pin!(accept);
        poll_fn(|cx| {
            assert!(accept.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        server.goaway().await.unwrap();
        assert_eq!(accept.await.err(), Some(Error::H3_REQUEST_REJECTED));
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn peer_goaway_interrupts_a_pending_transport_open() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        client.transport.blocked_open.set(true);
        let open = client.open_bi();
        tokio::pin!(open);
        poll_fn(|cx| {
            assert!(open.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        server.goaway().await.unwrap();
        assert_eq!(open.await.err(), Some(Error::H3_REQUEST_REJECTED));
        assert_eq!(client.transport.next_bi.get(), 0);
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn immediate_goaway_waits_for_initial_settings() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    server.goaway().await.unwrap();
    for _ in 0..1000 {
        if client.received_goaway().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(client.peer_settings_received());
    assert_eq!(client.received_goaway(), Some(0));
    assert_eq!(
        client.open_bi().await.err(),
        Some(Error::H3_REQUEST_REJECTED)
    );
}

#[tokio::test]
async fn cancelling_goaway_wait_keeps_partial_frame_owned_by_driver() {
    use tokio::io::AsyncReadExt;

    use crate::protocol::stream::control;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0);
    assert!(matches!(
        control::read(&mut recv, true).await.unwrap(),
        H3Frame::Settings(_)
    ));
    connection
        .uni
        .goaway
        .state
        .lock()
        .unwrap()
        .accepted_boundary = 64;

    let mut sending = Box::pin(connection.goaway());
    poll_fn(|cx| {
        assert!(sending.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    // This four-byte frame cannot fit in the three-byte transport buffer.
    assert_eq!(recv.read_u8().await.unwrap(), 7);
    drop(sending);
    let mut remainder = [0; 3];
    recv.read_exact(&mut remainder).await.unwrap();
    assert_eq!(remainder, [2, 0x40, 0x40]);
    assert_eq!(connection.error(), None);

    let (sent, received) = tokio::join!(connection.goaway(), control::read(&mut recv, false));
    sent.unwrap();
    let H3Frame::Goaway(frame) = received.unwrap() else {
        panic!()
    };
    assert_eq!(frame.payload.id.into_u64(), 64);
    assert_eq!(connection.error(), None);
}

#[tokio::test]
async fn goaway_write_failure_closes_connection() {
    use tokio::io::AsyncReadExt;

    use crate::protocol::stream::control;

    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0);
    control::read(&mut recv, true).await.unwrap();
    drop(recv);
    assert_eq!(
        connection.goaway().await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
    assert_eq!(
        connection.closed().await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
}

#[tokio::test]
async fn concurrent_goaways_follow_settings() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (first, second, third) = tokio::join!(server.goaway(), server.goaway(), server.goaway());
    first.unwrap();
    second.unwrap();
    third.unwrap();
    for _ in 0..1000 {
        if client.received_goaway().is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(client.peer_settings_received());
    assert_eq!(client.received_goaway(), Some(0));
    assert_eq!(client.error(), None);
    assert_eq!(server.error(), None);
}
