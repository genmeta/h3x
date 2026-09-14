use std::{
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Wake, Waker},
};

use tokio::io::AsyncReadExt;

use super::*;
use crate::protocol::stream::control;

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn graceful_shutdown_stops_admission_and_survives_cancelling_goaway_before_the_driver_runs() {
    for use_goaway in [false, true] {
        let (transport, peer) = pair();
        transport.blocked_open.set(true);
        let connection = H3Connection::new(transport);
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut open = pin!(connection.open_bi());
        let mut accept = pin!(connection.accept_bi());
        assert!(open.as_mut().poll(&mut cx).is_pending());
        assert!(accept.as_mut().poll(&mut cx).is_pending());

        if use_goaway {
            let mut sending = pin!(connection.goaway());
            assert!(sending.as_mut().poll(&mut cx).is_pending());
            // Dropping the wait before the driver runs must still send GOAWAY.
        } else {
            connection.close(Error::H3_NO_ERROR);
        }
        assert!(matches!(
            *connection.uni.goaway.state.lock().unwrap(),
            GoawayState::Draining { boundary: 0, .. }
        ));
        assert!(wakes.0.load(Ordering::SeqCst) >= 2);
        assert_eq!(open.await.err(), Some(Error::H3_REQUEST_REJECTED));
        assert_eq!(accept.await.err(), Some(Error::H3_REQUEST_REJECTED));
        assert_eq!(
            connection.open_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        assert_eq!(
            connection.accept_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        assert_eq!(connection.transport.ended.0.get(), None);
        assert_eq!(connection.error(), None);

        // Even an empty connection must finish SETTINGS and GOAWAY before closing.
        let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
        assert_eq!(recv.read_u8().await.unwrap(), 0);
        assert!(matches!(
            control::read(&mut recv, true).await.unwrap(),
            H3Frame::Settings(_)
        ));
        let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
            panic!("close must send GOAWAY");
        };
        assert_eq!(frame.payload.id.into_u64(), 0);
        if use_goaway {
            assert_waiting_for_idle(&connection).await;
            expire_transport(&connection).await;
        }
        connection.closed().await.unwrap();
        assert_eq!(connection.error(), Some(Error::H3_NO_ERROR));
    }
}

#[tokio::test]
async fn graceful_shutdown_preserves_io_and_waits_for_both_halves_with_retained_handles() {
    for use_goaway in [false, true] {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();

        if use_goaway {
            server.goaway().await.unwrap();
            server.goaway().await.unwrap();
        } else {
            server.close(Error::H3_NO_ERROR);
            server.close(Error::H3_NO_ERROR);
        }
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.received_goaway(), Some(4));
        assert_eq!(server.error(), None);
        let closed = server.closed();
        tokio::pin!(closed);

        send.write_all(b"req").await.unwrap();
        let mut bytes = [0; 3];
        peer_recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"req");
        peer_send.write_all(b"res").await.unwrap();
        recv.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"res");
        peer_send.shutdown().await.unwrap();
        assert_eq!(recv.read(&mut bytes).await.unwrap(), 0);
        send.shutdown().await.unwrap();
        poll_fn(|cx| {
            assert!(closed.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        assert_eq!(peer_recv.read(&mut bytes).await.unwrap(), 0);
        if use_goaway {
            assert_waiting_for_idle(&server).await;
            expire_transport(&server).await;
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), closed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(server.bi.len(), 0);
        // EOF/FIN remains successful even when the application retains the handles.
        assert_eq!(peer_recv.read(&mut bytes).await.unwrap(), 0);
        peer_send.shutdown().await.unwrap();
        assert_eq!(server.error(), Some(Error::H3_NO_ERROR));
    }
}

#[tokio::test]
async fn dropping_the_last_half_completes_graceful_close() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (send, recv) = client.open_bi().await.unwrap();
    let _peer_halves = server.accept_bi().await.unwrap();
    client.close(Error::H3_NO_ERROR);
    while server.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    drop(recv);
    let closed = client.closed();
    tokio::pin!(closed);
    poll_fn(|cx| {
        assert!(closed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(send);
    closed.await.unwrap();
    assert_eq!(client.bi.len(), 0);
}

#[tokio::test]
async fn close_waits_for_a_partial_goaway_write_even_without_active_streams() {
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0);
    control::read(&mut recv, true).await.unwrap();
    // Model the boundary left after sixteen previously accepted streams finished.
    *connection.uni.goaway.state.lock().unwrap() = GoawayState::Open {
        accepted_boundary: 64,
        peer: None,
    };
    connection.close(Error::H3_NO_ERROR);
    tokio::task::yield_now().await;
    assert_eq!(connection.transport.ended.0.get(), None);
    assert_eq!(connection.error(), None);

    let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
        panic!("expected GOAWAY");
    };
    assert_eq!(frame.payload.id.into_u64(), 64);
    connection.closed().await.unwrap();
}

#[tokio::test]
async fn draining_rejects_late_streams_and_preserves_an_admitted_stream() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (mut send, recv) = client.open_bi().await.unwrap();
    let (peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
    server.close(Error::H3_NO_ERROR);
    while client.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    // Bypass the application API to model a request arriving after the boundary.
    let (_, (mut late_recv, mut late_send)) =
        client.transport.open_bi_stream().await.unwrap().unwrap();
    assert_eq!(late_recv.read(&mut [0]).await.unwrap(), 0);
    assert!(late_send.write_all(b"late").await.is_err());
    assert_eq!(server.bi.len(), 1);
    send.write_all(b"x").await.unwrap();
    let mut byte = [0];
    peer_recv.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"x");
    assert_eq!(server.error(), None);
    drop((send, recv, peer_send, peer_recv));
    server.closed().await.unwrap();
}

#[tokio::test]
async fn qpack_keeps_processing_dynamic_fields_while_draining() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let halves = client.open_bi().await.unwrap();
    let peer_halves = server.accept_bi().await.unwrap();
    while !client.peer_settings_received() || !server.peer_settings_received() {
        tokio::task::yield_now().await;
    }
    server.close(Error::H3_NO_ERROR);
    for (sender, receiver) in [(&server, &client), (&client, &server)] {
        let fields = vec![qpack::Field {
            name: Bytes::from_static(b"x-draining"),
            value: Bytes::from_static(b"still-processing"),
            never_index: false,
        }];
        let encoded = sender.qpack().encode(0, fields.clone()).unwrap();
        assert_ne!(
            encoded[0], 0,
            "decoding must require dynamic encoder instructions"
        );
        assert_eq!(receiver.qpack().decode(0, encoded).await.unwrap(), fields);
    }
    assert_eq!(client.error(), None);
    assert_eq!(server.error(), None);
    drop((halves, peer_halves));
    server.closed().await.unwrap();
}

#[tokio::test]
async fn an_error_during_draining_terminates_immediately() {
    let (transport, _peer) = pair();
    let connection = H3Connection::new(transport);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    connection.close(Error::H3_NO_ERROR);
    assert_eq!(connection.error(), None);
    connection.close(Error::H3_INTERNAL_ERROR);
    connection.close(Error::H3_NO_ERROR);
    assert_eq!(connection.closed().await, Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(
        Error::from(recv.read(&mut [0]).await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(
        Error::from(send.write_all(b"x").await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(connection.bi.len(), 0);
}

#[tokio::test]
async fn a_goaway_write_failure_ends_graceful_close_with_the_protocol_error() {
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (_, mut recv) = peer.accept_uni_stream().await.unwrap();
    assert_eq!(recv.read_u8().await.unwrap(), 0);
    control::read(&mut recv, true).await.unwrap();
    drop(recv);
    connection.close(Error::H3_NO_ERROR);
    assert_eq!(
        connection.closed().await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
}

#[tokio::test]
async fn simultaneous_repeated_close_finishes_without_polling_closed() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    for _ in 0..3 {
        client.close(Error::H3_NO_ERROR);
        server.close(Error::H3_NO_ERROR);
    }
    // Waiting on the transport demonstrates that closed() does not drive shutdown.
    assert_eq!(client.transport.terminated().await, Error::H3_NO_ERROR);
    let (a, b) = tokio::join!(client.closed(), server.closed());
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn dropping_connection_stops_partial_critical_io() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let qpack = connection.qpack().clone();
    let transport = Arc::downgrade(&connection.transport);
    let uni = Arc::downgrade(&connection.uni);
    tokio::task::yield_now().await;
    drop(connection);
    assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
    assert_eq!(b.terminated().await, Error::H3_NO_ERROR);
    tokio::task::yield_now().await;
    assert!(
        transport.upgrade().is_none() && uni.upgrade().is_none(),
        "driver must release the transport and unidirectional stream state"
    );
}

#[tokio::test]
async fn closing_connection_releases_owned_streams_and_wakes_pending_io() {
    use tokio::io::{AsyncRead, ReadBuf};
    let (a, _b) = pair();
    let connection = H3Connection::new(a);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut bytes = [0];
    let mut buf = ReadBuf::new(&mut bytes);
    poll_fn(|cx| {
        assert!(
            std::pin::Pin::new(&mut recv)
                .poll_read(cx, &mut buf)
                .is_pending()
        );
        Poll::Ready(())
    })
    .await;
    connection.close(Error::H3_INTERNAL_ERROR);
    assert_eq!(connection.bi.len(), 0);
    let result = poll_fn(|cx| std::pin::Pin::new(&mut recv).poll_read(cx, &mut buf)).await;
    assert_eq!(Error::from(result.unwrap_err()), Error::H3_INTERNAL_ERROR);
    assert_eq!(
        Error::from(send.write_all(b"x").await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    drop(connection);
    assert_eq!(
        Error::from(send.flush().await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
}

#[tokio::test]
async fn close_before_driver_is_polled_preserves_error() {
    let (a, _b) = pair();
    let connection = H3Connection::new(a);
    connection.close(Error::H3_INTERNAL_ERROR);
    assert_eq!(connection.closed().await, Err(Error::H3_INTERNAL_ERROR));
    tokio::task::yield_now().await;
    assert!(connection.task.is_finished());
    assert_eq!(
        connection.open_bi().await.err(),
        Some(Error::H3_INTERNAL_ERROR)
    );
}

#[tokio::test]
async fn dropping_connection_during_initialization_closes_before_aborting_driver() {
    let (a, _b) = pair();
    let connection = H3Connection::new(a);
    let qpack = connection.qpack().clone();
    // The tiny transport buffer leaves SETTINGS partially written.
    tokio::task::yield_now().await;
    drop(connection);
    assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
}

#[tokio::test]
async fn close_wakes_pending_stream_operations_and_preserves_first_error() {
    let (transport, _peer) = pair();
    transport.blocked_open.set(true);
    let connection = H3Connection::new(transport);
    let open = connection.open_bi();
    let accept = connection.accept_bi();
    tokio::pin!(open, accept);
    poll_fn(|cx| {
        assert!(open.as_mut().poll(cx).is_pending());
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    connection.close(Error::H3_INTERNAL_ERROR);
    connection.close(Error::H3_NO_ERROR);
    assert_eq!(open.await.err(), Some(Error::H3_INTERNAL_ERROR));
    assert_eq!(accept.await.err(), Some(Error::H3_INTERNAL_ERROR));
    assert_eq!(connection.closed().await, Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(connection.goaway().await, Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(connection.qpack().error(), Some(Error::H3_INTERNAL_ERROR));
}
