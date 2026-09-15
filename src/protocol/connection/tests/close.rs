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

/// Start closing while retaining ownership in the returned future.
async fn start_close(
    connection: H3Connection<Memory>,
) -> std::pin::Pin<Box<impl Future<Output = Result<()>>>> {
    let mut closing = Box::pin(wait_for_drain(connection));
    poll_fn(|cx| {
        assert!(closing.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    closing
}

#[tokio::test]
async fn peer_goaway_replies_while_pending_stream_operations_wait_for_transport() {
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

    let _reply = acknowledge_goaway(&peer, 0).await;
    while connection.cursor.lock().unwrap().sent().is_none() {
        tokio::task::yield_now().await;
    }
    assert!(matches!(
        *connection.cursor.lock().unwrap(),
        StreamCursor {
            local: StreamView::Gone(1),
            ..
        }
    ));
    assert!(open.as_mut().poll(&mut cx).is_pending());
    assert!(accept.as_mut().poll(&mut cx).is_pending());
    assert_eq!(connection.transport().ended.0.get(), None);
    assert_eq!(connection.error(), None);

    // Even an empty connection must finish SETTINGS and GOAWAY before closing.
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    assert!(matches!(
        control::read(&mut recv, true).await.unwrap(),
        H3Frame::Settings(_)
    ));
    let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
        panic!("close must send GOAWAY");
    };
    assert_eq!(frame.payload.id.into_u64(), 1);
    assert_closed(&connection).await;
    assert!(wakes.0.load(Ordering::SeqCst) >= 2);
    assert_eq!(accept.await.err(), Some(Error::H3_NO_ERROR));
    assert_eq!(open.await.err(), Some(Error::H3_NO_ERROR));
    wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
        .await
        .unwrap();
    assert_eq!(connection.error(), Some(Error::H3_NO_ERROR));
}

#[tokio::test]
async fn graceful_shutdown_preserves_io_and_waits_for_both_halves_with_retained_handles() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();

    let observed = observe(&server);
    server.goaway().await.unwrap();
    let server = observed;
    while client.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    assert_eq!(client.received_goaway(), Some(4));
    assert_eq!(server.error(), None);
    let closed = wait_for_transport(server.transport(), &server.qpack, &server.bi);
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
    server.assert_closed().await;
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

#[tokio::test]
async fn dropping_the_last_half_completes_graceful_close() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (send, recv) = client.open_bi().await.unwrap();
    let _peer_halves = server.accept_bi().await.unwrap();
    let bi = client.bi.clone();
    let closed = wait_for_drain(client);
    tokio::pin!(closed);
    poll_fn(|cx| {
        assert!(closed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    while server.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    drop(recv);
    poll_fn(|cx| {
        assert!(closed.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(send);
    closed.await.unwrap();
    assert_eq!(bi.len(), 0);
}

#[tokio::test]
async fn dropping_last_response_producer_completes_graceful_close() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (a, b) = pair();
        let client = H3Connection::new(a);
        let server = H3Connection::new(b);
        let (mut request_send, mut response_recv) = client.open_bi().await.unwrap();
        let (response_send, mut request_recv) = server.accept_bi().await.unwrap();
        request_send.shutdown().await.unwrap();
        assert_eq!(request_recv.read(&mut [0]).await.unwrap(), 0);

        let mut response = server::Response::<Bytes>::default();
        response.set_status(http::StatusCode::OK);
        let response = response.streaming(1);
        let producer = response.clone();
        let sending = server::respond(
            response,
            response_send,
            server.qpack().clone(),
            &http::Method::GET,
        );
        tokio::pin!(sending);
        tokio::select! {
            result = &mut sending => panic!("the unfinished response completed: {result:?}"),
            headers = frame::be_frame(&mut response_recv) => {
                assert!(matches!(headers.unwrap(), H3Frame::Headers(_)));
            }
        }
        poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        let bi = server.bi.clone();
        let transport = server.transport().clone();
        let qpack = server.qpack().clone();
        let closed = start_close(server).await;
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        tokio::pin!(closed);
        poll_fn(|cx| {
            assert!(closed.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(bi.len(), 1);
        assert_eq!(transport.close_calls.get(), 0);

        drop(producer);
        assert_eq!((&mut sending).await, Err(Error::H3_REQUEST_CANCELLED));
        closed.await.unwrap();
        assert_eq!(bi.len(), 0);
        assert!(transport.close_calls.get() >= 1);
        assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
    })
    .await
    .expect("producer Drop must cancel the response and release graceful close");
}

#[tokio::test]
async fn close_waits_for_a_partial_goaway_write_even_without_active_streams() {
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    control::read(&mut recv, true).await.unwrap();
    // Model the boundary left after sixteen previously accepted streams finished.
    connection.cursor.lock().unwrap().local = StreamView::Max(60);
    let transport = connection.transport().clone();
    let qpack = connection.qpack().clone();
    let closing = start_close(connection).await;
    tokio::task::yield_now().await;
    assert_eq!(transport.ended.0.get(), None);
    assert_eq!(qpack.error(), None);

    let H3Frame::Goaway(frame) = control::read(&mut recv, false).await.unwrap() else {
        panic!("expected GOAWAY");
    };
    assert_eq!(frame.payload.id.into_u64(), 64);
    let _reply = acknowledge_goaway(&peer, 1).await;
    closing.await.unwrap();
}

#[tokio::test]
async fn draining_rejects_late_streams_and_preserves_an_admitted_stream() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (mut send, recv) = client.open_bi().await.unwrap();
    let (peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
    let bi = server.bi.clone();
    let qpack = server.qpack().clone();
    let closing = start_close(server).await;
    while client.received_goaway().is_none() {
        tokio::task::yield_now().await;
    }
    // Bypass the application API to model a request arriving after the boundary.
    let (_, (mut late_recv, mut late_send)) =
        client.transport().open_bi_stream().await.unwrap().unwrap();
    assert_eq!(late_recv.read(&mut [0]).await.unwrap(), 0);
    assert!(late_send.write_all(b"late").await.is_err());
    assert_eq!(bi.len(), 1);
    send.write_all(b"x").await.unwrap();
    let mut byte = [0];
    peer_recv.read_exact(&mut byte).await.unwrap();
    assert_eq!(&byte, b"x");
    assert_eq!(qpack.error(), None);
    drop((send, recv, peer_send, peer_recv));
    closing.await.unwrap();
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
    let server_qpack = server.qpack().clone();
    let client_qpack = client.qpack().clone();
    let closing = start_close(server).await;
    for (sender, receiver) in [
        (&server_qpack, &client_qpack),
        (&client_qpack, &server_qpack),
    ] {
        let fields = vec![qpack::Field {
            name: Bytes::from_static(b"x-draining"),
            value: Bytes::from_static(b"still-processing"),
            never_index: false,
        }];
        let encoded = sender.encode(0, fields.clone()).unwrap();
        assert_ne!(
            encoded[0], 0,
            "decoding must require dynamic encoder instructions"
        );
        assert_eq!(receiver.decode(0, encoded).await.unwrap(), fields);
    }
    assert_eq!(client.error(), None);
    assert_eq!(server_qpack.error(), None);
    drop((halves, peer_halves));
    closing.await.unwrap();
}

#[tokio::test]
async fn an_error_during_draining_terminates_immediately() {
    let (transport, _peer) = pair();
    let connection = H3Connection::new(transport);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let bi = connection.bi.clone();
    let qpack = connection.qpack().clone();
    let closing = start_close(connection).await;
    qpack.on_error(Error::H3_INTERNAL_ERROR);
    assert_eq!(closing.await, Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(
        Error::from(recv.read(&mut [0]).await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(
        Error::from(send.write_all(b"x").await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(bi.len(), 0);
}

#[tokio::test]
async fn a_goaway_write_failure_ends_graceful_close_with_the_protocol_error() {
    let (peer, transport) = pair();
    let connection = H3Connection::new(transport);
    let (mut recv, _qpack_streams) = receive_control_stream(&peer).await;
    control::read(&mut recv, true).await.unwrap();
    drop(recv);
    assert_eq!(
        wait_for_drain(connection).await,
        Err(Error::H3_CLOSED_CRITICAL_STREAM)
    );
}

#[tokio::test]
async fn simultaneous_close_finishes_without_polling_closed() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let (a, b) = tokio::join!(wait_for_drain(client), wait_for_drain(server));
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn dropping_connection_stops_partial_critical_io() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let qpack = connection.qpack().clone();
    let transport = Arc::downgrade(connection.transport());
    let settings = Arc::downgrade(&connection.settings);
    let goaway = Arc::downgrade(&connection.cursor);
    tokio::task::yield_now().await;
    drop(connection);
    assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
    drop(qpack);
    assert_eq!(b.terminated().await, Error::H3_NO_ERROR);
    tokio::task::yield_now().await;
    assert!(
        transport.upgrade().is_none() && settings.upgrade().is_none() && goaway.upgrade().is_none(),
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
    let bi = connection.bi.clone();
    connection.qpack.on_error(Error::H3_INTERNAL_ERROR);
    wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
        .await
        .unwrap_err();
    drop(connection);
    assert_eq!(bi.len(), 0);
    let result = poll_fn(|cx| std::pin::Pin::new(&mut recv).poll_read(cx, &mut buf)).await;
    assert_eq!(Error::from(result.unwrap_err()), Error::H3_INTERNAL_ERROR);
    assert_eq!(
        Error::from(send.write_all(b"x").await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
    assert_eq!(
        Error::from(send.flush().await.unwrap_err()),
        Error::H3_INTERNAL_ERROR
    );
}

#[tokio::test]
async fn fatal_error_before_tasks_are_polled_preserves_error() {
    let (a, _b) = pair();
    let connection = H3Connection::new(a);
    let qpack = connection.qpack().clone();
    connection.qpack.on_error(Error::H3_INTERNAL_ERROR);
    wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
        .await
        .unwrap_err();
    drop(connection);
    tokio::task::yield_now().await;
    assert_eq!(qpack.error(), Some(Error::H3_INTERNAL_ERROR));
}

#[tokio::test]
async fn dropping_connection_during_initialization_closes_before_tasks_exit() {
    let (a, _b) = pair();
    let connection = H3Connection::new(a);
    let qpack = connection.qpack().clone();
    // The tiny transport buffer leaves SETTINGS partially written.
    tokio::task::yield_now().await;
    drop(connection);
    assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
}

#[tokio::test]
async fn driver_error_wakes_pending_stream_operations_and_preserves_first_error() {
    let (transport, _peer) = pair();
    transport.blocked_open.set(true);
    let connection = H3Connection::new(transport);
    let mut open = Box::pin(connection.open_bi());
    let mut accept = Box::pin(connection.accept_bi());
    poll_fn(|cx| {
        assert!(open.as_mut().poll(cx).is_pending());
        assert!(accept.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    super::super::close_connection(
        connection.transport().as_ref(),
        connection.qpack(),
        &connection.bi,
        Error::H3_INTERNAL_ERROR,
    );
    assert_eq!(open.await.err(), Some(Error::H3_INTERNAL_ERROR));
    assert_eq!(accept.await.err(), Some(Error::H3_INTERNAL_ERROR));
    assert_eq!(
        wait_for_transport(connection.transport(), &connection.qpack, &connection.bi).await,
        Err(Error::H3_INTERNAL_ERROR)
    );
    let qpack = connection.qpack.clone();
    assert_eq!(connection.goaway().await, Err(Error::H3_INTERNAL_ERROR));
    assert_eq!(qpack.error(), Some(Error::H3_INTERNAL_ERROR));
}

#[tokio::test]
async fn cancelling_owned_close_terminates_connection_and_driver() {
    for poll in [false, true] {
        let (transport, peer) = pair();
        let connection = H3Connection::new(transport);
        let qpack = connection.qpack().clone();
        let mut closing = Box::pin(wait_for_drain(connection));
        if poll {
            poll_fn(|cx| {
                assert!(closing.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        drop(closing);
        assert_eq!(peer.terminated().await, Error::H3_NO_ERROR);
        assert_eq!(qpack.error(), Some(Error::H3_NO_ERROR));
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn idle_timeout_without_peer_critical_streams_releases_queue_waiters() {
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let (transport, peer) = pair();
        let connection = H3Connection::new(transport);
        let (mut recv, _critical) = receive_control_stream(&peer).await;
        control::read(&mut recv, true).await.unwrap();
        let (mut send, mut read) = connection.open_bi().await.unwrap();
        let mut decoding = Box::pin(
            connection
                .qpack
                .decode(0, Bytes::from_static(&[2, 0, 0x80])),
        );
        poll_fn(|cx| {
            assert!(decoding.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        connection.transport().expire();
        assert_eq!(decoding.await, Err(Error::H3_NO_ERROR));
        wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
            .await
            .unwrap();
        assert_eq!(
            Error::from(send.write_all(b"x").await.unwrap_err()),
            Error::H3_NO_ERROR
        );
        assert_eq!(
            Error::from(read.read(&mut [0]).await.unwrap_err()),
            Error::H3_NO_ERROR
        );
        while Arc::strong_count(&connection.qpack) != 1
            || Arc::strong_count(&connection.cursor) != 1
            || Arc::strong_count(&connection.bi) != 1
        {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            connection.transport().close_calls.get(),
            0,
            "termination only cleans local resources"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fatal_request_decode_closes_transport_without_peer_critical_io() {
    let (transport, _peer) = pair();
    let connection = H3Connection::new(transport);
    let _stream = connection.open_bi().await.unwrap();
    assert_eq!(
        connection
            .qpack
            .decode(0, Bytes::from_static(&[0, 0, 0x80]))
            .await,
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        connection.transport().ended.0.get(),
        Some(Error::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
        )
        .await
        .unwrap(),
        Err(Error::QPACK_DECOMPRESSION_FAILED)
    );
    assert_eq!(connection.transport().close_calls.get(), 1);
}
