use super::*;

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
