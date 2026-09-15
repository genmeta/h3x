use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use qbase::frame::ResetStreamError;
use tokio::io::{AsyncRead, ReadBuf};

use super::*;

/// Supply bytes followed by FIN or a transport error, and signal classification cleanup.
struct EndedStream {
    prefix: io::Cursor<Vec<u8>>,
    error: Option<io::Error>,
    dropped: Arc<Notify>,
}

impl AsyncRead for EndedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            return Pin::new(&mut self.prefix).poll_read(cx, buf);
        }
        Poll::Ready(self.error.take().map_or(Ok(()), Err))
    }
}

impl Drop for EndedStream {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

fn inject_uni(peer: &Memory, prefix: &[u8], error: Option<io::Error>) -> Arc<Notify> {
    let dropped = Arc::new(Notify::new());
    let id = peer.next_uni.get();
    peer.next_uni.set(id + 4);
    peer.outgoing_uni.push((
        id,
        Recv(Box::new(EndedStream {
            prefix: io::Cursor::new(prefix.to_vec()),
            error,
            dropped: dropped.clone(),
        })),
    ));
    dropped
}

fn reset_error(kind: io::ErrorKind) -> io::Error {
    // Even a connection-looking application error code remains a stream-local RESET.
    io::Error::new(
        kind,
        ResetStreamError::new(
            VarInt::from_u32(Error::H3_INTERNAL_ERROR.as_u64() as u32),
            VarInt::from_u32(0),
        ),
    )
}

async fn requests_survive_unclassified_end(prefix: &[u8], mut error: Option<io::Error>) {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    for request_index in 0..2 {
        let (received, served) = tokio::join!(
            request_on(
                &client,
                client::Request::post("https://example.com/echo")
                    .unwrap()
                    .body(Bytes::from_static(b"hello")),
                |response| async {
                    assert_eq!(response.status(), http::StatusCode::OK);
                    let client::Response::Streaming(mut response) = response else {
                        panic!("expected a streaming echo response")
                    };
                    let mut bytes = [0; 5];
                    response.read_all(&mut bytes).await?;
                    assert_eq!(&bytes, b"hello");
                    Ok(())
                }
            ),
            accept_on(&server, |request| async {
                if request_index == 0 {
                    // End the extra stream while a normal request is still in flight.
                    let dropped = inject_uni(client.transport(), prefix, error.take());
                    dropped.notified().await;
                    assert_eq!(server.error(), None);
                    assert_eq!(client.error(), None);
                }
                let server::Request::Streaming(mut request) = request else {
                    panic!("expected a streaming request")
                };
                let mut bytes = [0; 5];
                request.read_all(&mut bytes).await?;
                assert_eq!(&bytes, b"hello");
                let mut response = server::Response::<Bytes>::default();
                response
                    .set_status(http::StatusCode::OK)
                    .set_body(Bytes::copy_from_slice(&bytes));
                Ok(response)
            })
        );
        received.unwrap();
        served.unwrap();
        assert_eq!(client.error(), None);
        assert_eq!(server.error(), None);
    }
}

#[tokio::test]
async fn empty_uni_fin_preserves_current_and_subsequent_requests() {
    requests_survive_unclassified_end(&[], None).await;
}

#[tokio::test]
async fn partial_uni_type_fin_preserves_current_and_subsequent_requests() {
    for (len, first) in [(2, 0x40), (4, 0x80), (8, 0xc0)] {
        let mut prefix = [0; 8];
        prefix[0] = first;
        for end in 1..len {
            requests_survive_unclassified_end(&prefix[..end], None).await;
        }
    }
}

#[tokio::test]
async fn uni_reset_before_type_preserves_current_and_subsequent_requests() {
    for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
        for prefix in [&[][..], &[0x40][..], &[0xc0, 0, 0][..]] {
            requests_survive_unclassified_end(prefix, Some(reset_error(kind))).await;
        }
    }
}

#[tokio::test]
async fn unclassified_uni_read_errors_preserve_connection_errors() {
    for prefix in [&[][..], &[0x40][..]] {
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::TimedOut,
        ] {
            for protocol_error in [None, Some(Error::H3_EXCESSIVE_LOAD)] {
                let (a, b) = pair();
                let connection = H3Connection::new(a);
                let error = protocol_error.map_or_else(
                    || io::Error::from(kind),
                    |error| io::Error::new(kind, error),
                );
                let expected = protocol_error.unwrap_or(if kind == io::ErrorKind::UnexpectedEof {
                    Error::H3_FRAME_ERROR
                } else {
                    Error::H3_INTERNAL_ERROR
                });
                inject_uni(&b, prefix, Some(error));
                assert_eq!(
                    wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)
                        .await,
                    Err(expected)
                );
                assert_eq!(connection.error(), Some(expected));
            }
        }
    }
}

#[tokio::test]
async fn identified_critical_stream_fin_and_reset_still_close_connection() {
    for prefix in [
        &[0][..],
        &[2][..],
        &[3][..],
        &[0x40, 0][..],
        &[0x80, 0, 0, 2][..],
        &[0xc0, 0, 0, 0, 0, 0, 0, 3][..],
    ] {
        for reset in [false, true] {
            let (a, b) = pair();
            let connection = H3Connection::new(a);
            inject_uni(
                &b,
                prefix,
                reset.then(|| reset_error(io::ErrorKind::BrokenPipe)),
            );
            assert_eq!(
                wait_for_transport(connection.transport(), &connection.qpack, &connection.bi).await,
                Err(Error::H3_CLOSED_CRITICAL_STREAM)
            );
        }
    }
}

#[tokio::test]
async fn ended_unclassified_streams_do_not_block_following_control_stream() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    // Ended unclassified streams must not starve the following control stream.
    for _ in 0..32 {
        inject_uni(&b, &[], None);
        inject_uni(&b, &[0x40], Some(reset_error(io::ErrorKind::BrokenPipe)));
    }
    let (_, mut control) = b.open_uni_stream().await.unwrap().unwrap();
    control.write_all(&[0, 4, 0, 7, 1, 1]).await.unwrap();
    assert_eq!(
        wait_for_transport(connection.transport(), &connection.qpack, &connection.bi).await,
        Err(Error::H3_ID_ERROR)
    );
    assert!(connection.peer_settings_received());
}

#[tokio::test]
async fn partial_stream_type_resumes_after_an_unknown_stream_is_discarded() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let (_, mut control) = b.open_uni_stream().await.unwrap().unwrap();
    let peer = async {
        // More than the three-byte transport buffer forces a partial type read.
        control.write_all(&[0xc0, 0, 0, 0, 0, 0]).await.unwrap();
        inject_uni(&b, &[0x21], None).notified().await;
        assert_eq!(connection.error(), None);
        // Finish the control type, then SETTINGS and an invalid server GOAWAY.
        let _ = control.write_all(&[0, 0, 4, 0, 7, 1, 1]).await;
        std::future::pending::<()>().await
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::select! {
            result = wait_for_transport(connection.transport(), &connection.qpack, &connection.bi) => result,
            _ = peer => unreachable!(),
        }
    })
    .await
    .expect("partial type read must resume after classifying another stream");
    assert_eq!(result, Err(Error::H3_ID_ERROR));
    assert!(connection.peer_settings_received());
}

#[tokio::test]
async fn duplicate_qpack_streams_close_connection() {
    for stream_type in [2, 3] {
        let (a, b) = pair();
        let connection = H3Connection::new(a);
        let (_, mut one) = b.open_uni_stream().await.unwrap().unwrap();
        one.write_all(&[stream_type]).await.unwrap();
        let (_, mut two) = b.open_uni_stream().await.unwrap().unwrap();
        // Uniqueness depends on the type's value, not its varint encoding.
        two.write_all(&[0x40, stream_type]).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            wait_for_transport(connection.transport(), &connection.qpack, &connection.bi),
        )
        .await
        .expect("duplicate QPACK streams must close the connection");
        assert_eq!(result, Err(Error::H3_STREAM_CREATION_ERROR));
    }
}

#[tokio::test]
async fn slow_unclassified_stream_does_not_block_control_and_wrong_goaway_is_rejected() {
    let (a, b) = pair();
    let connection = H3Connection::new(a);
    let peer = async {
        let (_, mut slow) = b.open_uni_stream().await.unwrap().unwrap();
        slow.write_all(&[0x40]).await.unwrap();
        let (_, mut control) = b.open_uni_stream().await.unwrap().unwrap();
        control.write_all(&[0, 4, 0, 7, 1, 1]).await.unwrap();
        std::future::pending::<()>().await
    };
    tokio::pin!(peer);
    assert_eq!(
        tokio::select! { result=wait_for_transport(connection.transport(), &connection.qpack, &connection.bi)=>result, _=&mut peer=>unreachable!() },
        Err(Error::H3_ID_ERROR)
    );
    assert!(connection.peer_settings_received());
}
