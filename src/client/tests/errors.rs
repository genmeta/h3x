use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{io::AsyncWrite, time::timeout};

use super::*;
use crate::protocol::qpack::Field;

struct FailingWriter;
impl AsyncWrite for FailingWriter {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "upload peer stopped reading",
        )))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn upload_failure_reaches_response_waiter_for_both_body_modes() {
    for streaming in [false, true] {
        let connection = crate::test_support::connection();
        let (_peer, recv) = duplex(64); // Peer never sends a response.
        let outgoing: common::Request<Write> = if streaming {
            Request::streaming_post("https://example.com/upload")
                .unwrap()
                .into()
        } else {
            Request::<Bytes>::get("https://example.com/")
                .unwrap()
                .into()
        };
        let error = timeout(
            Duration::from_secs(1),
            request(
                outgoing,
                H3ReadStream::new(0, recv),
                H3WriteStream::new(0, FailingWriter),
                connection.qpack().clone(),
            ),
        )
        .await
        .expect("upload failure must wake response reception")
        .err()
        .unwrap();
        assert_eq!(error.code, ErrorCode::H3_INTERNAL_ERROR);
        assert_eq!(error.reason, "upload peer stopped reading");
        assert!(
            connection.qpack().error().is_none(),
            "local upload failures must not close the connection"
        );
    }
}

#[tokio::test]
async fn successful_upload_still_waits_for_response() {
    for streaming in [false, true] {
        let connection = crate::test_support::connection();
        let (_peer, recv) = duplex(64);
        let outgoing: common::Request<Write> = if streaming {
            let mut request = Request::streaming_post("https://example.com/").unwrap();
            request.finish().await.unwrap();
            request.into()
        } else {
            Request::<Bytes>::get("https://example.com/")
                .unwrap()
                .into()
        };
        let result = timeout(
            Duration::from_millis(100),
            request(
                outgoing,
                H3ReadStream::new(0, recv),
                H3WriteStream::new(0, tokio::io::sink()),
                connection.qpack().clone(),
            ),
        )
        .await;
        assert!(
            result.is_err(),
            "successful upload must still wait for the response"
        );
    }
}

fn headers_frame(qpack: &Qpack, fields: Vec<Field>) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.put_frame(
        &Frame::new(Headers {
            field_section: qpack.encode(0, fields).unwrap(),
        })
        .unwrap(),
    );
    wire
}

fn field(name: &'static [u8], value: &'static [u8]) -> Field {
    Field {
        name: Bytes::from_static(name),
        value: Bytes::from_static(value),
        never_index: false,
    }
}

#[tokio::test]
async fn malformed_http_headers_leave_the_connection_usable() {
    let connection = crate::test_support::connection();
    let qpack = connection.qpack().clone();
    let wire = headers_frame(&qpack, vec![field(b"x-test", b"missing status")]);
    let error = read_response(H3ReadStream::new(0, Cursor::new(wire)), qpack.clone(), None)
        .await
        .err()
        .unwrap();
    assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
    tokio::task::yield_now().await;
    assert!(qpack.error().is_none());
    assert!(qpack.encode(4, vec![field(b":status", b"200")]).is_ok());
}
