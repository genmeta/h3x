use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{io::AsyncWrite, time::timeout};

use super::*;
use crate::protocol::qpack::{ArcQpack, Field};

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
        let connection = crate::test_support::connection().await;
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
                crate::test_support::read_stream(0, recv),
                crate::test_support::write_stream(0, FailingWriter),
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
        let connection = crate::test_support::connection().await;
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
                crate::test_support::read_stream(0, recv),
                crate::test_support::write_stream(0, tokio::io::sink()),
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

fn headers_frame(qpack: &ArcQpack, fields: Vec<Field>) -> Vec<u8> {
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
async fn malformed_response_headers_and_both_trailer_paths_close_the_connection() {
    for stage in ["response headers", "response trailers", "request trailers"] {
        let connection = crate::test_support::connection().await;
        let qpack = connection.qpack().clone();
        let mut wire = match stage {
            "response headers" => Vec::new(),
            "response trailers" => headers_frame(&qpack, vec![field(b":status", b"200")]),
            _ => headers_frame(
                &qpack,
                vec![
                    field(b":method", b"GET"),
                    field(b":scheme", b"https"),
                    field(b":authority", b"example.com"),
                    field(b":path", b"/"),
                ],
            ),
        };
        // Indexed static field 99 is beyond the QPACK static table.
        wire.extend_from_slice(&[1, 4, 0, 0, 0xff, 0x24]);
        let error = if stage == "request trailers" {
            let request = crate::server::read_request(
                crate::test_support::read_stream(0, Cursor::new(wire)),
                connection.qpack().clone(),
            )
            .await
            .unwrap();
            request.into_body().collect().await.unwrap_err()
        } else {
            match read_response(
                crate::test_support::read_stream(0, Cursor::new(wire)),
                qpack.clone(),
                None,
            )
            .await
            {
                Err(error) => error,
                Ok(response) => response.into_body().collect().await.unwrap_err(),
            }
        };
        assert_eq!(error.code, ErrorCode::QPACK_DECOMPRESSION_FAILED, "{stage}");
        timeout(Duration::from_secs(1), async {
            while qpack.error().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection-scoped decode failure must close the connection");
        assert_eq!(qpack.error(), Some(error.clone()));
        assert_eq!(connection.open_bi().await.err(), Some(error));
    }
}

#[tokio::test]
async fn malformed_http_headers_leave_the_connection_usable() {
    let connection = crate::test_support::connection().await;
    let qpack = connection.qpack().clone();
    let wire = headers_frame(&qpack, vec![field(b"x-test", b"missing status")]);
    let error = read_response(
        crate::test_support::read_stream(0, Cursor::new(wire)),
        qpack.clone(),
        None,
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
    tokio::task::yield_now().await;
    assert!(qpack.error().is_none());
    assert!(qpack.encode(4, vec![field(b":status", b"200")]).is_ok());
}

#[tokio::test]
async fn frame_errors_in_headers_bodies_and_trailers_close_the_connection() {
    for stage in [
        "response headers",
        "request headers",
        "response body",
        "request body",
        "response trailers",
        "request trailers",
    ] {
        for code in [ErrorCode::H3_FRAME_ERROR, ErrorCode::H3_FRAME_UNEXPECTED] {
            let connection = crate::test_support::connection().await;
            let qpack = connection.qpack().clone();
            let request = stage.starts_with("request");
            let mut wire = if stage.ends_with("headers") {
                Vec::new()
            } else if request {
                headers_frame(
                    &qpack,
                    vec![
                        field(b":method", b"GET"),
                        field(b":scheme", b"https"),
                        field(b":authority", b"example.com"),
                        field(b":path", b"/"),
                    ],
                )
            } else {
                headers_frame(&qpack, vec![field(b":status", b"200")])
            };
            if stage.ends_with("trailers") {
                wire.extend(headers_frame(&qpack, vec![field(b"x-trailer", b"ok")]));
            }
            match code {
                // A HEADERS payload truncated before its declared length.
                ErrorCode::H3_FRAME_ERROR => wire.extend_from_slice(&[1, 2, 0]),
                // DATA after trailers, or a forbidden HTTP/2 frame elsewhere.
                _ if stage.ends_with("trailers") => wire.extend_from_slice(&[0, 0]),
                _ => wire.extend_from_slice(&[2, 0]),
            }
            let error = if request {
                match crate::server::read_request(
                    crate::test_support::read_stream(0, Cursor::new(wire)),
                    connection.qpack().clone(),
                )
                .await
                {
                    Err(error) => error,
                    Ok(request) => request.into_body().collect().await.unwrap_err(),
                }
            } else {
                match read_response(
                    crate::test_support::read_stream(0, Cursor::new(wire)),
                    qpack.clone(),
                    None,
                )
                .await
                {
                    Err(error) => error,
                    Ok(response) => response.into_body().collect().await.unwrap_err(),
                }
            };
            assert_eq!(error.code, code, "{stage}");
            assert_eq!(
                timeout(Duration::from_secs(1), connection.open_bi())
                    .await
                    .expect("frame error must terminate the transport")
                    .err(),
                Some(error.clone()),
                "{stage}",
            );
            timeout(Duration::from_secs(1), async {
                while qpack.error().is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(qpack.error(), Some(error), "{stage}");
        }
    }
}

#[tokio::test]
async fn body_message_errors_leave_the_connection_usable() {
    for request in [false, true] {
        let connection = crate::test_support::connection().await;
        let qpack = connection.qpack().clone();
        let mut fields = if request {
            vec![
                field(b":method", b"GET"),
                field(b":scheme", b"https"),
                field(b":authority", b"example.com"),
                field(b":path", b"/"),
            ]
        } else {
            vec![field(b":status", b"200")]
        };
        fields.push(field(b"content-length", b"1"));
        let wire = headers_frame(&qpack, fields);
        let error = if request {
            crate::server::read_request(
                crate::test_support::read_stream(0, Cursor::new(wire)),
                connection.qpack().clone(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap_err()
        } else {
            read_response(
                crate::test_support::read_stream(0, Cursor::new(wire)),
                qpack.clone(),
                None,
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap_err()
        };
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR);
        tokio::task::yield_now().await;
        assert!(qpack.error().is_none());
        assert!(qpack.encode(4, vec![field(b":status", b"200")]).is_ok());
    }
}

#[tokio::test]
async fn malformed_response_stops_transport_with_message_error() {
    use crate::test_support::TestStream;

    for stage in ["headers", "body", "trailers"] {
        let connection = crate::test_support::connection().await;
        let qpack = connection.qpack().clone();
        let fields = match stage {
            "headers" => vec![field(b"x-test", b"missing status")],
            "body" => vec![field(b":status", b"200"), field(b"content-length", b"1")],
            _ => vec![field(b":status", b"200")],
        };
        let mut wire = headers_frame(&qpack, fields);
        match stage {
            "body" => {
                wire.put_frame(&Frame::new(crate::protocol::frame::Data(2)).unwrap());
                wire.extend_from_slice(b"xx");
            }
            "trailers" => wire.extend(headers_frame(&qpack, vec![field(b":status", b"200")])),
            _ => {}
        }
        let (mut peer, recv) = duplex(4096);
        peer.write_all(&wire).await.unwrap();
        let recv = TestStream::new(recv);
        let stopped = recv.stopped.clone();
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            match read_response(H3ReadStream::new(0, recv), qpack.clone(), None).await {
                Err(error) => error,
                Ok(response) => response.into_body().collect().await.unwrap_err(),
            }
        })
        .await
        .unwrap();
        assert_eq!(error.code, ErrorCode::H3_MESSAGE_ERROR, "{stage}");
        assert_eq!(
            *stopped.lock().unwrap(),
            [ErrorCode::H3_MESSAGE_ERROR.as_u64()],
            "{stage}"
        );
        assert!(qpack.error().is_none());
    }
}
