use std::{
    future::Future,
    task::{Context, Waker},
    time::Duration,
};

use qbase::sid::{Dir, StreamId};

use crate::{ErrorCode, Role, Transport, test_support};

struct RecordingWriter(tokio::io::DuplexStream);
impl tokio::io::AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl qrecovery::send::CancelStream for RecordingWriter {
    fn cancel(&mut self, _: u64) {}
}
struct RecordingTransport {
    base: test_support::TestTransport,
    send: std::sync::Mutex<Option<tokio::io::DuplexStream>>,
}
impl Transport for RecordingTransport {
    type StreamReader = test_support::Reader;
    type StreamWriter = RecordingWriter;
    fn role(&self) -> Role {
        Role::Client
    }
    async fn open_bi(
        &self,
    ) -> crate::Result<Option<(u64, (Self::StreamReader, Self::StreamWriter))>> {
        Err(self.terminated().await)
    }
    async fn accept_bi(&self) -> crate::Result<(u64, (Self::StreamReader, Self::StreamWriter))> {
        Err(self.terminated().await)
    }
    async fn open_uni(&self) -> crate::Result<Option<(u64, Self::StreamWriter)>> {
        let send = self.send.lock().unwrap().take();
        if let Some(send) = send {
            return Ok(Some((2, RecordingWriter(send))));
        }
        Err(self.terminated().await)
    }
    async fn accept_uni(&self) -> crate::Result<(u64, Self::StreamReader)> {
        self.base.accept_uni().await
    }
    fn close(&self, reason: String, code: u64) -> crate::Result<()> {
        self.base.close(reason, code)
    }
    async fn terminated(&self) -> crate::Error {
        self.base.terminated().await
    }
}

#[tokio::test]
async fn background_settings_precedes_immediate_goaway() {
    use crate::protocol::frame::{self, Control, StreamType};
    let (send, mut recv) = tokio::io::duplex(1024);
    let connection = crate::H3Connection::new(
        RecordingTransport {
            base: Default::default(),
            send: std::sync::Mutex::new(Some(send)),
        },
        Default::default(),
    )
    .await
    .unwrap();
    let mut goaway = Box::pin(connection.send_goaway());
    assert!(
        goaway
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    tokio::time::timeout(Duration::from_secs(1), goaway)
        .await
        .unwrap()
        .unwrap();
    use tokio::io::AsyncReadExt;
    assert_eq!(recv.read_u8().await.unwrap(), StreamType::Control as u8);
    assert!(matches!(
        frame::be_control(&mut recv).await.unwrap(),
        Control::Settings(_)
    ));
    let Control::Goaway(frame) = frame::be_control(&mut recv).await.unwrap() else {
        panic!("expected GOAWAY after SETTINGS");
    };
    assert_eq!(
        StreamId::from(frame.payload.id),
        StreamId::new(Role::Server, Dir::Bi, 0)
    );
}

#[tokio::test]
async fn transport_close_releases_qpack_writers_waiting_for_instructions() {
    let connection = test_support::connection().await;
    tokio::task::yield_now().await;
    connection
        .transport
        .close(String::new(), ErrorCode::H3_NO_ERROR.as_u64())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while std::sync::Arc::strong_count(&connection.transport) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        (connection.qpack.error()).map(ErrorCode::from),
        Some(ErrorCode::H3_NO_ERROR)
    );
}

#[tokio::test]
async fn local_field_limit_does_not_close_connection_but_receive_failure_does() {
    use crate::{
        client,
        protocol::{
            qpack,
            stream::{H3ReadStream, H3WriteStream},
        },
    };
    let connection = test_support::connection().await;
    connection
        .qpack
        .configure(qpack::Settings::default(), 256)
        .unwrap();
    use crate::WriteRequest;
    let request = client::Request::get("https://example.com/").unwrap();
    let oversized = client::Request::get("https://example.com/")
        .unwrap()
        .header(
            http::HeaderName::from_static("x-large"),
            http::HeaderValue::from_str(&"x".repeat(1024)).unwrap(),
        );
    assert!(matches!(
        client::write_bytes_request(
            oversized,
            H3WriteStream::new(0, test_support::Writer),
            H3ReadStream::new(0, test_support::Reader),
            connection.qpack().clone()
        ),
        Err(h3x::Error {
            code: ErrorCode::H3_EXCESSIVE_LOAD,
            ..
        })
    ));
    tokio::task::yield_now().await;
    let mut ended = Box::pin(connection.transport.terminated());
    assert!(
        ended
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(
        client::write_bytes_request(
            request,
            H3WriteStream::new(4, test_support::Writer),
            H3ReadStream::new(4, test_support::Reader),
            connection.qpack().clone()
        )
        .is_ok()
    );
    let _ = connection.transport.close(
        "test closes the connection during stream processing".into(),
        ErrorCode::H3_EXCESSIVE_LOAD.as_u64(),
    );
    tokio::task::yield_now().await;
    assert_eq!(ErrorCode::from(ended.await), ErrorCode::H3_EXCESSIVE_LOAD);
    assert_eq!(
        (connection.qpack.error()).map(ErrorCode::from),
        Some(ErrorCode::H3_EXCESSIVE_LOAD)
    );
}

#[tokio::test]
async fn protocol_failure_preserves_observed_transport_reason_and_closes_streams() {
    let connection = test_support::connection().await;
    let (mut send, _recv) = connection
        .bi_streams
        .insert(0, test_support::Reader, test_support::Writer)
        .unwrap();
    connection
        .transport
        .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
        .unwrap();
    // Let the connection observe transport termination before a later protocol failure.
    tokio::time::timeout(Duration::from_secs(1), async {
        while connection.qpack.error().is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let _ = connection.transport.close(
        "test closes the connection during stream processing".into(),
        ErrorCode::QPACK_DECOMPRESSION_FAILED.as_u64(),
    );
    tokio::task::yield_now().await;
    assert_eq!(
        (connection.qpack.error()).map(ErrorCode::from),
        Some(ErrorCode::H3_INTERNAL_ERROR)
    );
    assert_eq!(
        (connection.open_bi().await.err()).map(ErrorCode::from),
        Some(ErrorCode::H3_INTERNAL_ERROR)
    );
    use tokio::io::AsyncWriteExt;
    let error = send.write_all(b"x").await.unwrap_err();
    assert_eq!(ErrorCode::from(error), ErrorCode::H3_INTERNAL_ERROR);
}

#[tokio::test]
async fn goaway_waits_for_peer_before_closing() {
    let connection = test_support::connection().await;
    let mut closing = Box::pin(connection.clone().goaway());
    assert!(
        closing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    tokio::task::yield_now().await;
    let mut ended = Box::pin(connection.transport.terminated());
    assert!(
        ended
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    connection
        .cursor
        .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 0));
    tokio::task::yield_now().await;
    assert!(
        ended
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    tokio::time::timeout(Duration::from_secs(1), closing)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ErrorCode::from(
            tokio::time::timeout(Duration::from_secs(1), ended)
                .await
                .unwrap()
        ),
        ErrorCode::H3_NO_ERROR
    );
}

#[tokio::test]
async fn goaway_waits_for_admitted_streams_after_peer_goaway() {
    let connection = test_support::connection().await;
    let (send, recv) = connection
        .bi_streams
        .insert(0, test_support::Reader, test_support::Writer)
        .unwrap();
    connection
        .cursor
        .receive_goaway(StreamId::new(Role::Client, Dir::Bi, 1));
    connection.cursor.local_goaway().unwrap();
    tokio::task::yield_now().await;
    let mut closing = Box::pin(connection.clone().goaway());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    drop(send);
    assert!(closing.as_mut().poll(&mut cx).is_pending());
    drop(recv);
    tokio::time::timeout(Duration::from_secs(1), closing)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn transport_termination_wakes_goaway_waiting_for_peer() {
    let connection = test_support::connection().await;
    connection.send_goaway().await.unwrap();
    let mut closing = Box::pin(connection.clone().goaway());
    assert!(
        closing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let error =
        ErrorCode::H3_INTERNAL_ERROR.with_reason("transport terminated while awaiting peer");
    connection
        .transport
        .close(error.reason.clone(), error.code.as_u64())
        .unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .unwrap(),
        Err(error)
    );
}

#[tokio::test]
async fn goaway_reports_transport_failure() {
    let connection = test_support::connection().await;
    connection
        .transport
        .close(String::new(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
        .unwrap();
    assert_eq!(
        (connection.goaway().await).map_err(ErrorCode::from),
        Err(ErrorCode::H3_INTERNAL_ERROR)
    );
}
