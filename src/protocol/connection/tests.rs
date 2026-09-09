//! Connection lifecycle checks using native dquic streams.

use std::sync::atomic::{AtomicUsize, Ordering};

use dquic::prelude::{StreamReader, StreamWriter};
use http::Method;
use http_body_util::BodyExt;

use super::*;
use crate::test_streams::Streams;

struct EarlyResponseTransport {
    opening: u8,
    role_queries: Arc<AtomicUsize>,
    streams: Arc<Streams>,
    closed: watch::Sender<Option<crate::transport::ConnectionError>>,
}
impl crate::transport::Connection for EarlyResponseTransport {
    fn role(&self) -> Result<crate::transport::Role, crate::transport::ConnectionError> {
        self.role_queries.fetch_add(1, Ordering::Relaxed);
        if let Some(error) = self.closed.borrow().clone() {
            return Err(error);
        }
        Ok(crate::transport::Role::Client)
    }
    async fn open_bi(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), crate::transport::ConnectionError> {
        if self.opening == 3 {
            return std::future::pending().await;
        }
        let stream = self.streams.open_bi();
        if self.opening != 5 {
            self.streams.feed(
                stream.0,
                0,
                Bytes::from_static(&[1, 3, 0, 0, 0xd9]),
                self.opening != 6,
            );
        }
        Ok(stream)
    }
    async fn open_uni(
        &self,
    ) -> Result<(StreamId, StreamWriter), crate::transport::ConnectionError> {
        match self.opening {
            1 => std::future::pending().await,
            2 => Err(crate::transport::ConnectionError::application(
                Code::H3_INTERNAL_ERROR,
                Bytes::new(),
            )),
            _ => Ok(self.streams.writer()),
        }
    }
    async fn accept_bi(
        &self,
    ) -> Result<(StreamId, (StreamReader, StreamWriter)), crate::transport::ConnectionError> {
        std::future::pending().await
    }
    async fn accept_uni(
        &self,
    ) -> Result<(StreamId, StreamReader), crate::transport::ConnectionError> {
        std::future::pending().await
    }
    fn close(&self, code: Code, reason: &[u8]) {
        self.closed.send_if_modified(|closed| {
            if closed.is_some() {
                return false;
            }
            *closed = Some(crate::transport::ConnectionError::application(
                code,
                Bytes::copy_from_slice(reason),
            ));
            true
        });
        self.streams.data.on_conn_error(
            &qbase::error::AppError::new(
                qbase::varint::VarInt::try_from(code.as_u64()).unwrap(),
                "test connection closed",
            )
            .into(),
        );
    }
    async fn closed(&self) -> crate::transport::ConnectionError {
        self.closed
            .subscribe()
            .wait_for(Option::is_some)
            .await
            .unwrap()
            .clone()
            .unwrap()
    }
}

#[tokio::test]
async fn initialization_closes_transport_on_unpolled_drop_cancel_and_failure() {
    for opening in [0, 1, 2] {
        let (closed, mut observed) = watch::channel(None);
        let transport = EarlyResponseTransport {
            opening,
            streams: Arc::new(Streams::new()),
            role_queries: Arc::new(AtomicUsize::new(0)),
            closed,
        };
        let mut initialization =
            Box::pin(crate::protocol::new(transport, crate::Settings::default()));
        match opening {
            1 => assert!(futures::poll!(initialization.as_mut()).is_pending()),
            2 => assert!(initialization.as_mut().await.is_err()),
            _ => {}
        }
        drop(initialization);
        let closed = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            observed.wait_for(Option::is_some),
        )
        .await
        .expect("transport leaked")
        .unwrap();
        assert_eq!(
            closed.as_ref().unwrap().code(),
            Some(Code::H3_INTERNAL_ERROR)
        );
    }
}

#[tokio::test]
async fn early_response_keeps_upload_active_until_finished() {
    use tokio::io::AsyncWriteExt;
    let streams = Arc::new(Streams::new());
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        streams.drive(async {
            let role_queries = Arc::new(AtomicUsize::new(0));
            let transport = EarlyResponseTransport {
                opening: 0,
                role_queries: role_queries.clone(),
                streams: streams.clone(),
                closed: watch::channel(None).0,
            };
            let shared = Arc::new(
                crate::protocol::new(transport, crate::Settings::default())
                    .await
                    .unwrap(),
            );
            let connection = shared.clone();
            drop(shared);
            let accepting = connection.accept();
            tokio::pin!(accepting);
            assert!(futures::poll!(accepting.as_mut()).is_pending());
            let (parts, _) = http::Request::builder()
                .method("POST")
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts();
            let (mut writer, response) = connection.request_streaming(parts).await.unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status(), 200);
            response.into_body().collect().await.unwrap();
            assert_request_state(&connection, false, true);
            writer.write_all(&vec![b'x'; 128 * 1024]).await.unwrap();
            writer.flush().await.unwrap();
            let mut trailers = http::HeaderMap::new();
            trailers.insert("x-finished", "yes".parse().unwrap());
            writer.trailers(trailers).await.unwrap();
            let before = role_queries.load(Ordering::Relaxed);
            connection.inner.on_peer_goaway(4).unwrap();
            assert!(role_queries.load(Ordering::Relaxed) > before);
            connection.shutdown().await.unwrap();
            assert!(connection.inner.on_peer_goaway(4).is_err());
            assert!(accepting.await.unwrap().is_none());
        }),
    )
    .await
    .expect("request or drain stalled");
    assert!(
        streams
            .sent
            .lock()
            .unwrap()
            .iter()
            .any(|(frame, _)| u64::from(frame.stream_id()) == 0 && frame.is_fin())
    );
}

#[tokio::test]
async fn response_owns_send_direction_until_completion_or_drop() {
    for cancelled in [false, true] {
        let streams = Arc::new(Streams::new());
        let connection = test_connection(&streams, 0).await;
        let (id, (read_stream, write_stream)) = streams.open_bi();
        let mut reader = MessageReader::new(
            ChunkReader::new(id, read_stream),
            connection.inner.qpack.clone(),
            id,
        );
        let mut writer = ResetOnDrop::new(write_stream);
        connection.inner.track_request(&mut reader, &mut writer);
        let sender = ResponseSender {
            stream_id: id,
            method: Method::GET,
            writer,
            qpack: connection.inner.qpack.clone(),
            terminal: connection.inner.terminal.clone(),
        };
        if cancelled {
            drop(sender);
            streams.drain();
        } else {
            streams
                .drive(sender.send(http::Response::new(http_body_util::Full::new(
                    Bytes::from_static(b"pong"),
                ))))
                .await
                .unwrap();
        }
        let recorded = streams.sent.lock().unwrap();
        assert_eq!(recorded.iter().any(|(frame, _)| frame.is_fin()), !cancelled);
        assert_eq!(streams.reset.load(Ordering::Relaxed), cancelled);
        if !cancelled {
            assert!(
                recorded
                    .iter()
                    .any(|(_, bytes)| bytes.windows(4).any(|data| data == b"pong"))
            );
        }
        assert_request_state(&connection, true, false);
        drop(reader);
        assert!(connection.inner.state.lock().unwrap().is_drained());
    }
}

async fn test_connection(
    streams: &Arc<Streams>,
    opening: u8,
) -> Connection<EarlyResponseTransport> {
    new(
        EarlyResponseTransport {
            opening,
            streams: streams.clone(),
            role_queries: Arc::new(AtomicUsize::new(0)),
            closed: watch::channel(None).0,
        },
        Settings::default(),
    )
    .await
    .unwrap()
}

fn assert_request_state(
    connection: &Connection<EarlyResponseTransport>,
    reading: bool,
    writing: bool,
) {
    let state = connection.inner.state.lock().unwrap();
    assert_eq!(
        state.directions,
        usize::from(reading) + usize::from(writing)
    );
}

#[tokio::test]
async fn shutdown_cancels_preparation_and_waits_for_its_cleanup() {
    let streams = Arc::new(Streams::new());
    streams
        .drive(async {
            let connection = test_connection(&streams, 3).await;
            let request = http::Request::builder()
                .uri("https://example.test/")
                .body(http_body_util::Empty::<Bytes>::new())
                .unwrap();
            let mut pending = Box::pin(connection.request(request));
            assert!(futures::poll!(pending.as_mut()).is_pending());
            assert_eq!(connection.inner.state.lock().unwrap().preparations.len(), 1);
            let mut shutdown = Box::pin(connection.shutdown());
            assert!(futures::poll!(shutdown.as_mut()).is_pending());
            // Cancellation signals do not themselves unregister preparation.
            assert_eq!(connection.inner.state.lock().unwrap().preparations.len(), 1);
            assert!(matches!(pending.await, Err(Error::Cancelled)));
            assert!(connection.inner.state.lock().unwrap().is_drained());
            tokio::time::timeout(std::time::Duration::from_secs(1), shutdown)
                .await
                .unwrap()
                .unwrap();
        })
        .await;
}

#[tokio::test]
async fn response_eof_finishes_reading_while_body_is_retained() {
    let streams = Arc::new(Streams::new());
    streams
        .drive(async {
            let connection = test_connection(&streams, 0).await;
            let head = http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let (writer, response) = connection.request_streaming(head).await.unwrap();
            let mut body = response.await.unwrap().into_body();
            assert!(body.frame().await.is_none());
            assert_request_state(&connection, false, true);
            drop(writer);
            connection.shutdown().await.unwrap();
            assert!(connection.inner.state.lock().unwrap().is_drained());
            drop(body);
            assert!(connection.inner.state.lock().unwrap().is_drained());
        })
        .await;
}

#[tokio::test]
async fn cancellation_stops_both_normal_directions_but_streaming_can_cancel_upload() {
    let streams = Arc::new(Streams::new());
    streams
        .drive(async {
            let connection = test_connection(&streams, 5).await;
            let body = http_body_util::StreamBody::new(futures::stream::pending::<
                Result<http_body::Frame<Bytes>, Error>,
            >());
            let request = http::Request::builder()
                .uri("https://example.test/")
                .body(body)
                .unwrap();
            let mut pending = Box::pin(connection.request(request));
            assert!(futures::poll!(pending.as_mut()).is_pending());
            drop(pending);
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                connection.inner.drained(),
            )
            .await
            .unwrap();
            let head = http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let (writer, response) = connection.request_streaming(head).await.unwrap();
            drop(writer);
            assert!(matches!(response.await, Err(Error::Cancelled)));
            connection.shutdown().await.unwrap();
        })
        .await;
}

#[tokio::test]
async fn preparation_tracking_has_no_fixed_request_limit() {
    let streams = Arc::new(Streams::new());
    let connection = test_connection(&streams, 0).await;
    let preparations: Vec<_> = (0..300)
        .map(|_| connection.inner.prepare_request().unwrap())
        .collect();
    assert_eq!(
        connection.inner.state.lock().unwrap().preparations.len(),
        300
    );
    drop(preparations);
    assert!(connection.inner.state.lock().unwrap().is_drained());
}

#[tokio::test]
async fn queued_requests_are_revoked_on_shutdown_without_a_waiting_producer() {
    for accept_first in [false, true] {
        let streams = Arc::new(Streams::new());
        streams
            .drive(async {
                let connection = test_connection(&streams, 0).await;
                let mut accepting = Box::pin(connection.accept());
                assert!(futures::poll!(accepting.as_mut()).is_pending());
                let classifying = Arc::new(Semaphore::new(2));
                let mut pending = Vec::new();
                for _ in 0..1 {
                    let (id, (read_stream, write_stream)) = streams.open_bi();
                    let head = http::Request::builder()
                        .uri("https://example.test/")
                        .body(())
                        .unwrap()
                        .into_parts()
                        .0;
                    let encoded = connection
                        .inner
                        .qpack
                        .encode_fields(id, headers::request_fields(head).unwrap())
                        .await
                        .unwrap();
                    let mut frame = vec![1];
                    frame.put_varint(&VarInt::try_from(encoded.len()).unwrap());
                    frame.extend_from_slice(&encoded);
                    streams.feed(id, 0, Bytes::from(frame), true);
                    let permit = classifying.clone().try_acquire_owned().unwrap();
                    pending.push(Box::pin(connection.inner.clone().read_request(
                        id,
                        read_stream,
                        write_stream,
                        permit,
                    )));
                }
                pending.pop().unwrap().await.unwrap();
                assert_request_state(&connection, true, true);
                assert!(
                    connection
                        .inner
                        .state
                        .lock()
                        .unwrap()
                        .pending_accepts
                        .is_empty()
                );
                if accept_first {
                    let (mut request, sender) = accepting.await.unwrap().unwrap();
                    assert_request_state(&connection, true, true);
                    assert!(request.body_mut().frame().await.is_none());
                    assert_request_state(&connection, false, true);
                    drop(sender);
                } else {
                    connection.inner.begin_shutdown().unwrap();
                    // No accept or producer task poll is needed to release queued streams.
                    assert!(connection.inner.state.lock().unwrap().queued.is_empty());
                }
                assert!(connection.inner.state.lock().unwrap().is_drained());
            })
            .await;
    }
}

#[tokio::test]
async fn force_close_finishes_with_an_unread_body_still_owned_by_application() {
    let streams = Arc::new(Streams::new());
    streams
        .drive(async {
            let connection = test_connection(&streams, 6).await;
            let head = http::Request::builder()
                .uri("https://example.test/")
                .body(())
                .unwrap()
                .into_parts()
                .0;
            let (writer, response) = connection.request_streaming(head).await.unwrap();
            let mut body = response.await.unwrap().into_body();
            assert!(futures::poll!(body.frame()).is_pending());
            drop(writer);
            let mut shutdown = Box::pin(connection.shutdown());
            assert!(futures::poll!(shutdown.as_mut()).is_pending());
            connection.close(Code::H3_NO_ERROR, b"force close");
            tokio::time::timeout(std::time::Duration::from_secs(1), shutdown)
                .await
                .unwrap()
                .unwrap();
            assert_request_state(&connection, true, false);
            assert!(body.frame().await.unwrap().is_err());
            assert!(connection.inner.state.lock().unwrap().is_drained());
        })
        .await;
}

#[tokio::test]
async fn stream_cleanup_counts_each_direction_once() {
    let streams = Arc::new(Streams::new());
    let connection = test_connection(&streams, 0).await;
    let mut requests = Vec::new();
    for _ in 0..2 {
        let (id, (read_stream, write_stream)) = streams.open_bi();
        let mut reader = MessageReader::new(
            ChunkReader::new(id, read_stream),
            connection.inner.qpack.clone(),
            id,
        );
        let mut writer = ResetOnDrop::new(write_stream);
        connection.inner.track_request(&mut reader, &mut writer);
        requests.push((id, reader, writer));
    }
    let (_, reader, mut writer) = requests.pop().unwrap();
    drop(reader);
    assert_eq!(connection.inner.state.lock().unwrap().directions, 3);
    writer.reset(Code::H3_REQUEST_CANCELLED);
    writer.reset(Code::H3_REQUEST_CANCELLED);
    drop(writer);
    assert_request_state(&connection, true, true);
    drop(requests);
    assert!(connection.inner.state.lock().unwrap().is_drained());
}

#[tokio::test]
async fn full_request_queue_rejects_without_waiting() {
    let streams = Arc::new(Streams::new());
    let connection = test_connection(&streams, 0).await;
    for index in 0..=REQUEST_QUEUE_SIZE {
        // Separate native stream fixtures avoid depending on QUIC stream credit.
        let stream = Streams::new();
        let (id, (recv, send)) = stream.open_bi();
        let mut reader = MessageReader::new(
            ChunkReader::new(id, recv),
            connection.inner.qpack.clone(),
            id,
        );
        let mut writer = ResetOnDrop::new(send);
        connection.inner.track_request(&mut reader, &mut writer);
        let result = connection.inner.deliver_request(QueuedRequest {
            stream_id: id,
            request_head: http::Request::new(()).into_parts().0,
            reader,
            message_body: MessageBody::Unknown,
            writer,
        });
        if index == REQUEST_QUEUE_SIZE {
            assert_eq!(result.unwrap_err().code(), Some(Code::H3_REQUEST_REJECTED));
        } else {
            result.unwrap();
        }
    }
    assert_eq!(
        connection.inner.state.lock().unwrap().directions,
        2 * REQUEST_QUEUE_SIZE
    );
    connection.close(Code::H3_NO_ERROR, b"test complete");
    assert!(connection.inner.state.lock().unwrap().is_drained());
}

#[tokio::test]
async fn dropping_unpolled_upload_wakes_writer_with_owner_stopped() {
    use tokio::io::AsyncWriteExt;
    let (mut writer, upload) = BodyWriter::channel();
    let mut flush = Box::pin(writer.flush());
    assert!(futures::poll!(flush.as_mut()).is_pending());
    drop(upload);
    let error = tokio::time::timeout(std::time::Duration::from_secs(1), flush)
        .await
        .unwrap()
        .unwrap_err();
    assert!(matches!(
        error.get_ref().unwrap().downcast_ref::<Error>(),
        Some(Error::OwnerStopped)
    ));
    assert!(matches!(writer.finish().await, Err(Error::OwnerStopped)));
}
