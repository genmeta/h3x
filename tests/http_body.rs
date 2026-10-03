//! Public message API: callers use standard HTTP bodies without window adapters.
mod support;

use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use h3x::{Body, BoxError, ErrorCode, ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use tower::ServiceExt;

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("exchange stalled")
}

fn payload() -> impl http_body::Body<Data = Bytes, Error = BoxError> + Send {
    let mut trailers = http::HeaderMap::new();
    trailers.append("x-tag", http::HeaderValue::from_static("one"));
    trailers.append("x-tag", http::HeaderValue::from_static("two"));
    let mut secret = http::HeaderValue::from_static("secret");
    secret.set_sensitive(true);
    trailers.insert("x-secret", secret);
    StreamBody::new(futures::stream::iter([
        Ok::<_, BoxError>(Frame::data(Bytes::from(vec![42; 1024 * 1024]))),
        Ok(Frame::trailers(trailers)),
    ]))
}

#[tokio::test]
async fn empty_requests_preserve_headers_and_finish_before_the_response() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let serving = tokio::spawn(async move {
            let (writer, reader) = server.accept_bi().await.unwrap();
            let request = reader.read_request(server.qpack().clone()).await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            assert_eq!(request.uri(), "https://example.com/empty");
            assert_eq!(request.headers().get_all("x-tag").iter().count(), 2);
            assert!(
                request
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
            writer
                .write_response(
                    http::Response::builder()
                        .status(204)
                        .body(Body::default())
                        .unwrap(),
                    http::Method::POST,
                    server.qpack().clone(),
                )
                .await
                .unwrap();
        });
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/empty")
            .header("x-tag", "one")
            .header("x-tag", "two")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let ((), response) = tokio::try_join!(
            writer.write_request(request, client.qpack().clone()),
            reader.read_response(http::Method::POST, client.qpack().clone()),
        )
        .unwrap();
        assert_eq!(response.status(), 204);
        serving.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn axum_echo_streams_both_directions_with_trailers() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let serving = tokio::spawn(async move {
            let router = axum::Router::new().route(
                "/",
                axum::routing::post(|request: axum::extract::Request| async move {
                    http::Response::new(request.into_body())
                }),
            );
            let (writer, reader) = server.accept_bi().await.unwrap();
            let request = reader.read_request(server.qpack().clone()).await.unwrap();
            assert!(request.extensions().get::<Arc<str>>().is_none());
            let method = request.method().clone();
            let response = router
                .oneshot(request.map(axum::body::Body::new))
                .await
                .unwrap();
            writer
                .write_response(
                    response.map(|body| body.map_err(Into::into).boxed_unsync()),
                    method,
                    server.qpack().clone(),
                )
                .await
                .unwrap();
        });
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/")
            .body(payload())
            .unwrap();
        let uploading = writer.write_request(request, client.qpack().clone());
        let receiving = async {
            let response = reader
                .read_response(http::Method::POST, client.qpack().clone())
                .await
                .unwrap();
            assert_eq!(response.version(), http::Version::HTTP_3);
            let received = response.into_body().collect().await.unwrap();
            let trailers = received.trailers().unwrap();
            assert_eq!(trailers.get_all("x-tag").iter().count(), 2);
            assert!(trailers["x-secret"].is_sensitive());
            assert_eq!(received.to_bytes(), vec![42; 1024 * 1024]);
        };
        let (uploaded, ()) = tokio::join!(uploading, receiving);
        uploaded.unwrap();
        serving.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn response_headers_do_not_wait_for_source_eof() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (release, released) = tokio::sync::oneshot::channel();
        let upload = StreamBody::new(async_stream::stream! {
            released.await.unwrap();
            yield Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"late")));
        });
        let serving = tokio::spawn(async move {
            let (writer, reader) = server.accept_bi().await.unwrap();
            let request = reader.read_request(server.qpack().clone()).await.unwrap();
            writer
                .write_response(
                    http::Response::new(
                        Full::new(Bytes::from_static(b"early"))
                            .map_err(Into::into)
                            .boxed_unsync(),
                    ),
                    http::Method::POST,
                    server.qpack().clone(),
                )
                .await
                .unwrap();
            assert_eq!(
                request.into_body().collect().await.unwrap().to_bytes(),
                "late"
            );
        });
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = http::Request::builder()
            .method("POST")
            .uri("https://example.com/")
            .body(upload)
            .unwrap();
        let uploading = tokio::spawn(writer.write_request(request, client.qpack().clone()));
        let response = reader
            .read_response(http::Method::POST, client.qpack().clone())
            .await
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "early"
        );
        uploading.await.unwrap().unwrap();
        serving.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn dropping_unpolled_write_futures_cancels_transport() {
    bounded(async {
        for response in [false, true] {
            let (client, server) = support::connection_pair();
            let (writer, reader) = client.open_bi().await.unwrap();
            let (peer_writer, peer_reader) = server.accept_bi().await.unwrap();
            if response {
                drop(peer_writer.write_response(
                    http::Response::new(Body::default()),
                    http::Method::GET,
                    server.qpack().clone(),
                ));
                let error = reader
                    .read_response(http::Method::GET, client.qpack().clone())
                    .await
                    .unwrap_err();
                assert_eq!(error.code, ErrorCode::RequestCancelled);
            } else {
                drop(
                    writer
                        .write_request(http::Request::new(Body::default()), client.qpack().clone()),
                );
                let error = peer_reader
                    .read_request(server.qpack().clone())
                    .await
                    .unwrap_err();
                assert_eq!(error.code, ErrorCode::RequestCancelled);
            }
        }
    })
    .await;
}

#[tokio::test]
async fn unpolled_incoming_drop_stops_large_upload_and_allows_response() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = http::Request::builder()
            .uri("https://example.com/")
            .body(payload())
            .unwrap();
        let uploading = tokio::spawn(writer.write_request(request, client.qpack().clone()));
        let (writer, request_reader) = server.accept_bi().await.unwrap();
        let request = request_reader
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        drop(request);
        writer
            .write_response(
                http::Response::new(
                    Full::new(Bytes::from_static(b"declined"))
                        .map_err(Into::into)
                        .boxed_unsync(),
                ),
                http::Method::GET,
                server.qpack().clone(),
            )
            .await
            .unwrap();
        let response = reader
            .read_response(http::Method::GET, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "declined"
        );
        let error = uploading.await.unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::NoError);
    })
    .await;
}

#[tokio::test]
async fn producer_error_preserves_source_and_connection_remains_usable() {
    bounded(async {
        let (client, server) = support::connection_pair();
        let (writer, reader) = client.open_bi().await.unwrap();
        let (_peer_writer, peer_reader) = server.accept_bi().await.unwrap();
        let failed = StreamBody::new(futures::stream::iter([Err::<Frame<Bytes>, _>(
            std::io::Error::other("producer failed"),
        )]));
        let error = writer
            .write_request(http::Request::new(failed), client.qpack().clone())
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::RequestCancelled);
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "producer failed"
        );
        assert!(
            peer_reader
                .read_request(server.qpack().clone())
                .await
                .is_err()
        );
        drop(reader);

        let (writer, _unused_direction_1) = client.open_bi().await.unwrap();
        let (_unused_direction_2, reader) = server.accept_bi().await.unwrap();
        let request = http::Request::builder()
            .uri("https://example.com/")
            .body(Full::new(Bytes::from_static(b"healthy")))
            .unwrap();
        writer
            .write_request(request, client.qpack().clone())
            .await
            .unwrap();
        let request = reader.read_request(server.qpack().clone()).await.unwrap();
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            "healthy"
        );
    })
    .await;
}

#[tokio::test]
async fn no_content_responses_never_poll_source() {
    bounded(async {
        for (method, status) in [
            (http::Method::HEAD, http::StatusCode::OK),
            (http::Method::GET, http::StatusCode::NO_CONTENT),
            (http::Method::GET, http::StatusCode::NOT_MODIFIED),
        ] {
            let (client, server) = support::connection_pair();
            let (_writer, reader) = client.open_bi().await.unwrap();
            let (writer, _reader) = server.accept_bi().await.unwrap();
            let (dropped, observed) = tokio::sync::oneshot::channel();
            let guard = scopeguard::guard(dropped, |tx| {
                let _ = tx.send(());
            });
            let source = futures::stream::poll_fn(
                move |_| -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
                    let _ = &guard;
                    panic!("suppressed body was polled");
                },
            );
            let response = http::Response::builder()
                .status(status)
                .header("x-test", "kept")
                .body(StreamBody::new(source).boxed_unsync())
                .unwrap();
            writer
                .write_response(response, method.clone(), server.qpack().clone())
                .await
                .unwrap();
            observed.await.unwrap();
            let response = reader
                .read_response(method, client.qpack().clone())
                .await
                .unwrap();
            assert_eq!(response.headers()["x-test"], "kept");
            assert!(
                response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes()
                    .is_empty()
            );
        }
    })
    .await;
}

#[tokio::test]
async fn data_after_trailers_fails_locally() {
    bounded(async {
        let (client, _server) = support::connection_pair();
        let (writer, _reader) = client.open_bi().await.unwrap();
        let frames = futures::stream::iter([
            Ok::<_, BoxError>(Frame::trailers(http::HeaderMap::new())),
            Ok(Frame::data(Bytes::from_static(b"invalid"))),
        ]);
        let error = writer
            .write_request(
                http::Request::new(StreamBody::new(frames)),
                client.qpack().clone(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::MessageError);
    })
    .await;
}
