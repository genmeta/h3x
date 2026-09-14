use super::*;

#[tokio::test]
async fn raw_connections_support_explicit_message_io() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let requests = async {
        for _ in 0..2 {
            let request = client::Request::post("https://example.com/echo")
                .unwrap()
                .body(Bytes::from_static(b"hello"));
            let (received, served) = tokio::join!(
                request_on(&client, request, |response| async {
                    assert_eq!(response.status(), http::StatusCode::OK);
                    let client::Response::Streaming(mut response) = response else {
                        panic!()
                    };
                    let mut bytes = [0; 5];
                    response.read_all(&mut bytes).await?;
                    assert_eq!(&bytes, b"hello");
                    Ok(())
                }),
                accept_on(&server, |request| async {
                    assert_eq!(request.method(), http::Method::POST);
                    let server::Request::Streaming(mut request) = request else {
                        panic!()
                    };
                    let mut bytes = [0; 5];
                    request.read_all(&mut bytes).await?;
                    let mut response = server::Response::<Bytes>::default();
                    response
                        .set_status(http::StatusCode::OK)
                        .set_body(Bytes::copy_from_slice(&bytes));
                    Ok(response)
                })
            );
            received.unwrap();
            served.unwrap();
        }
        server.goaway().await.unwrap();
        while client.received_goaway().is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.received_goaway(), Some(8));
        assert_eq!(
            client.open_bi().await.err(),
            Some(Error::H3_REQUEST_REJECTED)
        );
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), requests);
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn streaming_request_remains_writable_and_goaway_preserves_admitted_post() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let response_sent = Notify::new();
    let work = async {
        let mut request = client::Request::streaming_post("https://example.com/upload").unwrap();
        let (send, recv) = client.open_bi().await.unwrap();
        assert_eq!(recv.stream_id(), 0);
        assert_eq!(send.stream_id(), 0);
        let response = client::request(request.clone(), recv, send, client.qpack().clone());
        assert_eq!(client.transport.next_bi.get(), 4);
        let (response, produced, served) = tokio::join!(
            response,
            async {
                response_sent.notified().await;
                assert_eq!(request.write(b"hello").await?, 5);
                request.finish().await
            },
            async {
                let (send, recv) = server.accept_bi().await?;
                let incoming = server::accept(recv, server.qpack().clone()).await?;
                let method = incoming.method();
                let mut response = server::Response::<Bytes>::default();
                let server::Request::Streaming(mut incoming) = incoming else {
                    panic!()
                };
                response.set_status(http::StatusCode::OK);
                server.goaway().await?;
                assert_eq!(server.uni.goaway.state.lock().unwrap().accepted_boundary, 4);
                server::respond(response, send, server.qpack().clone(), &method).await?;
                response_sent.notify_one();
                let mut bytes = [0; 5];
                incoming.read_all(&mut bytes).await?;
                assert_eq!(&bytes, b"hello");
                Ok::<_, Error>(())
            }
        );
        assert_eq!(response.unwrap().status(), http::StatusCode::OK);
        produced.unwrap();
        served.unwrap();
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn head_response_with_representation_content_length_roundtrips() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        let (received, served) = tokio::join!(
            request_on(
                &client,
                client::Request::<Bytes>::head("https://example.com/").unwrap(),
                |response| async {
                    let client::Response::Bytes(response) = response else {
                        panic!()
                    };
                    assert!(crate::ReadBody::body(&response).is_empty());
                    Ok(())
                }
            ),
            async {
                let (send, recv) = server.accept_bi().await?;
                let request = server::accept(recv, server.qpack().clone()).await?;
                let method = request.method();
                assert_eq!(method, http::Method::HEAD);
                let mut response = server::Response::<Bytes>::default();
                response.set_status(http::StatusCode::OK);
                response
                    .message
                    .0
                    .lock()
                    .unwrap()
                    .set_header(http::header::CONTENT_LENGTH, "5".parse().unwrap());
                server::respond(response, send, server.qpack().clone(), &method).await
            }
        );
        received.unwrap();
        served.unwrap();
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn dropping_request_releases_transport_halves_and_upload() {
    use tokio::io::AsyncReadExt;
    let (transport, peer) = pair();
    let connection = H3Connection::new(transport);
    let request = client::Request::streaming_post("https://example.com/upload").unwrap();
    let mut upload = request.clone();
    {
        let request = request_on(&connection, request, |_| async { Ok(()) });
        tokio::pin!(request);
        poll_fn(|cx| {
            assert!(request.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    let (_, (mut recv, mut send)) = peer.accept_bi_stream().await.unwrap();
    let mut partial = Vec::new();
    recv.read_to_end(&mut partial).await.unwrap(); // Drop closed the unfinished sending half.
    // Cancellation can precede the upload task's first poll and send no bytes.
    assert!(send.write_all(b"response").await.is_err());
    assert_eq!(
        upload.write(b"body").await,
        Err(Error::H3_REQUEST_CANCELLED)
    );
    assert_eq!(connection.error(), None);
}

#[tokio::test]
async fn messages_use_explicit_qpack_and_stream_owned_ids() {
    let (a, b) = pair();
    let client = H3Connection::new(a);
    let server = H3Connection::new(b);
    let work = async {
        let request = client::Request::post("https://example.com/")
            .unwrap()
            .header(http::header::CONTENT_LENGTH, "3".parse().unwrap())
            .body(Bytes::from_static(b"abc"));
        let (send, recv) = client.open_bi().await.unwrap();
        assert_eq!(recv.stream_id(), send.stream_id());
        let (response, served) = tokio::join!(
            client::request(request, recv, send, client.qpack().clone()),
            async {
                let (send, recv) = server.accept_bi().await?;
                assert_eq!(recv.stream_id(), send.stream_id());
                let request = server::accept(recv, server.qpack().clone()).await?;
                let method = request.method();
                assert!(matches!(&request, server::Request::Bytes(_)));
                let mut response = server::Response::<Bytes>::default();
                response.set_status(http::StatusCode::OK);
                let response = response.streaming(2);
                let mut producer = response.clone();
                let ((), ()) = tokio::try_join!(
                    server::respond(response, send, server.qpack().clone(), &method),
                    async {
                        assert_eq!(producer.write(b"ok").await?, 2);
                        producer.finish().await
                    }
                )?;
                Ok::<_, Error>(())
            }
        );
        served.unwrap();
        let response = response.unwrap();
        let client::Response::Streaming(mut response) = response else {
            panic!()
        };
        let mut body = [0; 2];
        response.read_all(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");
        assert_eq!(response.read(&mut [0; 1]).await.unwrap(), 0);
        client.close(Error::H3_NO_ERROR);
    };
    let (a, b, ()) = tokio::join!(client.closed(), server.closed(), work);
    a.unwrap();
    b.unwrap();
}
