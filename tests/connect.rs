mod support;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use h3x::{
    ErrorCode, H3Connection, ReadRequest, ReadResponse, ReadStream, Result, Role, Settings,
    Transport, WriteBody, WriteRequest, WriteResponse, client, server,
};
use support::{TestStream, TestTransport};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    sync::{Mutex, mpsc},
};
type R = TestStream<ReadHalf<DuplexStream>>;
type W = TestStream<WriteHalf<DuplexStream>>;
type Bi = (u64, (R, W));
struct MemoryTransport {
    base: Arc<TestTransport>,
    role: Role,
    next: AtomicU64,
    bi_tx: mpsc::UnboundedSender<Bi>,
    bi_rx: Mutex<mpsc::UnboundedReceiver<Bi>>,
    uni_tx: mpsc::UnboundedSender<(u64, R)>,
    uni_rx: Mutex<mpsc::UnboundedReceiver<(u64, R)>>,
    capacity: usize,
    stopped_flush: Option<Arc<support::StoppedFlush>>,
}
impl Transport for MemoryTransport {
    type StreamReader = R;
    type StreamWriter = W;
    fn role(&self) -> Role {
        self.role
    }
    async fn open_bi(&self) -> Result<Option<Bi>> {
        let id = self.next.fetch_add(4, Ordering::SeqCst);
        let (a, b) = io::duplex(self.capacity);
        let (ar, aw) = io::split(a);
        let (br, bw) = io::split(b);
        let mut br = TestStream::new(br);
        let mut aw = TestStream::new(aw);
        br.stopped_flush = self.stopped_flush.clone();
        aw.stopped_flush = self.stopped_flush.clone();
        self.bi_tx.send((id, (br, TestStream::new(bw)))).unwrap();
        Ok(Some((id, (TestStream::new(ar), aw))))
    }
    async fn accept_bi(&self) -> Result<Bi> {
        tokio::select! { value = async { self.bi_rx.lock().await.recv().await } => Ok(value.unwrap()), error = self.terminated() => Err(error) }
    }
    async fn open_uni(&self) -> Result<Option<(u64, W)>> {
        let (a, b) = io::duplex(65536);
        let (_, aw) = io::split(a);
        let (br, _) = io::split(b);
        self.uni_tx.send((2, TestStream::new(br))).unwrap();
        Ok(Some((2, TestStream::new(aw))))
    }
    async fn accept_uni(&self) -> Result<(u64, R)> {
        tokio::select! { value = async { self.uni_rx.lock().await.recv().await } => Ok(value.unwrap()), error = self.terminated() => Err(error) }
    }
    fn close(&self, reason: String, code: u64) -> Result<()> {
        self.base.close(reason, code)
    }
    async fn terminated(&self) -> h3x::Error {
        self.base.terminated().await
    }
}
fn transports(capacity: usize) -> (MemoryTransport, MemoryTransport) {
    let (at, ar) = mpsc::unbounded_channel();
    let (bt, br) = mpsc::unbounded_channel();
    let (au, aur) = mpsc::unbounded_channel();
    let (bu, bur) = mpsc::unbounded_channel();
    (
        MemoryTransport {
            base: Default::default(),
            role: Role::Client,
            next: AtomicU64::new(0),
            bi_tx: bt,
            bi_rx: Mutex::new(ar),
            uni_tx: bu,
            uni_rx: Mutex::new(aur),
            capacity,
            stopped_flush: None,
        },
        MemoryTransport {
            base: Default::default(),
            role: Role::Server,
            next: AtomicU64::new(1),
            bi_tx: at,
            bi_rx: Mutex::new(br),
            uni_tx: au,
            uni_rx: Mutex::new(bur),
            capacity,
            stopped_flush: None,
        },
    )
}
async fn pair(capacity: usize) -> (H3Connection<MemoryTransport>, H3Connection<MemoryTransport>) {
    let (a, b) = transports(capacity);
    (
        H3Connection::new(a, Settings::default()).await.unwrap(),
        H3Connection::new(b, Settings::default()).await.unwrap(),
    )
}
// WebSocket codecs require one duplex value. This application adapter only
// combines directional bodies; HTTP/3 framing stays in the shared body pumps.
struct Bodies {
    recv: h3x::Body<h3x::WndBuf, h3x::R>,
    send: h3x::Body<h3x::WndBuf, h3x::W>,
}
impl Bodies {
    async fn finish(&mut self) -> Result<()> {
        self.send.finish().await
    }
    async fn abort(self) {
        self.send.reset().await.unwrap();
        self.recv.stop().await;
    }
}
impl tokio::io::AsyncRead for Bodies {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Bodies {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().send).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().send).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().send).poll_shutdown(cx)
    }
}

async fn accept_connect(
    response: http::Response<()>,
    ws: h3x::H3WriteStream<W>,
    rs: h3x::H3ReadStream<R>,
    qpack: h3x::ArcQpack,
    head: http::Request<()>,
) -> Result<Bodies> {
    let method = head.method().clone();
    let server::Request::Streaming(request) = server::read_request_body(head, rs, qpack.clone())?
    else {
        unreachable!()
    };
    let mut outgoing = server::Response::default().streaming(16 * 1024);
    outgoing.set_status(response.status());
    for (name, value) in response.headers() {
        outgoing.append_header(name.clone(), value.clone());
    }
    let send = outgoing.body();
    tokio::spawn(server::write_streaming_response(
        outgoing, ws, qpack, &method,
    ));
    Ok(Bodies {
        recv: request.into_body(),
        send,
    })
}

// Stream allocation is separate from the handshake.
async fn connect(
    request: client::Request<h3x::WndBuf>,
    connection: &H3Connection<MemoryTransport>,
) -> std::result::Result<(http::Response<()>, Bodies), client::ConnectError> {
    let (ws, rs) = connection.open_bi().await?;
    let send = request.body();
    let response =
        client::write_streaming_request(request, ws, rs, connection.qpack().clone())?.await?;
    if !response.status().is_success() {
        return Err(client::ConnectError::Rejected(response));
    }
    let mut head = http::Response::new(());
    *head.status_mut() = response.status();
    *head.headers_mut() = response.headers();
    *head.version_mut() = http::Version::HTTP_3;
    let client::Response::Streaming(response) = response else {
        unreachable!()
    };
    Ok((
        head,
        Bodies {
            recv: response.into_body(),
            send,
        },
    ))
}

async fn tunnels(
    a: &H3Connection<MemoryTransport>,
    b: &H3Connection<MemoryTransport>,
) -> (Bodies, Bodies) {
    let (client, server) = tokio::join!(
        connect(
            client::Request::connect("wss://home.example/api/websocket?q=1").unwrap(),
            a
        ),
        async {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let request = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            assert_eq!(
                request
                    .extensions()
                    .get::<h3x::Protocol>()
                    .unwrap()
                    .as_str(),
                "websocket"
            );
            assert_eq!(request.uri().scheme_str().unwrap(), "https");
            assert_eq!(
                request.uri().path_and_query().unwrap().as_str(),
                "/api/websocket?q=1"
            );
            assert_eq!(request.headers()["sec-websocket-version"], "13");
            accept_connect(http::Response::new(()), ws, rs, b.qpack().clone(), request)
                .await
                .unwrap()
        }
    );
    let (response, tunnel) = client.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), http::Version::HTTP_3);
    (tunnel, server)
}
#[tokio::test]
async fn tiny_buffers_duplex_flush_half_close_and_bounded_writes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (a, b) = pair(3).await;
        let (mut client, mut server) = tunnels(&a, &b).await;
        let payload = vec![0xa5; 100_000];
        let ((), ()) = tokio::join!(
            async {
                client.write_all(b"hi").await.unwrap();
                client.flush().await.unwrap();
                let mut reply = [0; 2];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"ok");
                let n = client.write(&payload).await.unwrap();
                assert_eq!(n, 16 * 1024);
                client.write_all(&payload[n..]).await.unwrap();
                client.finish().await.unwrap();
                let mut tail = Vec::new();
                client.read_to_end(&mut tail).await.unwrap();
                assert_eq!(tail, b"tail");
            },
            async {
                let mut hello = [0; 2];
                server.read_exact(&mut hello).await.unwrap();
                assert_eq!(&hello, b"hi");
                server.write_all(b"ok").await.unwrap();
                server.flush().await.unwrap();
                let mut received = Vec::new();
                server.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, payload);
                server.write_all(b"tail").await.unwrap();
                server.finish().await.unwrap();
            }
        );
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn rejection_preserves_status_headers_and_body() {
    rejection(None).await;
}

#[tokio::test]
async fn rejection_survives_stopped_pending_flush() {
    for code in [ErrorCode::H3_NO_ERROR, ErrorCode::H3_REQUEST_CANCELLED] {
        tokio::time::timeout(Duration::from_secs(5), rejection(Some(code)))
            .await
            .unwrap();
    }
}

async fn rejection(stop_code: Option<ErrorCode>) {
    let (mut a, b) = transports(3);
    let flush = stop_code.map(|_| Arc::new(support::StoppedFlush::default()));
    a.stopped_flush = flush.clone();
    let a = H3Connection::new(a, Settings::default()).await.unwrap();
    let b = H3Connection::new(b, Settings::default()).await.unwrap();
    let (result, ()) = tokio::join!(
        async {
            let result = connect(client::Request::connect("ws://home.example/").unwrap(), &a).await;
            let Err(client::ConnectError::Rejected(response)) = result else {
                panic!()
            };
            assert_eq!(response.status(), 403);
            assert_eq!(response.headers()["x-reason"], "denied");
            let client::Response::Streaming(mut response) = response else {
                panic!()
            };
            let mut bytes = [0; 6];
            assert_eq!(response.read_all(&mut bytes).await.unwrap(), 6);
            assert_eq!(&bytes, b"denied");
        },
        async {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            if let Some(flush) = &flush {
                flush.pending.notified().await;
            }
            qrecovery::recv::StopSending::stop(
                &mut rs,
                stop_code.unwrap_or(ErrorCode::H3_NO_ERROR).as_u64(),
            );
            if let Some(flush) = &flush {
                // Do not publish the response until the client observes the send error.
                flush.failed.notified().await;
            }
            drop(rs);
            let mut response = server::Response::default();
            response
                .set_status(http::StatusCode::FORBIDDEN)
                .set_header("x-reason".parse().unwrap(), "denied".parse().unwrap())
                .set_body(Bytes::from_static(b"denied"));
            server::write_bytes_response(response, ws, b.qpack().clone(), &http::Method::CONNECT)
                .await
                .unwrap();
        }
    );
    let () = result;
}
#[tokio::test]
async fn cancelled_tunnel_does_not_disrupt_http_or_other_tunnels() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = pair(1024).await;
        let (cancelled, other) = tunnels(&a, &b).await;
        let (mut live, mut peer) = tunnels(&a, &b).await;
        cancelled.abort().await;
        other.abort().await;
        let ((), ()) = tokio::join!(
            async {
                let (ws, rs) = a.open_bi().await.unwrap();
                let response = client::write_bytes_request(
                    client::Request::get("https://example.com/").unwrap(),
                    ws,
                    rs,
                    a.qpack().clone(),
                )
                .unwrap()
                .await
                .unwrap();
                assert_eq!(response.status(), 200);
                live.write_all(b"live").await.unwrap();
                live.flush().await.unwrap();
            },
            async {
                let (ws, mut rs) = b.accept_bi().await.unwrap();
                let head = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
                let request = server::read_request_body(head, rs, b.qpack().clone()).unwrap();
                assert_eq!(request.method(), http::Method::GET);
                let mut response = server::Response::default();
                response.set_status(http::StatusCode::OK);
                server::write_bytes_response(response, ws, b.qpack().clone(), &http::Method::GET)
                    .await
                    .unwrap();
                let mut bytes = [0; 4];
                peer.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"live");
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn goaway_keeps_established_tunnels_until_both_directions_finish() {
    tokio::time::timeout(Duration::from_secs(3),async {
        let (a,b)=pair(1024).await;
        let (mut client,mut server)=tunnels(&a,&b).await;
        let ac=tokio::spawn(a.clone().goaway()); let bc=tokio::spawn(b.clone().goaway());
        // Drain the queued control work without releasing the application streams.
        for _ in 0..20 { tokio::task::yield_now().await; }
        assert!(!ac.is_finished()); assert!(!bc.is_finished());
        assert!(matches!(connect(client::Request::connect("ws://example.com/").unwrap(),&a).await,Err(client::ConnectError::H3(e)) if e.code==ErrorCode::H3_REQUEST_REJECTED));
        client.write_all(b"last").await.unwrap(); client.finish().await.unwrap();
        let mut bytes=Vec::new(); server.read_to_end(&mut bytes).await.unwrap(); assert_eq!(bytes,b"last");
        assert!(!ac.is_finished());
        server.finish().await.unwrap(); assert_eq!(client.read(&mut [0]).await.unwrap(),0);
        ac.await.unwrap().unwrap(); bc.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn copy_bidirectional_flushes_small_messages_without_eof() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = pair(3).await;
        let (mut client, mut tunnel) = tunnels(&a, &b).await;
        let (mut upstream, mut endpoint) = io::duplex(3);
        let (relay, (), ()) = tokio::join!(
            io::copy_bidirectional(&mut tunnel, &mut upstream),
            async {
                client.write_all(b"hi").await.unwrap();
                client.flush().await.unwrap();
                let mut response = [0; 2];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"ok");
                client.finish().await.unwrap();
                assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
            },
            async {
                let mut request = [0; 2];
                endpoint.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"hi");
                endpoint.write_all(b"ok").await.unwrap();
                assert_eq!(endpoint.read(&mut [0]).await.unwrap(), 0);
                endpoint.shutdown().await.unwrap();
            }
        );
        assert_eq!(relay.unwrap(), (2, 2));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_handshake_releases_both_directions() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let (a, b) = pair(1024).await;
    let mut handshake = Box::pin(connect(
        client::Request::connect("example.com:443").unwrap(),
        &a,
    ));
    assert!(
        handshake
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let (ws, mut rs) = b.accept_bi().await.unwrap();
    let incoming = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
    drop(handshake);
    // Our in-memory transport models cancellation by dropping owned halves.
    let mut response = server::Response::default().streaming(16 * 1024);
    response.set_status(http::StatusCode::OK);
    response.body().finish().await.unwrap();
    assert!(
        server::write_streaming_response(response, ws, b.qpack().clone(), incoming.method())
            .await
            .is_err()
    );
    drop(rs);
    let (_ws, _rs) = a.open_bi().await.unwrap();
    let (_ws, _rs) = b.accept_bi().await.unwrap();
}

#[tokio::test]
async fn extended_connect_opens_streams_before_peer_settings() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = transports(1024);
        let a = H3Connection::new(a, Settings::default()).await.unwrap();
        let mut clients = Vec::new();
        for _ in 0..8 {
            let a = a.clone();
            clients.push(tokio::spawn(async move {
                connect(client::Request::connect("ws://example.com/").unwrap(), &a)
                    .await
                    .unwrap()
            }));
        }
        // The peer has not started HTTP/3 or sent SETTINGS yet.
        while b.bi_rx.lock().await.len() < 8 {
            tokio::task::yield_now().await;
        }
        let b = H3Connection::new(b, Settings::default()).await.unwrap();
        let mut servers = Vec::new();
        for _ in 0..8 {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let incoming = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            servers.push(
                accept_connect(http::Response::new(()), ws, rs, b.qpack().clone(), incoming)
                    .await
                    .unwrap(),
            );
        }
        for task in clients {
            assert!(task.await.unwrap().0.status().is_success());
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn plain_connect_accepts_any_2xx() {
    let (a, b) = pair(1024).await;
    let (client, server) = tokio::join!(
        connect(client::Request::connect("example.com:443").unwrap(), &a),
        async {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let head = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            assert!(head.extensions().get::<h3x::Protocol>().is_none());
            assert_eq!(head.uri().authority().unwrap().as_str(), "example.com:443");
            accept_connect(
                http::Response::builder().status(201).body(()).unwrap(),
                ws,
                rs,
                b.qpack().clone(),
                head,
            )
            .await
            .unwrap()
        }
    );
    assert_eq!(client.unwrap().0.status(), 201);
    drop(server);
}

#[path = "connect/external_ws.rs"]
mod external_ws;

#[tokio::test]
async fn streaming_connect_uses_body_handles_and_gates_queued_data() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for convenience in [false, true] {
            let (a, b) = pair(3).await;
            let request = client::Request::connect("example.com:443").unwrap();
            let mut send = request.body();
            // Queue data before the handshake. It must stay in the body window.
            send.write_all(b"queued").await.unwrap();
            let (ws, rs) = a.open_bi().await.unwrap();
            let ((), ()) = tokio::join!(
                async {
                    let response = if convenience {
                        client::connect(request, ws, rs, a.qpack().clone())
                            .await
                            .unwrap()
                    } else {
                        client::write_streaming_request(request, ws, rs, a.qpack().clone())
                            .unwrap()
                            .await
                            .unwrap()
                    };
                    assert_eq!(response.status(), http::StatusCode::NO_CONTENT);
                    send.finish().await.unwrap();
                    assert_eq!(
                        response.into_body().collect().await.unwrap().as_ref(),
                        b"reply"
                    );
                },
                async {
                    let (ws, rs) = b.accept_bi().await.unwrap();
                    let request = server::read_request(rs, b.qpack().clone()).await.unwrap();
                    let method = request.method();
                    assert_eq!(method, http::Method::CONNECT);
                    let mut recv = request.into_body();
                    assert!(
                        tokio::time::timeout(Duration::from_millis(20), recv.read(&mut [0]))
                            .await
                            .is_err()
                    );
                    let mut response = server::Response::default().streaming(3);
                    // Any 2xx accepts CONNECT, including 204: DATA is still allowed.
                    response.set_status(http::StatusCode::NO_CONTENT);
                    let mut send = response.body();
                    let (written, ()) = tokio::join!(
                        server::write_streaming_response(response, ws, b.qpack().clone(), &method),
                        async {
                            assert_eq!(recv.collect().await.unwrap().as_ref(), b"queued");
                            send.write_all(b"reply").await.unwrap();
                            send.finish().await.unwrap();
                        }
                    );
                    written.unwrap();
                }
            );
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_streaming_connect_wakes_a_full_producer() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = pair(3).await;
        let request = client::Request::connect("example.com:443").unwrap();
        let mut send = request.body();
        send.write_all(&vec![1; 16 * 1024]).await.unwrap();
        let (ws, rs) = a.open_bi().await.unwrap();
        let (response, produced, ()) = tokio::join!(
            async {
                client::write_streaming_request(request, ws, rs, a.qpack().clone())
                    .unwrap()
                    .await
                    .unwrap()
            },
            send.write_all(b"blocked"),
            async {
                let (ws, rs) = b.accept_bi().await.unwrap();
                let request = server::read_request(rs, b.qpack().clone()).await.unwrap();
                request.into_body().stop().await;
                let mut response = server::Response::default();
                response
                    .set_status(http::StatusCode::FORBIDDEN)
                    .set_body(Bytes::from_static(b"denied"));
                server::write_bytes_response(
                    response,
                    ws,
                    b.qpack().clone(),
                    &http::Method::CONNECT,
                )
                .await
                .unwrap();
            }
        );
        assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
        assert_eq!(
            response.into_body().collect().await.unwrap().as_ref(),
            b"denied"
        );
        assert_eq!(produced.unwrap_err().code, ErrorCode::H3_REQUEST_CANCELLED);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn resetting_connect_body_cancels_a_pending_handshake() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = pair(3).await;
        let request = client::Request::connect("example.com:443").unwrap();
        let send = request.body();
        let (ws, rs) = a.open_bi().await.unwrap();
        let (result, ()) = tokio::join!(
            client::connect(request, ws, rs, a.qpack().clone()),
            async {
                let (_ws, mut rs) = b.accept_bi().await.unwrap();
                server::read_request_head(&mut rs, b.qpack()).await.unwrap();
                send.reset().await.unwrap();
            }
        );
        assert!(matches!(result, Err(client::ConnectError::H3(error)) if error.code == ErrorCode::H3_REQUEST_CANCELLED));
    }).await.unwrap();
}
