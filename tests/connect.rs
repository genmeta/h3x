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
    Transport, WriteBody, WriteRequest, WriteResponse,
    client::{self, ConnectOutcome},
    server,
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
        self.bi_tx
            .send((id, (TestStream::new(br), TestStream::new(bw))))
            .unwrap();
        Ok(Some((id, (TestStream::new(ar), TestStream::new(aw)))))
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
async fn tunnels(
    a: &H3Connection<MemoryTransport>,
    b: &H3Connection<MemoryTransport>,
) -> (h3x::Tunnel<R, W>, h3x::Tunnel<R, W>) {
    let (client, server) = tokio::join!(
        client::connect(
            client::Request::connect("wss://home.example/api/websocket?q=1").unwrap(),
            a
        ),
        async {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let request = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            assert_eq!(
                request
                    .extensions()
                    .get::<h3x::ext::Protocol>()
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
            server::accept_connect(
                http::Response::new(()),
                ws,
                rs,
                b.qpack().clone(),
                request.method(),
            )
            .await
            .unwrap()
        }
    );
    let ConnectOutcome::Connected { response, tunnel } = client.unwrap() else {
        panic!()
    };
    assert_eq!(response.status(), 200);
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
    let (a, b) = pair(3).await;
    let (result, ()) = tokio::join!(
        async {
            let result =
                client::connect(client::Request::connect("ws://home.example/").unwrap(), &a)
                    .await
                    .unwrap();
            let ConnectOutcome::Rejected(response) = result else {
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
async fn delayed_settings_wakes_all_connects_and_unsupported_keeps_connection_usable() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let (a, b) = transports(1024);
    let probe = a.base.clone();
    let a = H3Connection::new(a, Settings::default()).await.unwrap();
    let mut waiting: Vec<_> = (0..8)
        .map(|_| {
            Box::pin(client::connect(
                client::Request::connect("ws://example.com/").unwrap(),
                &a,
            ))
        })
        .collect();
    for future in &mut waiting {
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    assert!(
        b.bi_rx.lock().await.try_recv().is_err(),
        "no stream before SETTINGS"
    );
    // A peer implementation that omits ENABLE_CONNECT_PROTOCOL.
    let (_, mut control) = b.open_uni().await.unwrap().unwrap();
    control.write_all(&[0, 4, 0]).await.unwrap(); // control stream, empty SETTINGS
    control.flush().await.unwrap();
    for future in waiting {
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), future)
                .await
                .unwrap(),
            Err(client::ConnectError::NotSupported)
        ));
    }
    let (_ws, _rs) = a.open_bi().await.unwrap();
    let (_id, (_rs, _ws)) = b.accept_bi().await.unwrap();
    probe
        .close("done".into(), ErrorCode::H3_NO_ERROR.as_u64())
        .unwrap();
}
#[tokio::test]
async fn settings_wait_ends_on_connection_termination() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let (a, _b) = transports(1024);
    let probe = a.base.clone();
    let a = H3Connection::new(a, Settings::default()).await.unwrap();
    let mut future = Box::pin(client::connect(
        client::Request::connect("ws://example.com/").unwrap(),
        &a,
    ));
    assert!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    probe
        .close("closed".into(), ErrorCode::H3_INTERNAL_ERROR.as_u64())
        .unwrap();
    assert!(matches!(future.await, Err(client::ConnectError::H3(_))));
}
#[tokio::test]
async fn cancelled_tunnel_does_not_disrupt_http_or_other_tunnels() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = pair(1024).await;
        let (mut cancelled, other) = tunnels(&a, &b).await;
        let (mut live, mut peer) = tunnels(&a, &b).await;
        cancelled.abort();
        drop(cancelled);
        drop(other);
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
        assert!(matches!(client::connect(client::Request::connect("ws://example.com/").unwrap(),&a).await,Err(client::ConnectError::H3(e)) if e.code==ErrorCode::H3_REQUEST_REJECTED));
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
    let mut handshake = Box::pin(client::connect(
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
    assert!(
        server::accept_connect(
            http::Response::new(()),
            ws,
            rs,
            b.qpack().clone(),
            incoming.method()
        )
        .await
        .is_err()
    );
    let (_ws, _rs) = a.open_bi().await.unwrap();
    let (_ws, _rs) = b.accept_bi().await.unwrap();
}

#[tokio::test]
async fn delayed_enabled_settings_releases_all_handshakes() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (a, b) = transports(1024);
        let a = H3Connection::new(a, Settings::default()).await.unwrap();
        let mut clients = Vec::new();
        for _ in 0..8 {
            let a = a.clone();
            clients.push(tokio::spawn(async move {
                client::connect(client::Request::connect("ws://example.com/").unwrap(), &a)
                    .await
                    .unwrap()
            }));
        }
        tokio::task::yield_now().await;
        assert!(b.bi_rx.lock().await.try_recv().is_err());
        let b = H3Connection::new(b, Settings::default()).await.unwrap();
        let mut servers = Vec::new();
        for _ in 0..8 {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let incoming = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            servers.push(
                server::accept_connect(
                    http::Response::new(()),
                    ws,
                    rs,
                    b.qpack().clone(),
                    incoming.method(),
                )
                .await
                .unwrap(),
            );
        }
        for task in clients {
            assert!(matches!(
                task.await.unwrap(),
                ConnectOutcome::Connected { .. }
            ));
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn plain_connect_accepts_any_2xx() {
    let (a, b) = pair(1024).await;
    let (client, server) = tokio::join!(
        client::connect(client::Request::connect("example.com:443").unwrap(), &a),
        async {
            let (ws, mut rs) = b.accept_bi().await.unwrap();
            let head = server::read_request_head(&mut rs, b.qpack()).await.unwrap();
            assert!(head.extensions().get::<h3x::ext::Protocol>().is_none());
            assert_eq!(head.uri().authority().unwrap().as_str(), "example.com:443");
            server::accept_connect(
                http::Response::builder().status(201).body(()).unwrap(),
                ws,
                rs,
                b.qpack().clone(),
                head.method(),
            )
            .await
            .unwrap()
        }
    );
    assert!(
        matches!(client.unwrap(),ConnectOutcome::Connected{response,..} if response.status()==201)
    );
    drop(server);
}

#[path = "connect/external_ws.rs"]
mod external_ws;
