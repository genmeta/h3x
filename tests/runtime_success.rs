//! Exercise the production runtime over loopback QUIC, including its task limit.
use std::{
    collections::HashMap,
    convert::Infallible,
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use dquic::{
    prelude::{BindUri, IO, QuicClient, QuicListeners},
    qresolve::{self, Resolve},
};
use futures::{StreamExt, future::BoxFuture};
use h3x::{Endpoint, Fixed, client::Request, runtime::Runtime};
use http_body_util::{BodyExt, Full};
use qbase::param::{
    ParameterId,
    handy::{client_parameters, server_parameters},
};
use tokio::{
    io::AsyncWriteExt,
    sync::{Semaphore, mpsc},
    task::JoinSet,
    time::timeout,
};

#[derive(Debug)]
struct Loopback(HashMap<String, SocketAddr>);
impl fmt::Display for Loopback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test loopback")
    }
}
impl Resolve for Loopback {
    fn lookup<'a>(
        &'a self,
        name: &'a str,
        _: &'a str,
        _: Option<qresolve::Family>,
    ) -> qresolve::ResolveFuture<'a> {
        Box::pin(async move {
            let address = *self.0.get(name).expect("registered test endpoint");
            Ok(futures::stream::iter([(qresolve::Source::System, address.into())]).boxed())
        })
    }
}

struct Alive(Arc<AtomicUsize>);
impl Alive {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(count.clone())
    }
}
impl Drop for Alive {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
struct ResponseBody {
    inner: Full<Bytes>,
    _alive: Alive,
}
impl http_body::Body for ResponseBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}
struct Service {
    events: mpsc::UnboundedSender<(String, Option<String>, String)>,
    release: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
    sending: Arc<AtomicUsize>,
}
impl tower_service::Service<h3x::server::Request> for Service {
    type Response = h3x::server::Response<ResponseBody>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: h3x::server::Request) -> Self::Future {
        let events = self.events.clone();
        let release = self.release.clone();
        let running = self.running.clone();
        let sending = self.sending.clone();
        Box::pin(async move {
            let _alive = Alive::new(&running);
            let path = request.request().uri().path().to_owned();
            events
                .send((
                    request.local_authority().0.name().to_owned(),
                    request.remote_authority().map(|a| a.name().to_owned()),
                    path.clone(),
                ))
                .unwrap();
            if path == "/hold" || path == "/queued" {
                release.acquire().await.unwrap().forget();
            }
            let data = if path == "/send" {
                Bytes::from(vec![b'x'; 4 << 20])
            } else {
                Bytes::from_static(b"ok")
            };
            Ok(request.response(http::Response::new(ResponseBody {
                inner: Full::new(data),
                _alive: Alive::new(&sending),
            })))
        })
    }
}

#[tokio::test]
async fn runtime_initialization_reuse_admission_and_shutdown() {
    timeout(Duration::from_secs(30), async {
        let endpoints: Vec<_> = ["server.test", "alice.test", "bob.test"]
            .into_iter()
            .map(|name| {
                let cert = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
                Endpoint::new(
                    name,
                    vec![cert.cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                        .into(),
                    None,
                )
                .unwrap()
            })
            .collect();
        let mut roots = rustls::RootCertStore::empty();
        for endpoint in &endpoints {
            roots.add(endpoint.certificate().cert[0].clone()).unwrap();
        }
        let mut parameters = server_parameters();
        parameters
            .set(
                ParameterId::InitialMaxStreamsBidi,
                qbase::varint::VarInt::from_u32(1024),
            )
            .unwrap();
        let listeners = QuicListeners::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
                    .allow_unauthenticated()
                    .build()
                    .unwrap(),
            )
            .with_parameters(parameters)
            .with_alpns([h3x::ALPN])
            .listen(16)
            .unwrap();
        let mut addresses = HashMap::new();
        for endpoint in &endpoints {
            listeners
                .add_server_certified(
                    endpoint.name(),
                    endpoint.certificate(),
                    [BindUri::from("inet://127.0.0.1:0").alloc_port()],
                )
                .await
                .unwrap();
            let server = listeners.get_server(endpoint.name()).unwrap();
            let interface = server.bind_interfaces().into_iter().next().unwrap().1;
            addresses.insert(
                endpoint.name().to_owned(),
                interface.borrow().bound_addr().unwrap(),
            );
        }
        let resolver = Arc::new(Loopback(addresses));
        let client = |endpoint: Option<&Arc<Endpoint>>| {
            let mut parameters = client_parameters();
            parameters
                .set(
                    ParameterId::InitialMaxStreamsBidi,
                    qbase::varint::VarInt::from_u32(1024),
                )
                .unwrap();
            let builder = QuicClient::builder()
                .with_resolver(resolver.clone())
                .with_root_certificates(roots.clone())
                .with_parameters(parameters);
            let builder = match endpoint {
                Some(endpoint) => builder
                    .with_cert_resolver(endpoint.clone())
                    .with_name(endpoint.name()),
                None => builder.without_cert(),
            };
            Arc::new(builder.with_alpns([h3x::ALPN]).build())
        };
        h3x::init(
            endpoints
                .iter()
                .map(|e| (e.clone(), client(Some(e))))
                .collect(),
            client(None),
            listeners.clone(),
        )
        .unwrap();
        let (events, mut received) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let running = Arc::new(AtomicUsize::new(0));
        let sending = Arc::new(AtomicUsize::new(0));
        endpoints[0]
            .listen(Service {
                events,
                release: release.clone(),
                running: running.clone(),
                sending: sending.clone(),
            })
            .await
            .unwrap();

        let (first, same) = tokio::join!(
            Runtime::get(Some(endpoints[1].clone()), "server.test"),
            Runtime::get(Some(endpoints[1].clone()), "server.test")
        );
        let first = first.unwrap();
        assert!(Arc::ptr_eq(&first, &same.unwrap()));
        let other = Runtime::get(Some(endpoints[2].clone()), "server.test")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &other));
        for identity in [Some(endpoints[1].clone()), Some(endpoints[2].clone()), None] {
            let mut request = Request::new(
                http::Method::GET,
                "https://server.test/ok",
                Fixed::default(),
            )
            .unwrap();
            if let Some(identity) = &identity {
                request = request.with_identity(identity.clone());
            }
            let response = request.await.unwrap();
            assert_eq!(response.authority().name(), "server.test");
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "ok"
            );
            assert_eq!(
                received.recv().await.unwrap(),
                (
                    "server.test".into(),
                    identity.map(|i| i.name().to_owned()),
                    "/ok".into()
                )
            );
        }
        assert!(Arc::ptr_eq(
            &first,
            &Runtime::get(Some(endpoints[1].clone()), "server.test")
                .await
                .unwrap()
        ));

        // This response remains blocked in production send_body while its peer does not read.
        let sending_response = Request::new(
            http::Method::GET,
            "https://server.test/send",
            Fixed::default(),
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(received.recv().await.unwrap().2, "/send");
        timeout(Duration::from_secs(2), async {
            while sending.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("earlier responses did not finish");

        // One incomplete HEADERS plus 255 executing services occupy all 256 tasks.
        let (_, (half_recv, mut half_send)) = first
            .protocol()
            .transport()
            .open_bi_stream()
            .await
            .unwrap()
            .unwrap();
        half_send.write_all(&[1, 0x40]).await.unwrap();
        let mut requests = JoinSet::new();
        for _ in 0..255 {
            let connection = first.clone();
            requests.spawn(async move {
                let response = connection
                    .protocol()
                    .request(
                        http::Request::builder()
                            .uri("https://server.test/hold")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                    .await?;
                response.into_body().collect().await.map(|_| ())
            });
        }
        for _ in 0..255 {
            assert_eq!(received.recv().await.unwrap().2, "/hold");
        }
        let connection = first.clone();
        requests.spawn(async move {
            let response = connection
                .protocol()
                .request(
                    http::Request::builder()
                        .uri("https://server.test/queued")
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await?;
            response.into_body().collect().await.map(|_| ())
        });
        assert!(
            timeout(Duration::from_millis(150), received.recv())
                .await
                .is_err()
        );
        assert_eq!(running.load(Ordering::SeqCst), 255);
        release.add_permits(1);
        assert_eq!(received.recv().await.unwrap().2, "/queued");
        requests.join_next().await.unwrap().unwrap().unwrap();
        assert_eq!(running.load(Ordering::SeqCst), 255);

        // A full application task set must not prevent peer control-stream processing.
        let reverse = Runtime::get(Some(endpoints[0].clone()), "alice.test")
            .await
            .unwrap();
        let mut graceful = Box::pin(first.protocol().shutdown());
        assert!(futures::poll!(graceful.as_mut()).is_pending());
        timeout(Duration::from_secs(2), async {
            while !reverse.is_draining() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("GOAWAY stalled behind request tasks");
        assert_eq!(running.load(Ordering::SeqCst), 255);
        assert_eq!(sending.load(Ordering::SeqCst), 1);

        h3x::shutdown().await.unwrap();
        drop(graceful);
        assert_eq!(
            running.load(Ordering::SeqCst),
            0,
            "shutdown must join executing services"
        );
        assert_eq!(
            sending.load(Ordering::SeqCst),
            0,
            "shutdown must join blocked response sends"
        );
        while let Some(result) = requests.join_next().await {
            assert!(result.unwrap().is_err());
        }
        assert!(half_send.write_all(b"tail").await.is_err());
        drop((half_recv, half_send, sending_response));
        assert!(matches!(
            Runtime::get(None, "server.test").await,
            Err(h3x::Error::Draining)
        ));
        h3x::shutdown().await.unwrap();
        listeners.shutdown();
    })
    .await
    .expect("runtime acceptance test timed out");
}
