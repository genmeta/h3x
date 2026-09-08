#![cfg(feature = "axum")]

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures::FutureExt;
use h3x::{
    Endpoint, Error, Pool, PoolConfig, RemoteAuthority, RequestAuthority,
    transport::{Backend, PendingTransport},
};
use http_body_util::BodyExt;
use tokio::{io::AsyncWriteExt, sync::mpsc};

mod support;
use support::MemoryTransport;

fn endpoint(name: &str) -> Arc<Endpoint> {
    let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    Endpoint::new(
        name,
        vec![generated.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into(),
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn request_pool_ownership_streaming_and_shutdown() {
    tokio::time::timeout(Duration::from_secs(15), scenario())
        .await
        .expect("request/pool lifecycle must make progress");
}

async fn scenario() {
    let alice = endpoint("alice.example.test");
    let bob = endpoint("bob.example.test");
    let peers = Arc::new(HashMap::from([
        (alice.name().to_owned(), alice.clone()),
        (bob.name().to_owned(), bob.clone()),
    ]));
    let (incoming, received) = mpsc::channel(8);
    let connections = Arc::new(AtomicUsize::new(0));
    let count = connections.clone();
    let dial_gate = Arc::new(tokio::sync::Semaphore::new(0));
    let gate = dial_gate.clone();
    let mut backend = Backend::new(
        move |local: h3x::transport::Credentials, target: http::uri::Authority| {
            let peers = peers.clone();
            let incoming = incoming.clone();
            let count = count.clone();
            let gate = gate.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                gate.acquire().await.unwrap().forget();
                let peer = peers.get(target.host()).unwrap();
                let (client, server) = MemoryTransport::pair();
                let local_fact = local
                    .as_ref()
                    .map(|(endpoint, cert)| (endpoint.name().to_owned(), cert.clone()));
                let local_remote = local.as_ref().map(|(endpoint, cert)| {
                    RemoteAuthority::from_authenticated(endpoint.name(), cert.cert.clone()).unwrap()
                });
                incoming
                    .send(Ok(PendingTransport::new(
                        server,
                        Some((peer.name().to_owned(), peer.certificate())),
                        local_remote,
                        local
                            .as_ref()
                            .map(|(endpoint, _)| endpoint.name().parse().unwrap()),
                    )))
                    .await
                    .unwrap();
                Ok(PendingTransport::new(
                    client,
                    local_fact,
                    Some(
                        RemoteAuthority::from_authenticated(
                            peer.name(),
                            peer.certificate().cert.clone(),
                        )
                        .unwrap(),
                    ),
                    Some(target),
                ))
            }
        },
    );
    backend.incoming = Some(Box::pin(futures::stream::unfold(
        received,
        |mut received| async move {
            received
                .recv()
                .await
                .map(|value| (async move { value }.boxed(), received))
        },
    )));
    backend.listen = Some(Arc::new(|_, _, _| async { Ok(()) }.boxed()));
    let pool = Pool::init(
        backend,
        PoolConfig {
            max_body_buffer: 80,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();
    std::thread::spawn(move || {
        let other = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(matches!(
            other.block_on(pool.get(None, "bob.example.test")),
            Err(Error::InvalidState { .. })
        ));
    })
    .join()
    .unwrap();
    let (consumed, mut consumption) = mpsc::channel(4);
    let service = axum::Router::new()
        .route(
            "/reject",
            axum::routing::post(|| async { (http::StatusCode::FORBIDDEN, "denied") }),
        )
        .route(
            "/consume",
            axum::routing::post(move |request: axum::extract::Request| {
                let consumed = consumed.clone();
                async move {
                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                    consumed.send(bytes).await.unwrap();
                    "accepted"
                }
            }),
        )
        .fallback(|request: axum::extract::Request| async move {
            assert!(matches!(
                request.extensions().get::<RequestAuthority>(),
                Some(RequestAuthority::Peer(_))
            ));
            http::Response::new(request.into_body())
        });
    alice.listen(service.clone()).await.unwrap();
    bob.listen(service).await.unwrap();
    assert!(matches!(
        bob.listen(axum::Router::new()).await,
        Err(Error::AlreadyListening)
    ));

    // Construction and invalid headers cannot dial or allocate an upload pipe.
    let invalid = alice
        .post("https://bob.example.test/echo")
        .unwrap()
        .header("bad\nname", "x");
    assert_eq!(connections.load(Ordering::Relaxed), 0);
    assert!(matches!(invalid.await, Err(Error::InvalidMessage { .. })));
    assert_eq!(connections.load(Ordering::Relaxed), 0);

    // Both waiters leave; the shared dial remains available to the next request.
    let mut first = Box::pin(pool.get(Some(alice.clone()), bob.name()));
    let mut second = Box::pin(pool.get(Some(alice.clone()), bob.name()));
    assert!(futures::poll!(&mut first).is_pending());
    assert!(futures::poll!(&mut second).is_pending());
    drop((first, second));
    tokio::task::yield_now().await;
    assert_eq!(connections.load(Ordering::Relaxed), 1);
    dial_gate.add_permits(1);

    let response = alice
        .get("https://bob.example.test/echo")
        .unwrap()
        .await
        .unwrap();
    assert_eq!(response.authority().unwrap().name(), bob.name());
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let payload = Bytes::from(vec![42; 8192]);
    let response = alice
        .post("https://bob.example.test/echo")
        .unwrap()
        .body(payload.clone())
        .await
        .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        payload
    );

    let (mut writer, response) = alice
        .streaming_post("https://bob.example.test/echo")
        .unwrap()
        .await
        .unwrap();
    let sending = async {
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-upload-done", "yes".parse().unwrap());
        writer.trailers(trailers).await.unwrap();
    };
    let receiving = async {
        let collected = response.await.unwrap().into_body().collect().await.unwrap();
        assert_eq!(collected.trailers().unwrap()["x-upload-done"], "yes");
        assert_eq!(collected.to_bytes(), payload);
    };
    futures::join!(sending, receiving);
    assert_eq!(connections.load(Ordering::Relaxed), 1);

    // Passive connection reuse preserves the opposite initiating identity.
    let reverse = bob
        .get("https://alice.example.test/echo")
        .unwrap()
        .await
        .unwrap();
    assert_eq!(reverse.authority().unwrap().name(), alice.name());
    reverse.into_body().collect().await.unwrap();
    assert_eq!(connections.load(Ordering::Relaxed), 1);

    // ResponseFuture Drop does not cancel a still-held upload capability.
    let (mut writer, response) = alice
        .streaming_post("https://bob.example.test/consume")
        .unwrap()
        .await
        .unwrap();
    drop(response);
    writer
        .write_all(b"upload survives response drop")
        .await
        .unwrap();
    writer.finish().await.unwrap();
    assert_eq!(
        consumption.recv().await.unwrap(),
        "upload survives response drop"
    );

    // A peer refusing the body can still deliver its complete HTTP response.
    let (mut writer, response) = alice
        .streaming_post("https://bob.example.test/reject")
        .unwrap()
        .await
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "denied"
    );
    let send = async {
        writer.write_all(&payload).await?;
        writer.shutdown().await
    };
    assert!(send.await.is_err());

    let connection = pool.get(Some(alice.clone()), bob.name()).await.unwrap();
    pool.close(&connection, Duration::from_secs(2))
        .await
        .unwrap();
    dial_gate.add_permits(1);
    let replacement = pool.get(Some(alice), bob.name()).await.unwrap();
    assert!(!Arc::ptr_eq(&connection, &replacement));
    pool.shutdown(Duration::from_secs(2)).await.unwrap();
    pool.shutdown(Duration::ZERO).await.unwrap();
    assert!(matches!(
        pool.get(None, bob.name()).await,
        Err(Error::Draining)
    ));
}
