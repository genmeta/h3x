#![allow(unused)]

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use h3x::dquic::{
    Name,
    cert::handy::{ToCertificate, ToPrivateKey},
    net::IO,
    resolver::handy::SystemResolver,
};
use http::uri::Authority;
use tokio::time;
use tracing::{Instrument, level_filters::LevelFilter};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    Layer, prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt,
};

pub const TEST_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run<F: Future>(test_name: &'static str, future: F) -> F::Output {
    static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    });

    static TRACING: LazyLock<WorkerGuard> = LazyLock::new(|| {
        let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

        tracing_subscriber::registry()
            // .with(console_subscriber::spawn())
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(non_blocking)
                    .with_file(true)
                    .with_line_number(true)
                    .with_filter(LevelFilter::DEBUG),
            )
            .with(tracing_subscriber::filter::filter_fn(|metadata| {
                !metadata.target().contains("netlink_packet_route")
            }))
            .init();
        guard
    });

    RT.block_on(async move {
        LazyLock::force(&TRACING);
        let test = future.instrument(tracing::info_span!("test", test_name));
        match time::timeout(TEST_TIMEOUT, test).await {
            Ok(output) => output,
            Err(_timedout) => panic!("test timed out"),
        }
    })
}

pub const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
pub const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
pub const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");
pub const TEST_DATA: &[u8] = include_bytes!("mod.rs");

pub async fn test_client() -> h3x::dquic::H3Endpoint {
    let quic = h3x::dquic::QuicEndpoint::builder().build().await;
    h3x::endpoint::H3Endpoint::new(quic)
}

pub async fn test_server() -> (h3x::dquic::H3Endpoint, Authority) {
    let identity = Arc::new(h3x::dquic::Identity {
        name: "localhost".parse().unwrap(),
        certs: Arc::new(SERVER_CERT.to_certificate()),
        key: Arc::new(SERVER_KEY.to_private_key()),
        ocsp: Arc::new(None),
    });
    let network = h3x::dquic::Network::builder().build();
    let quic = h3x::dquic::QuicEndpoint::builder()
        .network(network.clone())
        .identity(identity)
        .bind(Arc::new(vec![
            "127.0.0.1:0".parse().expect("valid pattern"),
        ]))
        .build()
        .await;
    let bind_iface = network
        .interfaces()
        .into_iter()
        .next()
        .expect("no bound interface");
    let port = bind_iface
        .borrow()
        .bound_addr()
        .expect("no bound addr")
        .port();
    let authority = Authority::from_maybe_shared(format!("localhost:{port}"))
        .expect("failed to parse authority");
    (h3x::endpoint::H3Endpoint::new(quic), authority)
}
