#![allow(unused)]

use std::{
    error::Error,
    sync::{Arc, LazyLock},
    time::Duration,
};

use gm_quic::{
    prelude::{
        BindUri, QuicIO, RealAddr,
        handy::{ToCertificate, ToPrivateKey},
    },
    qinterface::component::route::QuicRouter,
};
use h3x::{
    gm_quic::{H3Client, H3Servers},
    server::UnresolvedRequest,
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
            .unwrap()
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

pub fn test_client() -> H3Client {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
    H3Client::builder()
        .with_root_certificates(roots)
        .without_identity()
        .expect("failed to initialize client tls")
        .with_router(Arc::new(QuicRouter::new()))
        .build()
}

pub async fn test_server<S>(router: S) -> H3Servers<S>
where
    S: tower_service::Service<UnresolvedRequest, Response = ()> + Clone + Send + Sync + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let mut servers = H3Servers::builder()
        .without_client_cert_verifier()
        .expect("failed to initialize server tls")
        .with_router(Arc::new(QuicRouter::new()))
        .listen()
        .expect("failed to listen");
    servers
        .add_server(
            "localhost",
            SERVER_CERT.to_certificate(),
            SERVER_KEY.to_private_key(),
            None,
            [
                BindUri::from("inet://127.0.0.1:0").alloc_port(),
                BindUri::from("inet://[::1]:0").alloc_port(),
            ],
            router,
        )
        .await
        .expect("failed to add server");
    servers
}

pub fn get_server_addr<S>(servers: &H3Servers<S>) -> RealAddr {
    let localhost = servers
        .quic_listener()
        .get_server("localhost")
        .expect("server localhost must be registered");
    let (_bind_uri, localhost_bind_interface) = localhost
        .bind_interfaces()
        .into_iter()
        .next()
        .expect("server localhost must have at least one bind interface");
    localhost_bind_interface
        .borrow()
        .real_addr()
        .expect("bind interface must have local addr")
}

pub fn get_server_authority<S>(servers: &H3Servers<S>) -> Authority {
    match get_server_addr(servers) {
        RealAddr::Internet(socket_addr) => {
            Authority::from_maybe_shared(Vec::from(format!("localhost:{}", socket_addr.port())))
                .expect("failed to parse authority")
        }
        _ => unimplemented!("Only Internet addresses are supported now"),
    }
}
