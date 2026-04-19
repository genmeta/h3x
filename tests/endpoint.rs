//! Integration tests exercising the new `h3x::endpoint` API.
//!
//! Each test pairs a server [`H3Endpoint`] + `serve(Router)` with a client
//! built on top of [`h3x::client::Client`] using [`QuicEndpoint`] as the
//! [`quic::Connect`](h3x::quic::Connect) implementation.

#![cfg(feature = "endpoint")]

mod common;

use std::sync::Arc;

use common::{CA_CERT, SERVER_CERT, SERVER_KEY, run};
use dquic::{
    prelude::{
        BindUri, BoundAddr, IO,
        handy::{ToCertificate, ToPrivateKey},
    },
    qinterface::component::route::QuicRouter,
    qresolve::SystemResolver,
};
use h3x::{
    client::Client,
    connection::ConnectionBuilder,
    endpoint::{
        ClientOnlyConfig, ClientQuicConfig, H3Endpoint, Identity, NamedIdentity, Network,
        QuicEndpoint, ServerCertVerifierChoice, ServerQuicConfig,
    },
    pool::Pool,
    server::{self, Router},
};
use http::uri::Authority;
use rustls::{
    RootCertStore,
    client::WebPkiServerVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tokio_util::task::AbortOnDropHandle;

async fn hello_service(_: &mut server::Request, response: &mut server::Response) {
    response
        .set_status(http::StatusCode::OK)
        .set_body(&b"hello from endpoint"[..]);
}

fn named_server_identity() -> Identity {
    let certs: Vec<CertificateDer<'static>> = SERVER_CERT.to_certificate();
    let key: PrivateKeyDer<'static> = SERVER_KEY.to_private_key();
    Identity::Named(Arc::new(NamedIdentity {
        name: Arc::from("localhost"),
        certs,
        key: Arc::new(key),
    }))
}

fn client_webpki_verifier() -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(CA_CERT.to_certificate());
    WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .expect("failed to build webpki verifier")
}

fn test_network() -> Arc<Network> {
    // Each test uses its own `QuicRouter` so that parallel tests do not
    // stomp on each other's connectionless dispatcher.
    Network::builder()
        .quic_router(Arc::new(QuicRouter::new()))
        .build()
}

#[test]
fn serve_and_connect_hello() {
    run("serve_and_connect_hello", async move {
        let network = test_network();

        // --- Server ---
        let server_quic = QuicEndpoint::new(
            network.clone(),
            named_server_identity(),
            Arc::new(SystemResolver),
            ClientQuicConfig::default(),
            ServerQuicConfig::default(),
        );
        let bind_iface = network.bind(BindUri::from("inet://127.0.0.1:0")).await;
        let bound_addr = bind_iface
            .borrow()
            .bound_addr()
            .expect("bind interface must have a local address");
        let port = match bound_addr {
            BoundAddr::Internet(socket_addr) => socket_addr.port(),
            _ => unreachable!("bound to inet://127.0.0.1"),
        };

        let server_endpoint = H3Endpoint::new(
            server_quic,
            Pool::empty(),
            Arc::new(ConnectionBuilder::new(Arc::default())),
        );
        let router = Router::new().get("/hello", hello_service);
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(
                async move { server_endpoint.serve(router).await },
            ));

        // --- Client ---
        let client_own = ClientOnlyConfig {
            verifier: ServerCertVerifierChoice::WebPki(client_webpki_verifier()),
            ..Default::default()
        };
        let client_quic_config = ClientQuicConfig {
            common: Arc::default(),
            own: Arc::new(client_own),
        };
        let client_quic = QuicEndpoint::new(
            network.clone(),
            Identity::Anonymous,
            Arc::new(SystemResolver),
            client_quic_config,
            ServerQuicConfig::default(),
        );
        let client = Client::from_quic_client().client(client_quic).build();

        let authority: Authority = format!("localhost:{port}")
            .parse()
            .expect("valid authority");
        let uri: http::Uri = format!("https://{authority}/hello").parse().unwrap();
        let (_request, mut response) = client
            .new_request()
            .with_authority(authority)
            .get(uri)
            .await
            .expect("failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .read_to_string()
            .await
            .expect("failed to read response body");
        assert_eq!(body, "hello from endpoint");
    });
}

// ---------------------------------------------------------------------------
// bind_server semantics
// ---------------------------------------------------------------------------

fn named_with(name: &str) -> Arc<NamedIdentity> {
    let certs: Vec<CertificateDer<'static>> = SERVER_CERT.to_certificate();
    let key: PrivateKeyDer<'static> = SERVER_KEY.to_private_key();
    Arc::new(NamedIdentity {
        name: Arc::from(name),
        certs,
        key: Arc::new(key),
    })
}

#[test]
fn bind_server_sni_in_use() {
    run("bind_server_sni_in_use", async move {
        let network = test_network();
        let a = named_with("localhost");
        let b = named_with("localhost");
        let _first = network
            .bind_server(a, ServerQuicConfig::default())
            .await
            .expect("first bind succeeds");
        let err = network
            .bind_server(b, ServerQuicConfig::default())
            .await
            .expect_err("second bind with different identity must fail");
        assert!(
            matches!(err, h3x::endpoint::BindServerError::SniInUse { .. }),
            "unexpected error: {err:?}"
        );
    });
}

#[test]
fn bind_server_reuses_identity() {
    run("bind_server_reuses_identity", async move {
        let network = test_network();
        let id = named_with("localhost");
        let first = network
            .bind_server(id.clone(), ServerQuicConfig::default())
            .await
            .expect("first bind succeeds");
        let second = network
            .bind_server(id.clone(), ServerQuicConfig::default())
            .await
            .expect("same identity must reuse binding");
        assert_eq!(first.name, second.name);
    });
}

#[test]
fn bind_server_config_conflict() {
    run("bind_server_config_conflict", async move {
        let network = test_network();
        let a = named_with("alpha");
        let b = named_with("beta");

        let cfg_a = ServerQuicConfig::default();
        let cfg_b = {
            let own = h3x::endpoint::ServerOnlyConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            };
            ServerQuicConfig {
                common: Arc::default(),
                own: Arc::new(own),
            }
        };

        let _held = network
            .bind_server(a, cfg_a)
            .await
            .expect("first bind succeeds");
        let err = network
            .bind_server(b, cfg_b)
            .await
            .expect_err("incompatible server config must fail");
        assert!(
            matches!(err, h3x::endpoint::BindServerError::ServerConfigConflict),
            "unexpected error: {err:?}"
        );
    });
}

#[test]
fn bind_server_slot_auto_reset() {
    run("bind_server_slot_auto_reset", async move {
        let network = test_network();

        let cfg_a = ServerQuicConfig::default();
        let cfg_b = {
            let own = h3x::endpoint::ServerOnlyConfig {
                alpns: vec![b"altproto".to_vec()],
                ..Default::default()
            };
            ServerQuicConfig {
                common: Arc::default(),
                own: Arc::new(own),
            }
        };

        {
            let _first = network
                .bind_server(named_with("alpha"), cfg_a)
                .await
                .expect("first bind succeeds");
        }
        // After the binding drops the slot should clear, allowing a new
        // incompatible config to install.
        let _second = network
            .bind_server(named_with("beta"), cfg_b)
            .await
            .expect("slot should auto-reset after last binding dropped");
    });
}
