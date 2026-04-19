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
    qbase::net::addr::{EndpointAddr, SocketEndpointAddr},
    qinterface::{component::route::QuicRouter, manager::InterfaceManager},
    qresolve::{Resolve, ResolveFuture, Source, SystemResolver},
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
    // Each test uses its own `QuicRouter` AND `InterfaceManager` so that
    // parallel tests do not share the global dispatcher or cross-route
    // packets destined for other tests.
    Network::builder()
        .quic_router(Arc::new(QuicRouter::new()))
        .iface_manager(Arc::new(InterfaceManager::new()))
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

// ---------------------------------------------------------------------------
// Multi-server end-to-end tests
// ---------------------------------------------------------------------------

/// Test-only resolver that maps every name lookup to a fixed loopback
/// endpoint. Lets tests dial arbitrary SNIs (e.g. `alpha`, `beta`) without
/// requiring `/etc/hosts` entries.
#[derive(Debug)]
struct FixedResolver(std::net::SocketAddr);

impl std::fmt::Display for FixedResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedResolver({})", self.0)
    }
}

impl Resolve for FixedResolver {
    fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
        use futures::{FutureExt, StreamExt, stream};
        let ep = EndpointAddr::Socket(SocketEndpointAddr::direct(self.0));
        let source = Source::System;
        async move { Ok(stream::iter(std::iter::once((source, ep))).boxed()) }.boxed()
    }
}

async fn alpha_service(_: &mut server::Request, response: &mut server::Response) {
    response
        .set_status(http::StatusCode::OK)
        .set_body(&b"alpha"[..]);
}

async fn beta_service(_: &mut server::Request, response: &mut server::Response) {
    response
        .set_status(http::StatusCode::OK)
        .set_body(&b"beta"[..]);
}

/// Two named servers (`alpha`, `beta`) share one [`Network`] and one listen
/// port. Both register distinct SNIs via the Network's SNI registry. A
/// client dialing `alpha:PORT` must receive the `alpha` handler's response,
/// and `beta:PORT` must receive `beta`'s. This exercises:
///
/// * shared [`Network`] infrastructure (one bind port, one QuicRouter, one
///   connectionless dispatcher);
/// * the Network's per-SNI mpmc fan-out (`sni_registry` + `bind_server`);
/// * rustls [`SniCertResolver`] picking the correct [`CertifiedKey`];
/// * [`QuicEndpoint::accept`] returning only connections destined for its
///   own SNI.
#[test]
fn two_sni_share_network_and_port() {
    run("two_sni_share_network_and_port", async move {
        let network = test_network();
        let bind_iface = network.bind(BindUri::from("inet://127.0.0.1:0")).await;
        let port = match bind_iface.borrow().bound_addr().unwrap() {
            BoundAddr::Internet(s) => s.port(),
            _ => unreachable!(),
        };
        let resolver: Arc<dyn Resolve + Send + Sync> =
            Arc::new(FixedResolver(format!("127.0.0.1:{port}").parse().unwrap()));

        let mut serve_handles = Vec::new();
        let mut bindings = Vec::new(); // keep SNI registrations alive before spawn
        // Share one config Arc across both servers; otherwise
        // `ServerQuicConfig::default()` yields fresh trait objects each
        // call and `server_config_compatible` rejects the second bind.
        let shared_server_config = ServerQuicConfig::default();
        let alpha_router = Router::new().get("/hello", alpha_service);
        let beta_router = Router::new().get("/hello", beta_service);
        for (name, router) in [("alpha", alpha_router), ("beta", beta_router)] {
            let named = named_with(name);
            // Eagerly register so rustls' SniCertResolver sees both SNIs
            // before the first ClientHello arrives (avoids a startup race
            // where a client connects before the server task has polled
            // its first `accept()`).
            let binding = network
                .bind_server(named.clone(), shared_server_config.clone())
                .await
                .expect("eager bind_server");
            bindings.push(binding);
            let quic = QuicEndpoint::new(
                network.clone(),
                Identity::Named(named),
                resolver.clone(),
                ClientQuicConfig::default(),
                shared_server_config.clone(),
            );
            let h3 = H3Endpoint::new(
                quic,
                Pool::empty(),
                Arc::new(ConnectionBuilder::new(Arc::default())),
            );
            serve_handles.push(AbortOnDropHandle::new(tokio::spawn(async move {
                h3.serve(router).await
            })));
        }

        // Client with dangerous verifier (cert was issued for `localhost` so
        // webpki would reject `alpha`/`beta` even though they share material).
        let client_own = ClientOnlyConfig {
            verifier: ServerCertVerifierChoice::Dangerous,
            ..Default::default()
        };
        let client_quic_config = ClientQuicConfig {
            common: Arc::default(),
            own: Arc::new(client_own),
        };
        let client_quic = QuicEndpoint::new(
            network.clone(),
            Identity::Anonymous,
            resolver.clone(),
            client_quic_config,
            ServerQuicConfig::default(),
        );
        let client = Client::from_quic_client().client(client_quic).build();

        for (sni, expected) in [("alpha", "alpha"), ("beta", "beta")] {
            let authority: Authority = format!("{sni}:{port}").parse().unwrap();
            let uri: http::Uri = format!("https://{authority}/hello").parse().unwrap();
            let (_req, mut resp) = client
                .new_request()
                .with_authority(authority)
                .get(uri)
                .await
                .unwrap_or_else(|e| panic!("request for {sni} failed: {e:?}"));
            assert_eq!(resp.status(), http::StatusCode::OK);
            let body = resp.read_to_string().await.expect("read body");
            assert_eq!(body, expected, "sni {sni} got wrong response");
        }

        drop(serve_handles);
        drop(bindings);
    });
}

// ---------------------------------------------------------------------------
// Introspection accessors (Phase 0)
// ---------------------------------------------------------------------------

#[test]
fn get_iface_returns_bound_interface() {
    run("get_iface_returns_bound_interface", async move {
        let network = test_network();
        let uri = BindUri::from("inet://127.0.0.1:0");
        let bound = network.bind(uri.clone()).await;
        let expected_addr = bound.borrow().bound_addr().expect("bound addr");

        let fetched = network
            .get_iface(&uri)
            .expect("iface must be retrievable via get_iface");
        let fetched_addr = fetched.borrow().bound_addr().expect("bound addr");
        assert_eq!(expected_addr, fetched_addr);

        // Unknown URI yields None.
        let unknown = BindUri::from("inet://127.0.0.1:1");
        assert!(network.get_iface(&unknown).is_none());
    });
}

#[test]
fn registered_sni_names_tracks_live_bindings() {
    run("registered_sni_names_tracks_live_bindings", async move {
        let network = test_network();
        assert!(network.registered_sni_names().is_empty());

        let shared_config = ServerQuicConfig::default();
        let alpha = network
            .bind_server(named_with("alpha"), shared_config.clone())
            .await
            .expect("bind alpha");
        let beta = network
            .bind_server(named_with("beta"), shared_config.clone())
            .await
            .expect("bind beta");

        let mut names = network.registered_sni_names();
        names.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].as_ref(), "alpha");
        assert_eq!(names[1].as_ref(), "beta");

        drop(alpha);
        let remaining = network.registered_sni_names();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].as_ref(), "beta");

        drop(beta);
        assert!(network.registered_sni_names().is_empty());
    });
}
