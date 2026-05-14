mod common;

use std::sync::Arc;

use common::*;
use h3x::{
    endpoint::server::{self, Router},
    error::Code,
    quic,
    varint::VarInt,
};
use tokio_util::task::AbortOnDropHandle;

async fn hello_world_service(_: &mut server::Request, response: &mut server::Response) {
    response
        .set_status(http::StatusCode::OK)
        .set_body(&b"Hello, World!"[..]);
}

#[test]
fn hello_world() {
    run("hello_world", async move {
        let router = Router::new().get("/hello_world", hello_world_service);
        let network = test_network().await;
        let (mut server, host) = test_server_with(network.clone()).await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client_with(network).await);
        let mut response = client
            .get(
                format!("https://{host}/hello_world")
                    .parse()
                    .expect("valid uri"),
            )
            .await
            .expect("failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let response = response
            .read_to_string()
            .await
            .expect("failed to read response body");
        assert_eq!(response, "Hello, World!");
    })
}

async fn streaming_echo_service(request: &mut server::Request, response: &mut server::Response) {
    response.set_status(http::StatusCode::OK);
    response.flush().await.expect("failed to flush response");

    while let Some(chunk) = request
        .read()
        .await
        .transpose()
        .expect("failed to read request body")
    {
        response
            .write(chunk)
            .await
            .expect("failed to write response body");
    }
}

#[test]
fn streaming_echo() {
    run("streaming_echo", async move {
        let router = Router::new().post("/echo", streaming_echo_service);
        let network = test_network().await;
        let (mut server, host) = test_server_with(network.clone()).await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client_with(network).await);
        let request = client.post(format!("https://{host}/echo").parse().expect("valid uri"));
        // flush headers so the server can respond before we write body
        request
            .flush()
            .await
            .expect("failed to send request headers");
        let mut response = request.response().await.expect("failed to get response");
        assert_eq!(response.status(), http::StatusCode::OK);

        request
            .write(TEST_DATA)
            .await
            .expect("failed to write body")
            .close()
            .await
            .expect("failed to close stream");
        let body = response
            .read_to_bytes()
            .await
            .expect("failed to read response body");
        assert_eq!(body, TEST_DATA);
    })
}

#[test]
fn fallback() {
    run("fallback", async move {
        let router = Router::new()
            .get("/hello_world", hello_world_service)
            .post("/hello_world", hello_world_service);
        let network = test_network().await;
        let (mut server, host) = test_server_with(network.clone()).await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client_with(network).await);
        let response = client
            .get(
                format!("https://{host}/non_exist")
                    .parse()
                    .expect("valid uri"),
            )
            .await
            .expect("failed to send request");

        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    })
}

async fn echo_service(request: &mut server::Request, response: &mut server::Response) {
    let body = request
        .read_to_bytes()
        .await
        .expect("failed to read request body");
    response.set_status(http::StatusCode::OK).set_body(body);
}

#[test]
fn auto_close() {
    run("auto_close", async move {
        let router = Router::new().post("/echo", echo_service);
        let network = test_network().await;
        let (mut server, host) = test_server_with(network.clone()).await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client_with(network).await);
        let request = client.post(format!("https://{host}/echo").parse().expect("valid uri"));
        request
            .write(TEST_DATA)
            .await
            .expect("failed to write body")
            .close()
            .await
            .expect("failed to close stream");
        let mut response = request.await.expect("failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .read_to_bytes()
            .await
            .expect("failed to read response body");
        assert_eq!(body, TEST_DATA);
    })
}

#[test]
fn missing_server_name_closes_connection_with_no_error() {
    use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

    use dquic::prelude::{
        IO,
        handy::{SystemResolver, ToCertificate, ToPrivateKey},
    };
    use futures::{FutureExt, StreamExt, stream};
    use h3x::{
        dquic::{
            Identity, ServerName,
            qbase::net::addr::EndpointAddr,
            qresolve::{Resolve, ResolveFuture, Source},
        },
        endpoint::H3Endpoint,
    };

    #[derive(Debug)]
    struct FixedResolver(SocketAddr);

    impl std::fmt::Display for FixedResolver {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "FixedResolver({})", self.0)
        }
    }

    impl Resolve for FixedResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
            let ep = EndpointAddr::direct(self.0);
            let source = Source::System;
            async move { Ok(stream::iter(std::iter::once((source, ep))).boxed()) }.boxed()
        }
    }

    run(
        "missing_server_name_closes_connection_with_no_error",
        async move {
            let network = test_network().await;

            // Create server with identity "server" — client will use "localhost",
            // so the SNI won't match
            let identity = Arc::new(Identity {
                name: ServerName::new("server"),
                certs: Arc::new(SERVER_CERT.to_certificate()),
                key: Arc::new(SERVER_KEY.to_private_key()),
                ocsp: Arc::new(None),
            });
            let quic = h3x::dquic::QuicEndpoint::builder()
                .network(network.clone())
                .identity(identity)
                .resolver(Arc::new(SystemResolver))
                .bind(Arc::new(vec![
                    FromStr::from_str("inet://127.0.0.1:0").expect("valid bind pattern"),
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
            let mut server = H3Endpoint::new(quic);
            let host: http::uri::Authority = format!("localhost:{port}")
                .parse()
                .expect("valid authority");

            let _serve = AbortOnDropHandle::new(tokio::spawn(async move {
                let _ = server.serve(Router::new()).await;
            }));

            // Use FixedResolver to bypass system DNS and directly target the server port
            let client_quic = h3x::dquic::QuicEndpoint::builder()
                .network(network)
                .resolver(Arc::new(FixedResolver(
                    format!("127.0.0.1:{port}")
                        .parse()
                        .expect("valid socket addr"),
                )))
                .build()
                .await;
            let client = Arc::new(H3Endpoint::new(client_quic));
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                client.get(
                    format!("https://{host}/hello_world")
                        .parse()
                        .expect("valid uri"),
                ),
            )
            .await;

            let error = match result {
                // timeout is expected — server silently refuses via SilentRefuse,
                // the QUIC PTO exponential backoff takes ~18s; we cut it short here
                Err(_elapsed) => return,
                Ok(Ok(_response)) => {
                    panic!("expected error from missing server name, got success")
                }
                Ok(Err(e)) => e,
            };

            match error {
                // Connection rejected at QUIC level (SNI mismatch, path validation)
                h3x::endpoint::client::RequestError::Connect { .. } => { /* valid */ }
                h3x::endpoint::client::RequestError::ResponseStream {
                    source:
                        quic::StreamError::Connection {
                            source:
                                quic::ConnectionError::Application {
                                    source: quic::ApplicationError { code, .. },
                                },
                        },
                } => assert_eq!(code, Code::H3_NO_ERROR),
                h3x::endpoint::client::RequestError::ResponseStream {
                    source:
                        quic::StreamError::Connection {
                            source:
                                quic::ConnectionError::Transport {
                                    source: quic::TransportError { kind, .. },
                                },
                        },
                } => {
                    assert_eq!(kind, VarInt::from_u32(0x0c));
                }
                // Stream reset with H3_NO_ERROR: race between GuardedQuicWriter drop
                // (RESET_STREAM) and connection close (CONNECTION_CLOSE). Both are valid.
                h3x::endpoint::client::RequestError::ResponseStream {
                    source: quic::StreamError::Reset { code },
                } => {
                    assert_eq!(code, Code::H3_NO_ERROR.into_inner());
                }
                other => panic!(
                    "expected connection/stream close from missing-server-name, got: {other:?}"
                ),
            }
        },
    )
}
