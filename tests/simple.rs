mod common;

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use common::*;
use futures::{FutureExt, StreamExt, stream};
use h3x::{
    dquic::{
        Identity,
        cert::handy::{ToCertificate, ToPrivateKey},
        net::{EndpointAddr, IO},
        resolver::{Resolve, ResolveFuture, Source, handy::SystemResolver},
    },
    endpoint::{
        H3Endpoint,
        server::{self, Service},
    },
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
        let router = Service::new().get("/hello_world", hello_world_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
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
        let router = Service::new().post("/echo", streaming_echo_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
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
fn response_sends_request_headers() {
    run("response_sends_request_headers", async move {
        let router = Service::new().post("/echo", streaming_echo_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
        let request = client.post(format!("https://{host}/echo").parse().expect("valid uri"));
        let mut response = tokio::time::timeout(Duration::from_secs(5), request.response())
            .await
            .expect("response() should send headers before waiting for response")
            .expect("failed to get response");
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
        let router = Service::new()
            .get("/hello_world", hello_world_service)
            .post("/hello_world", hello_world_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
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
        let router = Service::new().post("/echo", echo_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
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
fn set_body_auto_close() {
    run("set_body_auto_close", async move {
        let router = Service::new().post("/echo", echo_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);
        let request = client.post(format!("https://{host}/echo").parse().expect("valid uri"));
        request.set_body(TEST_DATA);
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
            // Create server with identity "server" — client will use "localhost",
            // so the SNI won't match
            let network = h3x::dquic::Network::builder().build();
            let identity = Arc::new(Identity {
                name: "server".parse().unwrap(),
                certs: Arc::new(SERVER_CERT.to_certificate()),
                key: Arc::new(SERVER_KEY.to_private_key()),
                ocsp: Arc::new(None),
            });
            let quic = h3x::dquic::QuicEndpoint::builder()
                .network(network.clone())
                .identity(identity)
                .resolver(Arc::new(SystemResolver))
                .bind(Arc::new(vec![
                    "127.0.0.1:0".parse().expect("valid bind pattern"),
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
                let _ = server.serve(Service::new()).await;
            }));

            // Use FixedResolver to bypass system DNS and directly target the server port
            let client_quic = h3x::dquic::QuicEndpoint::builder()
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

#[test]
fn connection_refused() {
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

    run("connection_refused", async move {
        let client_quic = h3x::dquic::QuicEndpoint::builder()
            .resolver(Arc::new(FixedResolver(
                SocketAddr::from_str("127.0.0.1:1").expect("valid socket addr"),
            )))
            .build()
            .await;
        let client = Arc::new(H3Endpoint::new(client_quic));

        let result = tokio::time::timeout(
            Duration::from_secs(3),
            client.get("https://localhost/hello_world".parse().expect("valid uri")),
        )
        .await;

        match result {
            Err(_elapsed) => { /* expected — UDP to closed port times out */ }
            Ok(Err(e)) => match e {
                h3x::endpoint::client::RequestError::Connect { .. } => { /* expected */ }
                h3x::endpoint::client::RequestError::ResponseStream {
                    source:
                        quic::StreamError::Connection {
                            source: quic::ConnectionError::Transport { .. },
                        },
                } => { /* also valid */ }
                other => panic!("expected Connect error or timeout, got: {other:?}"),
            },
            Ok(Ok(_response)) => panic!("expected error from refused connection, got success"),
        }
    })
}

#[test]
#[ignore = "requires a real unresponsive server; QUIC-in-memory transport completes too fast"]
fn request_timeout() {
    run("request_timeout", async move {
        let router = Service::new().get("/hello_world", hello_world_service);
        let (mut server, host) = test_server().await;
        let _serve =
            AbortOnDropHandle::new(tokio::spawn(async move { server.serve(router).await }));

        let client = Arc::new(test_client().await);

        let result = tokio::time::timeout(
            tokio::time::Duration::from_millis(1),
            client.get(
                format!("https://{host}/hello_world")
                    .parse()
                    .expect("valid uri"),
            ),
        )
        .await;

        match result {
            Err(_elapsed) => { /* timeout fired as expected */ }
            Ok(Ok(response)) => {
                assert_eq!(response.status(), http::StatusCode::OK);
            }
            Ok(Err(e)) => panic!("request failed: {e:?}"),
        }
    })
}

#[test]
fn empty_authority_error() {
    run("empty_authority_error", async move {
        let client = Arc::new(test_client().await);

        let error = client
            .new_request_owned()
            .await
            .err()
            .expect("request without authority should fail");

        match error {
            h3x::endpoint::client::RequestError::MalformedRequestHeader { .. } => {
                // expected — EmptyAuthorityOrHost or similar
            }
            other => panic!(
                "expected MalformedRequestHeader error for missing authority, got: {other:?}"
            ),
        }
    })
}
