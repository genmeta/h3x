mod common;
use std::sync::Arc;

use common::*;
use gm_quic::prelude::handy::{ToCertificate, ToPrivateKey};
use h3x::{
    error::Code,
    gm_quic::H3Servers,
    quic,
    server::{self, Router},
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
        let server = test_server(Router::new().get("/hello_world", hello_world_service)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let (_, mut response) = client
            .new_request()
            .get(format!("https://{host}/hello_world").parse().unwrap())
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
        let server = test_server(Router::new().post("/echo", streaming_echo_service)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let (mut request, mut response) = client
            .new_request()
            .post(format!("https://{host}/echo").parse().unwrap())
            .await
            .expect("failed to send request");
        assert_eq!(response.status(), http::StatusCode::OK);

        request
            .write(TEST_DATA)
            .await
            .expect("failed to write body")
            .close()
            .await
            .expect("failed to close stream");
        let response = response
            .read_to_bytes()
            .await
            .expect("failed to read response body");
        assert_eq!(response, TEST_DATA);
    })
}

#[test]
fn fallback() {
    run("fallback", async move {
        let server = test_server(
            Router::new()
                .get("/hello_world", hello_world_service)
                .post("/hello_world", hello_world_service),
        )
        .await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let (_, response) = client
            .new_request()
            .get(format!("https://{host}/non_exist").parse().unwrap())
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
        let server = test_server(Router::new().post("/echo", echo_service)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let (_, mut response) = client
            .new_request()
            .with_body(TEST_DATA)
            .post(format!("https://{host}/echo").parse().unwrap())
            .await
            .expect("failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let response = response
            .read_to_bytes()
            .await
            .expect("failed to read response body");
        assert_eq!(response, TEST_DATA);
    })
}

#[test]
fn missing_server_name_closes_connection_with_no_error() {
    run(
        "missing_server_name_closes_connection_with_no_error",
        async move {
            let servers: H3Servers<Router> = H3Servers::builder()
                .without_client_cert_verifier()
                .expect("failed to initialize server tls")
                .with_router(Arc::new(
                    gm_quic::qinterface::component::route::QuicRouter::new(),
                ))
                .listen()
                .expect("failed to listen");
            servers
                .quic_listener()
                .add_server(
                    "localhost",
                    SERVER_CERT.to_certificate(),
                    SERVER_KEY.to_private_key(),
                    [
                        gm_quic::prelude::BindUri::from("inet://127.0.0.1:0").alloc_port(),
                        gm_quic::prelude::BindUri::from("inet://[::1]:0").alloc_port(),
                    ],
                    None,
                )
                .await
                .expect("failed to add server");

            let host = get_server_authority(&servers);
            let _serve = AbortOnDropHandle::new(tokio::spawn(async move { servers.run().await }));

            let client = test_client();
            let error = client
                .new_request()
                .get(
                    format!("https://{host}/hello_world")
                        .parse()
                        .expect("valid uri"),
                )
                .await
                .err()
                .expect("request should fail with no matching server name");

            match error {
                h3x::client::RequestError::ResponseStream {
                    source:
                        quic::StreamError::Connection {
                            source:
                                quic::ConnectionError::Application {
                                    source: quic::ApplicationError { code, .. },
                                },
                        },
                } => assert_eq!(code, Code::H3_NO_ERROR),
                h3x::client::RequestError::ResponseStream {
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
                other => panic!(
                    "expected response stream close from missing-server-name connection close, got: {other:?}"
                ),
            }
        },
    )
}
