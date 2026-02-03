mod common;
use std::pin::pin;

use axum::{
    Router,
    body::Body,
    routing::{any, get},
};
use bytes::Bytes;
use common::*;
use h3x::{
    hyper::upgrade,
    message::stream::ReadStream,
    qpack::field::Protocol,
    server::{self, TowerService},
};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    task::AbortOnDropHandle,
};

#[test]
fn axum_hello_world() {
    run("axum_hello_world", async move {
        let router = Router::new()
            .route("/hello_world", get(|| async { "Hello, World!" }))
            .into_service();
        let server = test_server(TowerService(router)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let connection = client
            .connect(host.clone())
            .await
            .expect("failed to connect to server");
        let (read_stream, mut write_stream) = connection
            .open_request_stream()
            .await
            .expect("failed to open request stream");

        // TODO: hign level API
        write_stream
            .send_hyper_request(
                Request::builder()
                    .method("GET")
                    .uri(format!("https://{host}/hello_world",))
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to send request");

        let response = read_stream
            .into_hyper_response()
            .await
            .expect("failed to take response");

        let body = response
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();

        assert_eq!(&body[..], b"Hello, World!");
    })
}

pub const INTERIM_RESPONSE_COUNT: usize = 3;

async fn interim_response_service(_request: &mut server::Request, response: &mut server::Response) {
    for _ in 0..INTERIM_RESPONSE_COUNT {
        response
            .set_status(http::StatusCode::CONTINUE)
            .flush()
            .await
            .expect("failed to send interim response");
    }
    response
        .set_status(http::StatusCode::OK)
        .set_body(b"37" as &[u8])
        .close()
        .await
        .expect("failed to send final response");
}

#[test]
fn interim_response() {
    run("interim_response", async move {
        let server =
            test_server(server::Router::new().get("/ultimate_answer", interim_response_service))
                .await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let connection = client
            .connect(host.clone())
            .await
            .expect("failed to connect to server");
        let (read_stream, mut write_stream) = connection
            .open_request_stream()
            .await
            .expect("failed to open request stream");

        write_stream
            .send_hyper_request(
                Request::get(format!("https://{host}/ultimate_answer"))
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to send request");

        let mut response = read_stream
            .into_hyper_response()
            .await
            .expect("failed to take response")
            .map(UnsyncBoxBody::new);

        while response.status().is_informational()
            && let Some(remain) = ReadStream::extract_from(&mut response).await
        {
            response = remain
                .into_hyper_response()
                .await
                .expect("failed to take response")
                .map(UnsyncBoxBody::new);
        }

        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .collect()
            .await
            .expect("failed to read body")
            .to_bytes();

        assert_eq!(&body[..], b"37");
    })
}

const CONNECTED_REQUEST: &str = "GET / HTTP/1.1\r\nHost: example.org\r\nConnection: close\r\n\r\n";
const CONNECTED_RESPONSE: &str = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";

#[axum::debug_handler]
async fn mock_connect_service(request: axum::extract::Request) -> Result<(), StatusCode> {
    let (Some(host), Some(port)) = (request.uri().host(), request.uri().port_u16()) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let host = host.to_string();

    if host != "example.org" || port != 80 {
        return Err(StatusCode::FORBIDDEN);
    }

    tokio::spawn(async move {
        let (read_stream, write_stream) = upgrade::on(request)
            .await
            .expect("failed to establish tunnel");
        tracing::info!("tunnel established to {host}:{port}");
        let read_stream = pin!(read_stream.into_bytes_stream());
        let mut read_stream = StreamReader::new(read_stream);
        let write_stream = pin!(write_stream.into_bytes_sink::<Bytes>());
        let mut write_stream = SinkWriter::new(CopyToBytes::new(write_stream));

        let mut buf = Vec::with_capacity(CONNECTED_REQUEST.len());
        read_stream
            .read_to_end(&mut buf)
            .await
            .expect("failed to read from tunnel");
        tracing::info!(request = %String::from_utf8_lossy(&buf), "Tunnel received request");

        assert_eq!(&buf[..], CONNECTED_REQUEST.as_bytes());
        write_stream
            .write_all(CONNECTED_RESPONSE.as_bytes())
            .await
            .expect("failed to write to tunnel");
        write_stream
            .shutdown()
            .await
            .expect("failed to close write stream");
    });

    Ok(())
}

#[test]
fn axum_connect() {
    run("axum_connect", async move {
        let router = Router::new()
            .route("/", any(mock_connect_service))
            .into_service();
        let server = test_server(TowerService(router)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let connection = client
            .connect(host.clone())
            .await
            .expect("failed to connect to server");
        let (mut read_stream, mut write_stream) = connection
            .open_request_stream()
            .await
            .expect("failed to open request stream");

        write_stream
            .send_hyper_request(
                // FIXME: correct way to build CONNECT request?
                Request::connect("https://example.org:80")
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to send request");

        let response = read_stream
            .read_hyper_response_parts()
            .await
            .expect("failed to take response");
        assert_eq!(response.status, StatusCode::OK);

        let read_stream = pin!(read_stream.into_bytes_stream());
        let mut read_stream = StreamReader::new(read_stream);
        let write_stream = pin!(write_stream.into_bytes_sink::<Bytes>());
        let mut write_stream = SinkWriter::new(CopyToBytes::new(write_stream));

        write_stream
            .write_all(CONNECTED_REQUEST.as_bytes())
            .await
            .expect("failed to write to tunnel");
        write_stream
            .shutdown()
            .await
            .expect("failed to close write stream");
        tracing::info!("Sent connected request");

        let mut buf = Vec::new();
        read_stream
            .read_to_end(&mut buf)
            .await
            .expect("failed to read from tunnel");

        assert_eq!(&buf[..], CONNECTED_RESPONSE.as_bytes());
    });
}

async fn extend_connect_service(request: axum::extract::Request) -> Result<(), StatusCode> {
    let protocol = request
        .extensions()
        .get::<Protocol>()
        .map(|p| p.as_str())
        .unwrap_or("");
    if protocol != "h3x-test" {
        return Err(StatusCode::BAD_REQUEST);
    }
    mock_connect_service(request).await
}

#[test]
fn axum_extend_connect() {
    run("axum_extend_connect", async move {
        let router = Router::new()
            .route("/connect", any(extend_connect_service))
            .into_service();
        let server = test_server(TowerService(router)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();

        let connection = client
            .connect(host.clone())
            .await
            .expect("failed to connect to server");
        let (mut read_stream, mut write_stream) = connection
            .open_request_stream()
            .await
            .expect("failed to open request stream");

        write_stream
            .send_hyper_request(
                Request::connect("https://example.org:80/connect")
                    .extension(hyper::ext::Protocol::from_static("h3x-test")) // use extension API to set :protocol header
                    .body(Body::empty())
                    .expect("failed to build request"),
            )
            .await
            .expect("failed to send request");

        let response = read_stream
            .read_hyper_response_parts()
            .await
            .expect("failed to take response");
        assert_eq!(response.status, StatusCode::OK);

        let read_stream = pin!(read_stream.into_bytes_stream());
        let mut read_stream = StreamReader::new(read_stream);
        let write_stream = pin!(write_stream.into_bytes_sink::<Bytes>());
        let mut write_stream = SinkWriter::new(CopyToBytes::new(write_stream));

        write_stream
            .write_all(CONNECTED_REQUEST.as_bytes())
            .await
            .expect("failed to write to tunnel");
        write_stream
            .shutdown()
            .await
            .expect("failed to close write stream");
        tracing::info!("Sent connected request");

        let mut buf = Vec::new();
        read_stream
            .read_to_end(&mut buf)
            .await
            .expect("failed to read from tunnel");

        assert_eq!(&buf[..], CONNECTED_RESPONSE.as_bytes());
    });
}
