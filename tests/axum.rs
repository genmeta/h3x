mod common;
use axum::{Router, body::Body, routing::get};
use common::*;
use h3x::server::TowerService;
use http::Request;
use tokio_util::task::AbortOnDropHandle;

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
        let (mut read_stream, mut write_stream) = connection
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

        let response_parts = read_stream
            .read_hyper_response_parts()
            .await
            .expect("Failed to read response parts");
        assert_eq!(response_parts.status, 200);

        use http_body_util::BodyExt;

        let body = read_stream
            .as_hyper_body()
            .collect()
            .await
            .expect("failed to read body");

        let response = http::Response::from_parts(response_parts, body.to_bytes());

        assert_eq!(&response.body()[..], b"Hello, World!");
    })
}
