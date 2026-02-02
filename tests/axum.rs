mod common;
use axum::{Router, body::Body, routing::get};
use common::*;
use h3x::{
    message::stream::http_body::RemainReadStream,
    server::{self, TowerService},
};
use http::Request;
use http_body_util::BodyExt;
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
            .to_hyper_response()
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
            .to_hyper_response()
            .await
            .expect("failed to take response");

        while response.status().is_informational()
            && let Some(remain) = response.extensions().get::<RemainReadStream>().cloned()
        {
            let read_stream = remain.await.expect("failed to get remain stream");
            response = read_stream
                .to_hyper_response()
                .await
                .expect("failed to take response");
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
