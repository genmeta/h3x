mod common;
use common::*;
use h3x::server::{self, Router};
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
            .expect("Failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let response = response
            .read_to_string()
            .await
            .expect("Failed to read response body");
        assert_eq!(response, "Hello, World!");
    })
}

async fn echo_service(request: &mut server::Request, response: &mut server::Response) {
    response.set_status(http::StatusCode::OK);
    while let Some(chunk) = request
        .read()
        .await
        .transpose()
        .expect("Failed to read request body")
    {
        response
            .write(chunk)
            .await
            .expect("Failed to write response body");
    }
}

#[test]
fn echo() {
    run("echo", async move {
        let server = test_server(Router::new().post("/echo", echo_service)).await;
        let host = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let (_, mut response) = client
            .new_request()
            .with_body(TEST_DATA)
            .post(format!("https://{host}/echo").parse().unwrap())
            .await
            .expect("Failed to send request");

        assert_eq!(response.status(), http::StatusCode::OK);
        let response = response
            .read_to_bytes()
            .await
            .expect("Failed to read response body");
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
            .expect("Failed to send request");

        assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    })
}
