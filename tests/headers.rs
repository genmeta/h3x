mod support;
use std::time::Duration;

use bytes::Bytes;
use h3x::{
    H3ReadStream, H3WriteStream, ReadRequest, ReadResponse, ReadStream, WriteBody, WriteRequest,
    WriteResponse, WriteStream, client, server,
};
use http::{HeaderValue, StatusCode, header};
use tokio::io::duplex;

const AUTHORIZATION: &str = "Bearer integration-test";
const COOKIE: &str = "session=request-session";
const COOKIES: [&str; 2] = [
    "session=first; Path=/; Expires=Wed, 21 Oct 2037 07:28:00 GMT",
    "theme=dark; Path=/; HttpOnly",
];

fn request_headers<B>(request: client::Request<B>) -> client::Request<B> {
    request
        .header(
            header::AUTHORIZATION,
            HeaderValue::from_static(AUTHORIZATION),
        )
        .header(header::COOKIE, HeaderValue::from_static(COOKIE))
}

fn assert_request_headers(request: &impl ReadRequest, buffered: bool) {
    let mut headers = request.headers();
    assert_eq!(headers[header::AUTHORIZATION], AUTHORIZATION);
    assert_eq!(headers[header::COOKIE], COOKIE);
    assert_eq!(headers.contains_key(header::CONTENT_LENGTH), buffered);
    assert!(headers.get("x-missing").is_none());
    assert_eq!(headers.len(), if buffered { 3 } else { 2 });

    headers.clear();
    assert_eq!(request.headers()[header::AUTHORIZATION], AUTHORIZATION);
}

fn assert_response_headers(response: &impl ReadResponse, buffered: bool) {
    let mut headers = response.headers();
    assert_eq!(headers[header::CONTENT_TYPE], "text/plain");
    assert_eq!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>(),
        COOKIES
    );
    assert!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .all(HeaderValue::is_sensitive)
    );
    assert_eq!(headers.contains_key(header::CONTENT_LENGTH), buffered);
    assert!(headers.get("x-missing").is_none());
    assert_eq!(headers.len(), if buffered { 4 } else { 3 });

    headers.clear();
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
}

#[tokio::test]
async fn ordinary_headers_round_trip() {
    let connection = support::connection();
    tokio::time::timeout(Duration::from_secs(5), async {
        for buffered in [true, false] {
            let (client_send, server_recv) = duplex(64);
            let (server_send, client_recv) = duplex(64);
            let (received, served) = tokio::join!(
                async {
                    let recv = H3ReadStream::new(0, client_recv);
                    let send = H3WriteStream::new(0, client_send);
                    let qpack = connection.clone();
                    if buffered {
                        let request = request_headers(
                            client::Request::post("https://example.com/headers").unwrap(),
                        )
                        .header(header::CONTENT_LENGTH, HeaderValue::from_static("5"))
                        .body(Bytes::from_static(b"hello"));
                        {
                            let (sending, receiving) =
                                client::write_bytes_request(request, send, recv, qpack)?;
                            let (sent, received) = tokio::join!(sending, receiving);
                            sent?;
                            received
                        }
                    } else {
                        let mut request = request_headers(
                            client::Request::streaming_post("https://example.com/headers").unwrap(),
                        );
                        request.write(b"hello").await?;
                        request.finish().await?;
                        {
                            let (sending, receiving) =
                                client::write_streaming_request(request, send, recv, qpack)?;
                            let (sent, received) = tokio::join!(sending, receiving);
                            sent?;
                            received
                        }
                    }
                },
                async {
                    let request =
                        server::read_request(H3ReadStream::new(0, server_recv), connection.clone())
                            .await?;
                    assert_request_headers(&request, buffered);
                    let method = request.method();
                    let server::Request::Streaming(mut request) = request else {
                        panic!("incoming requests are always streaming")
                    };
                    assert_request_headers(&request, buffered);
                    let mut body = [0; 6];
                    assert_eq!(request.read_all(&mut body).await?, 5);
                    assert_eq!(&body[..5], b"hello");

                    let mut first_cookie = HeaderValue::from_static(COOKIES[0]);
                    first_cookie.set_sensitive(true);
                    let mut second_cookie = HeaderValue::from_static(COOKIES[1]);
                    second_cookie.set_sensitive(true);
                    let mut response = server::Response::default();
                    response
                        .set_status(StatusCode::OK)
                        .set_header(header::CONTENT_TYPE, HeaderValue::from_static("text/html"))
                        .set_header(header::SET_COOKIE, HeaderValue::from_static("old=1"))
                        .append_header(header::SET_COOKIE, HeaderValue::from_static("old=2"))
                        .set_header(header::SET_COOKIE, first_cookie);
                    let send = H3WriteStream::new(0, server_send);
                    let qpack = connection.clone();
                    if buffered {
                        response
                            .set_header(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("text/plain"),
                            )
                            .append_header(header::SET_COOKIE, second_cookie)
                            .set_header(header::CONTENT_LENGTH, HeaderValue::from_static("5"))
                            .set_body(Bytes::from_static(b"world"));
                        server::write_bytes_response(response, send, qpack, &method).await
                    } else {
                        let mut response = response.streaming(5);
                        response
                            .set_header(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("text/plain"),
                            )
                            .append_header(header::SET_COOKIE, second_cookie);
                        response.write(b"world").await?;
                        response.finish().await?;
                        server::write_streaming_response(response, send, qpack, &method).await
                    }
                }
            );

            served.unwrap();
            let response = received.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_response_headers(&response, buffered);
            let client::Response::Streaming(mut response) = response else {
                panic!("incoming responses are always streaming")
            };
            assert_response_headers(&response, buffered);
            let mut body = [0; 6];
            assert_eq!(response.read_all(&mut body).await.unwrap(), 5);
            assert_eq!(&body[..5], b"world");
        }
    })
    .await
    .expect("header round trips must complete in both body modes");
}
