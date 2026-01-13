use std::{future::Future, marker::PhantomData, pin::Pin};

use bytes::Bytes;
use futures::stream;
use http_body_util::{BodyExt, StreamBody, combinators::UnsyncBoxBody};
use snafu::Snafu;
use tower::ServiceExt;

use crate::server::{Request, Response, Service};

pub type RequestBody = UnsyncBoxBody<Bytes, std::io::Error>;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum TowerError {
    /// Failed to construct a valid URI from request parts.
    #[snafu(display("Invalid URI: {source}"))]
    InvalidUri { source: http::uri::InvalidUriParts },

    /// Failed to build the HTTP request.
    #[snafu(display("Failed to build request: {source}"))]
    RequestBuild { source: http::Error },

    /// Failed to initialize streaming mode for response.
    #[snafu(display("Failed to init streaming: {message}"))]
    StreamingInit { message: String },

    /// Failed to write data to response body.
    #[snafu(display("Failed to write response: {message}"))]
    ResponseWrite { message: String },

    /// Failed to read frame from response body.
    #[snafu(display("Failed to read frame: {message}"))]
    FrameRead { message: String },

    /// Failed to flush response.
    #[snafu(display("Failed to flush response: {message}"))]
    Flush { message: String },

    /// The underlying Tower service returned an error.
    #[snafu(display("Service error: {source}"))]
    Service {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub struct TowerService<S, B> {
    inner: S,
    _marker: PhantomData<fn() -> B>,
}

impl<S: Clone, B> Clone for TowerService<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<S, B> TowerService<S, B> {
    pub fn new(router: S) -> Self {
        Self {
            inner: router,
            _marker: PhantomData,
        }
    }
}

impl<S, B> TowerService<S, B>
where
    S: tower::Service<http::Request<RequestBody>, Response = http::Response<B>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    S::Future: Send + 'static,
    B: http_body::Body<Data = Bytes> + Send + 'static + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    fn convert_request(
        &self,
        h3x_request: Request,
    ) -> Result<http::Request<RequestBody>, TowerError> {
        let method = h3x_request.method();
        let headers = h3x_request.headers().clone();

        let uri = {
            let mut parts = http::uri::Parts::default();
            parts.scheme = h3x_request.scheme().or(Some(http::uri::Scheme::HTTPS));
            parts.authority = h3x_request.authority();
            parts.path_and_query = h3x_request.path();
            http::Uri::from_parts(parts).map_err(|source| TowerError::InvalidUri { source })?
        };

        let body_stream = stream::unfold((h3x_request, false), |(mut request, done)| async move {
            if done {
                return None;
            }

            if let Some(result) = request.read().await {
                match result {
                    Ok(chunk) => Some((Ok(http_body::Frame::data(chunk)), (request, false))),
                    Err(e) => Some((Err(std::io::Error::other(e.to_string())), (request, true))),
                }
            } else {
                match request.trailers().await {
                    Ok(trailers) if !trailers.is_empty() => Some((
                        Ok(http_body::Frame::trailers(trailers.clone())),
                        (request, true),
                    )),
                    Ok(_) => None,
                    Err(e) => Some((Err(std::io::Error::other(e.to_string())), (request, true))),
                }
            }
        });

        let body = BodyExt::boxed_unsync(StreamBody::new(body_stream));

        http::Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .map(|mut req| {
                *req.headers_mut() = headers;
                req
            })
            .map_err(|source| TowerError::RequestBuild { source })
    }

    async fn execute(
        &self,
        request: http::Request<RequestBody>,
    ) -> Result<http::Response<B>, TowerError> {
        self.inner
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| TowerError::Service { source: e.into() })
    }

    async fn write_response(
        &self,
        service_response: http::Response<B>,
        h3x_response: &mut Response,
    ) -> Result<(), TowerError> {
        let (parts, mut body) = service_response.into_parts();

        // Set status and headers
        h3x_response.set_status(parts.status);
        for (name, value) in &parts.headers {
            h3x_response.set_header(name.clone(), value.clone());
        }

        // Must init streaming mode before sending headers,
        // otherwise it defaults to chunked mode which cannot be changed.
        h3x_response
            .init_streaming()
            .await
            .map_err(|e| TowerError::StreamingInit {
                message: e.to_string(),
            })?;

        // Stream body frames
        while let Some(result) = body.frame().await {
            let frame = result.map_err(|e| {
                let boxed: Box<dyn std::error::Error + Send + Sync> = e.into();
                TowerError::FrameRead {
                    message: boxed.to_string(),
                }
            })?;

            if let Some(data) = frame.data_ref()
                && !data.is_empty()
            {
                h3x_response
                    .write(data.clone())
                    .await
                    .map_err(|e| TowerError::ResponseWrite {
                        message: e.to_string(),
                    })?;
            }

            if let Some(trailers) = frame.trailers_ref() {
                for (name, value) in trailers {
                    h3x_response.set_trailer(name.clone(), value.clone());
                }
            }
        }

        h3x_response.flush().await.map_err(|e| TowerError::Flush {
            message: e.to_string(),
        })?;

        Ok(())
    }
}

impl<S, B> Service for TowerService<S, B>
where
    S: tower::Service<http::Request<RequestBody>, Response = http::Response<B>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    S::Future: Send + 'static,
    B: http_body::Body<Data = Bytes> + Send + 'static + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
{
    type Future<'s> = Pin<Box<dyn Future<Output = ()> + Send + 's>>;

    fn serve<'s>(&'s mut self, request: Request, response: &'s mut Response) -> Self::Future<'s> {
        Box::pin(async move {
            // Convert h3x request to http::Request
            let http_request = match self.convert_request(request) {
                Ok(req) => req,
                Err(error) => {
                    tracing::error!(?error, "Request conversion failed");
                    response.set_status(http::StatusCode::INTERNAL_SERVER_ERROR);
                    let _ = response.close().await;
                    return;
                }
            };

            // Execute the Tower service
            match self.execute(http_request).await {
                Ok(http_response) => {
                    if let Err(error) = self.write_response(http_response, response).await {
                        tracing::error!(?error, "Response write failed");
                        // Response may be partially written; just close it
                    }
                }
                Err(error) => {
                    tracing::error!(?error, "Service execution failed");
                    response.set_status(http::StatusCode::INTERNAL_SERVER_ERROR);
                }
            }

            if let Err(error) = response.close().await {
                tracing::error!(?error, "Response close failed");
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    // ==================== Test Utilities ====================

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    mod test_utils {
        pub const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
        pub const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        pub const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        pub fn init_tracing() {
            let _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
        }
    }

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    async fn setup_test_env(
        router: axum::Router,
    ) -> Result<
        (
            crate::server::Servers<std::sync::Arc<gm_quic::prelude::QuicListeners>>,
            std::net::SocketAddr,
            crate::client::Client<gm_quic::prelude::QuicClient>,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use std::net::SocketAddr;

        use gm_quic::{
            prelude::{
                BindUri,
                handy::{ToCertificate, ToPrivateKey},
            },
            qtraversal::nat::StunIO,
        };

        let mut servers = crate::server::Servers::builder()
            .without_client_cert_verifier()?
            .build();

        servers
            .add_server(
                "localhost",
                test_utils::SERVER_CERT.to_certificate(),
                test_utils::SERVER_KEY.to_private_key(),
                None,
                [BindUri::from("inet://[::1]:0").alloc_port()],
                TowerService::<_, axum::body::Body>::new(router),
            )
            .await?;

        let listen_addr: SocketAddr = servers
            .quic_listener()
            .get_server("localhost")
            .unwrap()
            .bind_interfaces()
            .iter()
            .next()
            .unwrap()
            .1
            .borrow()
            .unwrap()
            .local_addr()
            .unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(test_utils::CA_CERT.to_certificate());
        let client = crate::client::Client::builder()
            .with_root_certificates(roots)
            .without_identity()?
            .build();

        Ok((servers, listen_addr, client))
    }

    // ==================== Integration Tests ====================

    /// Simple integration test with just GET requests (no body reading)
    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    #[tokio::test]
    #[serial]
    async fn axum_simple_integration_test() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        use axum::{Router, http::StatusCode, response::Json, routing::get};
        use serde::{Deserialize, Serialize};
        use test_utils::init_tracing;
        use tracing::Instrument;

        #[derive(Serialize, Deserialize)]
        struct HealthResponse {
            status: String,
            message: String,
        }

        async fn health_handler() -> Json<HealthResponse> {
            Json(HealthResponse {
                status: "ok".to_string(),
                message: "H3X Axum integration working!".to_string(),
            })
        }

        async fn ping_handler() -> &'static str {
            "pong"
        }

        init_tracing();

        let axum_router = Router::new()
            .route("/health", get(health_handler))
            .route("/ping", get(ping_handler));

        let (servers, listen_addr, client) = setup_test_env(axum_router).await?;

        tracing::info!(target: "test", "Simple Axum server listening on {listen_addr}");

        let server = async {
            servers.run().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .instrument(tracing::info_span!("simple_axum_server"));

        let client_tests = async {
            let port = listen_addr.port();
            let base_url = format!("https://localhost:{port}");

            tracing::info!("Testing health endpoint");
            let (.., mut resp) = client
                .new_request()
                .get(format!("{base_url}/health").parse()?)
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.read_to_string().await?;
            let health_resp: HealthResponse = serde_json::from_str(&body)?;
            assert_eq!(health_resp.status, "ok");
            assert_eq!(health_resp.message, "H3X Axum integration working!");
            tracing::info!("✓ Health check passed");

            tracing::info!("Testing ping endpoint");
            let (.., mut resp) = client
                .new_request()
                .get(format!("{base_url}/ping").parse()?)
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.read_to_string().await?;
            assert_eq!(body, "pong");
            tracing::info!("✓ Ping test passed");

            tracing::info!("Testing 404 handling");
            let (.., mut resp) = client
                .new_request()
                .get(format!("{base_url}/nonexistent").parse()?)
                .await?;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            tracing::info!("✓ 404 handling test passed");

            tracing::info!("All simple axum integration tests passed! 🎉");
            servers.shutdown();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::try_join!(client_tests, server)?;
        Ok(())
    }

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    #[tokio::test]
    #[serial]
    async fn test_streaming_body_integration()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use axum::{Router, routing::post};
        use bytes::Bytes;
        use test_utils::init_tracing;
        use tracing::Instrument;

        async fn streaming_echo_handler(body: axum::body::Body) -> axum::body::Body {
            body
        }

        init_tracing();

        let axum_router = Router::new().route("/echo", post(streaming_echo_handler));

        let (servers, listen_addr, client) = setup_test_env(axum_router).await?;

        tracing::info!(target: "test", "Streaming server listening on {listen_addr}");

        let server = async {
            servers.run().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .instrument(tracing::info_span!("streaming_server"));

        let client_tests = async {
            let port = listen_addr.port();
            let base_url = format!("https://localhost:{port}");

            let chunk1 = Bytes::from("Hello, ");
            let chunk2 = Bytes::from("streaming ");
            let chunk3 = Bytes::from("world!");
            let test_chunks = vec![chunk1.clone(), chunk2.clone(), chunk3.clone()];
            let expected_data = test_chunks.iter().flatten().cloned().collect::<Vec<u8>>();

            tracing::info!("Testing streaming echo endpoint");
            // Send POST request with streaming body
            let (mut request, mut response) = client
                .new_request()
                .post(format!("{base_url}/echo").parse()?)
                .await?;

            tracing::info!("Sending streaming request body");
            for chunk in &test_chunks {
                tracing::debug!("Writing chunk of size {}", chunk.len());
                request.write(chunk.clone()).await?;
            }
            tracing::debug!("All chunks written to request body");
            request.flush().await?;
            tracing::debug!("Request body flushed");
            request.close().await?;
            tracing::debug!("Request body closed");

            let mut response_data = Vec::new();
            while let Some(chunk_result) = response.read().await {
                let chunk = chunk_result?;
                response_data.extend_from_slice(&chunk);
            }

            assert_eq!(
                response_data, expected_data,
                "Response data should match sent data"
            );

            tracing::info!("✓ Streaming body integration test passed");
            servers.shutdown();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::try_join!(client_tests, server)?;
        Ok(())
    }

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    #[tokio::test]
    #[serial]
    async fn test_body_size_limit() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use axum::{
            Router,
            body::Body,
            extract::Request,
            http::StatusCode as AxumStatusCode,
            middleware::{self, Next},
            response::{IntoResponse, Response as AxumResponse},
            routing::post,
        };
        use bytes::Bytes;
        use http::StatusCode;
        use test_utils::init_tracing;
        use tracing::Instrument;

        const BODY_LIMIT: usize = 16;

        async fn check_content_length(request: Request, next: Next) -> AxumResponse {
            if let Some(content_length) = request.headers().get(http::header::CONTENT_LENGTH)
                && let Ok(len_str) = content_length.to_str()
                && let Ok(len) = len_str.parse::<usize>()
                && len > BODY_LIMIT
            {
                return (AxumStatusCode::PAYLOAD_TOO_LARGE, "Payload Too Large").into_response();
            }
            next.run(request).await
        }

        async fn upload_handler(body: Body) -> Body {
            body
        }

        init_tracing();

        let axum_router = Router::new()
            .route("/upload", post(upload_handler))
            .layer(middleware::from_fn(check_content_length));

        let (servers, listen_addr, client) = setup_test_env(axum_router).await?;

        tracing::info!(target: "test", "Body limit server listening on {listen_addr}");

        // Start server
        let server = async {
            servers.run().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .instrument(tracing::info_span!("body_limit_server"));

        let client_tests = async {
            let port = listen_addr.port();
            let base_url = format!("https://localhost:{port}");

            tracing::info!("Testing small body (within limit)");
            let small_body = Bytes::from("Hello"); // 5 bytes < 16 bytes limit
            let (mut request, mut response) = client
                .new_request()
                .post(format!("{base_url}/upload").parse()?)
                .await?;
            request.write(small_body.clone()).await?;
            request.flush().await?;
            request.close().await?;

            assert_eq!(response.status(), StatusCode::OK);
            let mut response_data = Vec::new();
            while let Some(chunk) = response.read().await {
                response_data.extend_from_slice(&chunk?);
            }
            assert_eq!(
                response_data,
                small_body.to_vec(),
                "Response should echo the request body"
            );
            tracing::info!("✓ Small body test passed");

            tracing::info!("Testing large body (exceeds limit)");
            let large_body = Bytes::from("This is a very long body that exceeds the limit"); // 48 bytes > 16 bytes limit
            let (mut request, mut response) = client
                .new_request()
                .with_uri(format!("{base_url}/upload").parse()?)
                .with_method(http::Method::POST)
                .with_header(
                    http::header::CONTENT_LENGTH,
                    http::HeaderValue::from_str(&large_body.len().to_string())?,
                )
                .execute()
                .await?;
            request.close().await?;

            assert_eq!(
                response.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "Should return 413 Payload Too Large for oversized body"
            );
            tracing::info!(" Large body rejection test passed");

            servers.shutdown();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::try_join!(client_tests, server)?;
        Ok(())
    }

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    #[tokio::test]
    #[serial]
    async fn test_state_injection() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        use axum::{Router, extract::State, routing::get};
        use http::StatusCode;
        use test_utils::init_tracing;
        use tracing::Instrument;

        #[derive(Clone)]
        struct AppState {
            counter: Arc<AtomicUsize>,
        }

        async fn state_handler(State(state): State<AppState>) -> String {
            let count = state.counter.fetch_add(1, Ordering::SeqCst);
            format!("Count: {}", count)
        }

        init_tracing();

        let state = AppState {
            counter: Arc::new(AtomicUsize::new(0)),
        };

        let axum_router = Router::new()
            .route("/count", get(state_handler))
            .with_state(state);

        let (servers, listen_addr, client) = setup_test_env(axum_router).await?;

        tracing::info!(target: "test", "State injection server listening on {listen_addr}");

        let server = async {
            servers.run().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .instrument(tracing::info_span!("state_server"));

        let client_tests = async {
            let port = listen_addr.port();
            let base_url = format!("https://localhost:{port}");

            // First request, counter should be 0
            let (.., mut resp) = client
                .new_request()
                .get(format!("{base_url}/count").parse()?)
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.read_to_string().await?;
            assert_eq!(body, "Count: 0");

            // Second request, counter should be 1
            let (.., mut resp) = client
                .new_request()
                .get(format!("{base_url}/count").parse()?)
                .await?;
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.read_to_string().await?;
            assert_eq!(body, "Count: 1");

            tracing::info!("✓ State injection test passed");
            servers.shutdown();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::try_join!(client_tests, server)?;
        Ok(())
    }

    #[cfg(all(feature = "gm-quic", feature = "tower"))]
    #[tokio::test]
    #[serial]
    async fn test_middleware_flow() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use axum::{
            Router,
            extract::Request,
            http::{HeaderValue, StatusCode},
            middleware::{self, Next},
            response::Response as AxumResponse,
            routing::get,
        };
        use test_utils::init_tracing;
        use tracing::Instrument;

        // Middleware 1: Authentication simulation
        async fn auth_middleware(req: Request, next: Next) -> Result<AxumResponse, StatusCode> {
            if req.headers().contains_key("x-require-auth") {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::UNAUTHORIZED)
            }
        }

        // Middleware 2: Add response header
        async fn header_middleware(req: Request, next: Next) -> AxumResponse {
            let mut response = next.run(req).await;
            response
                .headers_mut()
                .insert("x-middleware-processed", HeaderValue::from_static("true"));
            response
        }

        async fn handler() -> &'static str {
            "Middleware works!"
        }

        init_tracing();

        let axum_router = Router::new()
            .route("/", get(handler))
            .layer(middleware::from_fn(header_middleware))
            .layer(middleware::from_fn(auth_middleware));

        let (servers, listen_addr, client) = setup_test_env(axum_router).await?;

        tracing::info!(target: "test", "Middleware server listening on {listen_addr}");

        let server_future = async {
            servers.run().await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .instrument(tracing::info_span!("middleware_server"));

        let client_tests = async {
            let port = listen_addr.port();
            let base_url = format!("https://localhost:{port}");

            tracing::info!("Test 1: Request without auth header (should fail)");
            let (.., mut resp) = client.new_request().get(base_url.parse()?).await?;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            tracing::info!("✓ Auth rejection passed");

            tracing::info!(
                "Test 2: Request with auth header (should pass and have middleware header)"
            );
            let (.., mut resp) = client
                .new_request()
                .with_header("x-require-auth", HeaderValue::from_static("secret"))
                .get(base_url.parse()?)
                .await?;

            assert_eq!(resp.status(), StatusCode::OK);

            let body = resp.read_to_string().await?;
            assert_eq!(body, "Middleware works!");

            let has_header = resp
                .headers()
                .iter()
                .any(|(k, v)| k.as_str() == "x-middleware-processed" && v == "true");
            assert!(has_header, "Response should contain middleware header");

            tracing::info!("✓ Middleware success passed");

            servers.shutdown();
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };

        tokio::try_join!(client_tests, server_future)?;
        Ok(())
    }
}
