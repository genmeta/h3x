use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, Method};
use tokio::sync::mpsc;

use crate::server::{Request, Response, Service};

struct RequestBodyStream {
    receiver: mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl Stream for RequestBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.receiver.poll_recv(cx)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Conversion failed: {0}")]
    Conversion(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AsyncExecutionError {
    #[error("Timeout")]
    Timeout,
    #[error("Service error: {0}")]
    ServiceError(Box<dyn std::error::Error + Send + Sync>),
    #[error("Extractor error: {0}")]
    ExtractorError(String),
    #[error("Middleware error: {0}")]
    MiddlewareError(String),
}

#[derive(Clone)]
pub struct AxumService<S> {
    inner: S,
    state: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl<S> AxumService<S>
where
    S: tower::Service<http::Request<axum::body::Body>, Response = http::Response<axum::body::Body>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    S::Future: Send + 'static,
{
    pub fn new(router: S) -> Self {
        Self {
            inner: router,
            state: None,
        }
    }

    pub fn with_state<T: Send + Sync + 'static>(mut self, state: T) -> Self {
        self.state = Some(Arc::new(state));
        self
    }

    fn create_error_response(
        &self,
        response: &mut Response,
        status_code: http::StatusCode,
        error_type: &str,
        message: &str,
    ) {
        response.set_status(status_code);
        response.set_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let error_response = serde_json::json!({"error": error_type, "message": message, "status": status_code.as_u16()});
        response.set_body(Bytes::from(error_response.to_string()));
    }

    async fn convert_request(
        &self,
        h3x_req: &mut Request,
    ) -> Result<
        (
            http::Request<axum::body::Body>,
            Option<mpsc::Sender<Result<Bytes, std::io::Error>>>,
        ),
        ConversionError,
    > {
        let method = h3x_req.method();
        let mut uri_parts = http::uri::Parts::default();
        uri_parts.scheme = h3x_req.scheme().or_else(|| Some(http::uri::Scheme::HTTPS));
        uri_parts.authority = h3x_req.authority();
        uri_parts.path_and_query = h3x_req.path();
        let uri = http::Uri::from_parts(uri_parts)
            .map_err(|e| ConversionError::Conversion(format!("Invalid URI: {}", e)))?;

        let mut headers = HeaderMap::new();
        for (name, value) in h3x_req.headers() {
            headers
                .try_insert(name.clone(), value.clone())
                .map_err(|e| {
                    ConversionError::Conversion(format!("Invalid header '{}': {}", name, e))
                })?;
        }

        let (body, body_tx) = if matches!(method, Method::GET | Method::HEAD | Method::DELETE) {
            (axum::body::Body::empty(), None)
        } else {
            // Create a channel for streaming request body chunks from H3X to Axum
            let (sender, receiver) = mpsc::channel(16);
            let stream = RequestBodyStream { receiver };
            (axum::body::Body::from_stream(stream), Some(sender))
        };

        let mut request_builder = http::Request::builder().method(method).uri(uri);
        if let Some(headers_mut) = request_builder.headers_mut() {
            *headers_mut = headers;
        } else {
            return Err(ConversionError::Conversion(
                "Failed to set headers".to_string(),
            ));
        }
        let request = request_builder
            .body(body)
            .map_err(|e| ConversionError::Conversion(format!("Failed to build request: {}", e)))?;
        Ok((request, body_tx))
    }

    #[allow(dead_code)]
    fn inject_state<T: 'static + Send + Sync>(&self) -> Option<Arc<T>> {
        self.state
            .as_ref()
            .and_then(|state| state.clone().downcast::<T>().ok())
    }

    async fn execute(
        &self,
        axum_request: http::Request<axum::body::Body>,
    ) -> Result<http::Response<axum::body::Body>, AsyncExecutionError> {
        let mut service_clone = self.inner.clone();
        let timeout_duration = std::time::Duration::from_secs(30);
        tracing::debug!("Executing request");
        match tokio::time::timeout(
            timeout_duration,
            tower::Service::call(&mut service_clone, axum_request),
        )
        .await
        {
            Ok(Ok(response)) => {
                self.validate_middleware_response(&response)?;
                Ok(response)
            }
            Ok(Err(service_error)) => {
                let boxed_error: Box<dyn std::error::Error + Send + Sync> = service_error.into();
                let error_msg = boxed_error.to_string();
                tracing::error!("Service error: {}", error_msg);
                if error_msg.contains("extractor")
                    || error_msg.contains("deserialize")
                    || error_msg.contains("parse")
                {
                    Err(AsyncExecutionError::ExtractorError(error_msg))
                } else if error_msg.contains("middleware") || error_msg.contains("layer") {
                    Err(AsyncExecutionError::MiddlewareError(error_msg))
                } else {
                    Err(AsyncExecutionError::ServiceError(boxed_error))
                }
            }
            Err(_) => {
                tracing::warn!("Timeout after {}s", timeout_duration.as_secs());
                Err(AsyncExecutionError::Timeout)
            }
        }
    }

    fn validate_middleware_response(
        &self,
        response: &http::Response<axum::body::Body>,
    ) -> Result<(), AsyncExecutionError> {
        let status = response.status();
        if !status.is_informational()
            && !status.is_success()
            && !status.is_redirection()
            && !status.is_client_error()
            && !status.is_server_error()
        {
            return Err(AsyncExecutionError::MiddlewareError(format!(
                "Invalid status: {}",
                status
            )));
        }
        for (name, value) in response.headers() {
            if name.as_str().is_empty() {
                return Err(AsyncExecutionError::MiddlewareError(
                    "Empty header name".to_string(),
                ));
            }
            if value.as_bytes().iter().any(|&b| b < 32 && b != 9) {
                return Err(AsyncExecutionError::MiddlewareError(format!(
                    "Invalid header value for '{}'",
                    name
                )));
            }
        }
        tracing::debug!("Response validation passed");
        Ok(())
    }

    fn handle_error(&self, error: AsyncExecutionError) -> (http::StatusCode, String, String) {
        match error {
            AsyncExecutionError::MiddlewareError(msg) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Middleware Error".to_string(),
                format!("Middleware processing failed: {}", msg),
            ),
            AsyncExecutionError::ExtractorError(msg) => (
                http::StatusCode::BAD_REQUEST,
                "Request Processing Error".to_string(),
                format!("Failed to process request data: {}", msg),
            ),
            AsyncExecutionError::Timeout => (
                http::StatusCode::GATEWAY_TIMEOUT,
                "Request Timeout".to_string(),
                "The request took too long to process".to_string(),
            ),
            AsyncExecutionError::ServiceError(service_error) => (
                http::StatusCode::INTERNAL_SERVER_ERROR,
                "Service Error".to_string(),
                service_error.to_string(),
            ),
        }
    }

    async fn convert_response(
        &self,
        axum_resp: http::Response<axum::body::Body>,
        h3x_resp: &mut Response,
    ) -> Result<(), ConversionError> {
        let status = axum_resp.status();
        if !status.is_informational()
            && !status.is_success()
            && !status.is_redirection()
            && !status.is_client_error()
            && !status.is_server_error()
        {
            return Err(ConversionError::Conversion(format!(
                "Invalid status: {}",
                status
            )));
        }
        h3x_resp.set_status(status);
        for (name, value) in axum_resp.headers() {
            if name.as_str().is_empty() {
                return Err(ConversionError::Conversion("Empty header name".to_string()));
            }
            if value.as_bytes().iter().any(|&b| b < 32 && b != 9) {
                return Err(ConversionError::Conversion(format!(
                    "Invalid header value for '{}'",
                    name
                )));
            }
            h3x_resp.set_header(name.clone(), value.clone());
        }
        // NOTE: 这里在发送 header 之前需要手动把 body 切换到 streaming 模式，否则等发送了 header，就默认是 chunk 模式无法更改
        h3x_resp.init_streaming().await.map_err(|e| {
            ConversionError::Conversion(format!("Init streaming mode failed: {}", e))
        })?;
        let (_parts, body) = axum_resp.into_parts();
        self.convert_streaming_response_body(body, h3x_resp).await?;
        Ok(())
    }

    async fn convert_streaming_response_body(
        &self,
        mut body: axum::body::Body,
        h3x_resp: &mut Response,
    ) -> Result<(), ConversionError> {
        use http_body_util::BodyExt;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref()
                        && !data.is_empty()
                    {
                        h3x_resp.write(data.clone()).await.map_err(|e| {
                            ConversionError::Conversion(format!("Write failed: {}", e))
                        })?;
                    }
                    if let Some(trailers) = frame.trailers_ref() {
                        for (name, value) in trailers {
                            h3x_resp.set_trailer(name.clone(), value.clone());
                        }
                    }
                }
                Some(Err(e)) => {
                    return Err(ConversionError::Conversion(format!(
                        "Read frame failed: {}",
                        e
                    )));
                }
                None => break,
            }
        }
        h3x_resp
            .flush()
            .await
            .map_err(|e| ConversionError::Conversion(format!("Flush failed: {}", e)))?;
        Ok(())
    }

    async fn pipe_request_body_to_axum(
        &self,
        request: &mut Request,
        body_tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
    ) {
        while let Some(result) = request.read().await {
            match result {
                Ok(chunk) if !chunk.is_empty() => {
                    // Send chunk to Axum body stream
                    if body_tx.send(Ok(chunk)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = body_tx
                        .send(Err(std::io::Error::other(e.to_string())))
                        .await;
                    break;
                }
                _ => {}
            }
        }
        drop(body_tx);
    }
}

impl<S> Service for AxumService<S>
where
    S: tower::Service<http::Request<axum::body::Body>, Response = http::Response<axum::body::Body>>
        + Clone
        + Send
        + Sync
        + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    S::Future: Send + 'static,
{
    type Future<'s> = Pin<Box<dyn Future<Output = ()> + Send + 's>>;

    fn serve<'s>(
        &'s mut self,
        request: &'s mut Request,
        response: &'s mut Response,
    ) -> Self::Future<'s> {
        Box::pin(async move {
            tracing::debug!("Starting request conversion");
            let (axum_request, body_tx) = match self.convert_request(request).await {
                Ok(req) => req,
                Err(error) => {
                    tracing::error!("Conversion failed: {}", error);
                    self.create_error_response(
                        response,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Conversion Error",
                        &error.to_string(),
                    );
                    if let Err(close_error) = response.close().await {
                        tracing::error!("Close failed: {}", close_error);
                    }
                    return;
                }
            };
            tracing::debug!("Request conversion succeeded");

            let service_handler = async {
                let axum_response = match self.execute(axum_request).await {
                    Ok(resp) => resp,
                    Err(error) => {
                        tracing::error!("Execution failed: {}", error);
                        let (status_code, error_type, message) = self.handle_error(error);
                        self.create_error_response(response, status_code, &error_type, &message);
                        return;
                    }
                };
                tracing::debug!("Request execution succeeded");
                if let Err(conversion_error) = self.convert_response(axum_response, response).await
                {
                    tracing::error!("Response conversion failed: {}", conversion_error);
                    self.create_error_response(
                        response,
                        http::StatusCode::INTERNAL_SERVER_ERROR,
                        "Conversion Error",
                        "Response conversion failed",
                    );
                }
            };

            if let Some(body_tx) = body_tx {
                tokio::join!(
                    self.pipe_request_body_to_axum(request, body_tx),
                    service_handler
                );
            } else {
                service_handler.await;
            }

            if let Err(close_error) = response.close().await {
                tracing::error!("Close failed: {}", close_error);
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;

    use super::*;

    /// Simple integration test with just GET requests (no body reading)
    #[cfg(all(feature = "gm-quic", feature = "axum"))]
    #[tokio::test]
    #[serial]
    async fn axum_simple_integration_test() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    {
        use std::net::SocketAddr;

        use axum::{Router, http::StatusCode, response::Json, routing::get};
        use gm_quic::prelude::{
            BindUri, QuicIO,
            handy::{ToCertificate, ToPrivateKey},
        };
        use serde::{Deserialize, Serialize};
        use tracing::Instrument;

        use crate::{client::Client, server::Servers};

        const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        fn init_tracing() {
            _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
        }

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

        let mut servers = Servers::builder().without_client_cert_verifier()?.build();

        servers
            .add_server(
                "localhost",
                SERVER_CERT.to_certificate(),
                SERVER_KEY.to_private_key(),
                None,
                [BindUri::from("inet://[::1]:0").alloc_port()],
                AxumService::new(axum_router),
            )
            .await?;

        // Get the listening address
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
            .real_addr()
            .unwrap()
            .try_into()
            .unwrap();

        tracing::info!(target: "test", "Simple Axum server listening on {listen_addr}");

        // Create h3x client
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CA_CERT.to_certificate());
        let client = Client::builder()
            .with_root_certificates(roots)
            .without_identity()?
            .build();

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

    #[cfg(all(feature = "gm-quic", feature = "axum"))]
    #[tokio::test]
    #[serial]
    async fn test_streaming_body_integration()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::net::SocketAddr;

        use axum::{Router, routing::post};
        use bytes::Bytes;
        use gm_quic::prelude::{
            BindUri, QuicIO,
            handy::{ToCertificate, ToPrivateKey},
        };
        use tracing::Instrument;

        use crate::{client::Client, server::Servers};

        const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        fn init_tracing() {
            _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
        }

        async fn streaming_echo_handler(body: axum::body::Body) -> axum::body::Body {
            body
        }

        init_tracing();

        let axum_router = Router::new().route("/echo", post(streaming_echo_handler));

        let mut servers = Servers::builder().without_client_cert_verifier()?.build();

        servers
            .add_server(
                "localhost",
                SERVER_CERT.to_certificate(),
                SERVER_KEY.to_private_key(),
                None,
                [BindUri::from("inet://[::1]:0").alloc_port()],
                AxumService::new(axum_router),
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
            .real_addr()
            .unwrap()
            .try_into()
            .unwrap();

        tracing::info!(target: "test", "Streaming server listening on {listen_addr}");

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CA_CERT.to_certificate());
        let client = Client::builder()
            .with_root_certificates(roots)
            .without_identity()?
            .build();

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

    #[cfg(all(feature = "gm-quic", feature = "axum"))]
    #[tokio::test]
    #[serial]
    async fn test_body_size_limit() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::net::SocketAddr;

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
        use gm_quic::prelude::{
            BindUri, QuicIO,
            handy::{ToCertificate, ToPrivateKey},
        };
        use http::StatusCode;
        use tracing::Instrument;

        use crate::{client::Client, server::Servers};

        const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
        const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
        const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

        const BODY_LIMIT: usize = 16;

        fn init_tracing() {
            _ = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .try_init();
        }

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

        let mut servers = Servers::builder().without_client_cert_verifier()?.build();

        servers
            .add_server(
                "localhost",
                SERVER_CERT.to_certificate(),
                SERVER_KEY.to_private_key(),
                None,
                [BindUri::from("inet://[::1]:0").alloc_port()],
                AxumService::new(axum_router),
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
            .real_addr()
            .unwrap()
            .try_into()
            .unwrap();

        tracing::info!(target: "test", "Body limit server listening on {listen_addr}");

        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CA_CERT.to_certificate());
        let client = Client::builder()
            .with_root_certificates(roots)
            .without_identity()?
            .build();

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
}
