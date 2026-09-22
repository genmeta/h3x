mod support;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body as AxumBody,
    extract::{Request as AxumRequest, State},
    response::Response as AxumResponse,
    routing::post,
};
use bytes::Bytes;
use futures::{StreamExt, TryStreamExt};
use h3x::{
    ArcWndBuf, R, ReadRequest, ReadResponse, Request, Response, Trailers, W, WriteRequest,
    WriteResponse,
};
use http::{Method, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use qrecovery::{recv::StopSending, send::CancelStream};
use support::{Connection, connection_pair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tower::ServiceExt;
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::{
    WasiHttpCtx,
    p2::{
        WasiHttpCtxView, WasiHttpView,
        bindings::{Proxy, http::types},
    },
};

#[derive(Clone, Copy)]
struct Fixture {
    path: &'static str,
    component: &'static [u8],
}

const READ_THEN_RESPOND: Fixture = Fixture {
    path: "/read-request-then-respond",
    component: include_bytes!("fixtures/wasi-http-read-request-then-respond.wasm"),
};
const RESPOND_THEN_READ: Fixture = Fixture {
    path: "/respond-then-read-request",
    component: include_bytes!("fixtures/wasi-http-respond-then-read-request.wasm"),
};
const STREAM_UNTIL_CANCELLED: Fixture = Fixture {
    path: "/stream-response-until-cancelled",
    component: include_bytes!("fixtures/wasi-http-stream-response-until-cancelled.wasm"),
};
const FAILING_ADAPTER_PATH: &str = "/failing-adapter-body";
const HEALTHY_ADAPTER_PATH: &str = "/healthy-adapter-body";

struct ServerState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
}

impl ServerState {
    fn new() -> Self {
        Self {
            table: ResourceTable::new(),
            wasi: WasiCtx::builder().build(),
            http: WasiHttpCtx::new(),
        }
    }
}

impl WasiView for ServerState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for ServerState {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: Default::default(),
        }
    }
}

#[derive(Clone)]
struct GuestTask(Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<wasmtime::Result<()>>>>>);

impl GuestTask {
    async fn wait(self) {
        self.0.lock().await.take().unwrap().await.unwrap().unwrap();
    }
}

#[derive(Clone)]
struct WasmHandler {
    engine: Engine,
    component: Component,
}

impl WasmHandler {
    fn new(engine: &Engine, component: &[u8]) -> Self {
        Self {
            engine: engine.clone(),
            component: Component::from_binary(engine, component).unwrap(),
        }
    }
}

fn fixture_router() -> Router {
    let engine = Engine::default();

    Router::new()
        .route(
            READ_THEN_RESPOND.path,
            post(handle_wasm).with_state(WasmHandler::new(&engine, READ_THEN_RESPOND.component)),
        )
        .route(
            RESPOND_THEN_READ.path,
            post(handle_wasm).with_state(WasmHandler::new(&engine, RESPOND_THEN_READ.component)),
        )
        .route(
            STREAM_UNTIL_CANCELLED.path,
            post(handle_wasm)
                .with_state(WasmHandler::new(&engine, STREAM_UNTIL_CANCELLED.component)),
        )
}

async fn failing_adapter_response() -> AxumResponse {
    let frames = futures::stream::iter([
        Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"partial"))),
        Err(std::io::Error::other("adapter body failed")),
    ]);
    AxumResponse::new(AxumBody::new(StreamBody::new(frames)))
}

async fn healthy_adapter_response() -> AxumResponse {
    AxumResponse::new(AxumBody::from("healthy"))
}

// Request head:
// client `writer.write_request(request, ...)`
//   → server `reader.read_request(...)`
//   → `request.into_parts()` / `http::Request::from_parts(...)`
//   → `router.oneshot(request)` / `post(handle_wasm)`
//   → `new_incoming_request(...)` / guest `call_handle(...)`
//
// Request body and trailers:
// client `request.write_all(...)` / `request.shutdown()`
//   → h3x `Request<R>` backed by `ArcWndBuf`
//   → `ReaderStream::new(body)` / `StreamBody::new(frames)` / `AxumBody::new(...)`
//   → `new_incoming_request(...)`
//   → guest `request.consume()` / `input.read_to_end(...)` / `IncomingBody::finish(...)`
//
// Response head:
// guest `ResponseOutparam::set(...)`
//   → host `new_response_outparam(sender)` / `receiver.await`
//   → `AxumResponse::from_parts(...)` / return from `handle_wasm`
//   → `router.oneshot(request).await`
//   → `Response::from_parts(...)` / `writer.write_response(...)`
//   → H3 HEADERS
//
// Response body and trailers:
// guest `response_body.write()` / `output.write_all(...)` / `OutgoingBody::finish(...)`
//   → `HyperOutgoingBody` / `AxumBody::new(body)` / `body.frame().await`
//   → `response.write_all(...)` / `response.append_trailer(...)`
//   → shared `ArcWndBuf` read by `writer.write_response(response.clone(), ...)`
//   → H3 DATA / trailing HEADERS

async fn handle_wasm(
    State(WasmHandler { engine, component }): State<WasmHandler>,
    request: AxumRequest,
) -> AxumResponse {
    let (parts, body) = request.into_parts();
    let body = body.map_err(|error| types::ErrorCode::InternalError(Some(error.to_string())));

    let mut linker = Linker::new(&engine);
    wasmtime_wasi_http::p2::add_to_linker_async(&mut linker).unwrap();
    let mut store = Store::new(&engine, ServerState::new());
    let proxy = Proxy::instantiate_async(&mut store, &component, &linker)
        .await
        .unwrap();
    let request = store
        .data_mut()
        .http()
        .new_incoming_request(types::Scheme::Https, http::Request::from_parts(parts, body))
        .unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let outparam = store
        .data_mut()
        .http()
        .new_response_outparam(sender)
        .unwrap();

    // A guest may commit its response before it finishes reading or writing.
    let task = tokio::spawn(async move {
        proxy
            .wasi_http_incoming_handler()
            .call_handle(&mut store, request, outparam)
            .await
    });
    let response = receiver.await.unwrap().unwrap();
    let (parts, body) = response.into_parts();
    let body = body.map_err(|error| std::io::Error::other(error.to_string()));
    let mut response = AxumResponse::from_parts(parts, AxumBody::new(body));
    response
        .extensions_mut()
        .insert(GuestTask(Arc::new(tokio::sync::Mutex::new(Some(task)))));
    response
}

async fn serve(
    router: Router,
    server: h3x::H3Connection<Connection>,
) -> (h3x::Result<()>, std::io::Result<()>) {
    let (writer, reader) = server.accept_bi().await.unwrap();
    let request = reader.read_request(server.qpack().clone()).await.unwrap();
    let method = request.method().clone();

    let (mut parts, body) = request.into_parts();
    let trailers = parts.extensions.remove::<Trailers>().unwrap();
    let frames = ReaderStream::new(body)
        .map_ok(Frame::data)
        .chain(futures::stream::once(async move {
            Ok::<_, std::io::Error>(Frame::trailers(trailers.headers()))
        }));
    let request = http::Request::from_parts(parts, AxumBody::new(StreamBody::new(frames)));

    let mut response = router.oneshot(request).await.unwrap();
    let guest = response.extensions_mut().remove::<GuestTask>();
    let (parts, mut body) = response.into_parts();
    let mut response = Response::from_parts(parts, ArcWndBuf::new(8));

    let writing = writer.write_response(response.clone(), method, server.qpack().clone());
    let forwarding_body = async move {
        let result = async {
            while let Some(frame) = body.frame().await {
                match frame
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .into_data()
                {
                    Ok(data) => {
                        response.write_all(&data).await?;
                        // Make the guest exercise Wasmtime's bounded output channel.
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    Err(frame) => {
                        let trailers = frame
                            .into_trailers()
                            .map_err(|_| std::io::Error::other("unknown response frame"))?;
                        for (name, value) in &trailers {
                            response.append_trailer(name.clone(), value.clone());
                        }
                    }
                }
            }
            response.shutdown().await
        }
        .await;
        if result.is_err() {
            response.cancel(h3x::ErrorCode::RequestCancelled.as_u64());
        }
        result
    };
    let result = tokio::join!(writing, forwarding_body);
    if let Some(guest) = guest {
        guest.wait().await;
    }
    result
}

#[tokio::test]
async fn streams_large_bodies_and_trailers() {
    const REQUEST_BODY: &[u8] = b"hello-hello-hello-hello-hello-hello-hello-hello";

    let (client, server) = connection_pair();
    let serving = serve(fixture_router(), server);
    let client_side = async move {
        let (writer, reader) = client.open_bi().await.unwrap();
        let mut request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", READ_THEN_RESPOND.path))
            .body(ArcWndBuf::new(8))
            .unwrap()
            .into();
        request.set_trailer(
            http::HeaderName::from_static("x-request-trailer"),
            http::HeaderValue::from_static("preserved"),
        );

        let sending = writer.write_request(request.clone(), client.qpack().clone());
        let uploading = async move {
            request.write_all(REQUEST_BODY).await?;
            request.shutdown().await.map_err(h3x::Error::from)
        };
        let ((), (), mut response): ((), (), Response<R>) = tokio::try_join!(
            sending,
            uploading,
            reader.read_response(Method::POST, client.qpack().clone()),
        )
        .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let mut bytes = Vec::new();
        response.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"world-world-".repeat(64));
        let trailers = response.trailers();
        let values: Vec<_> = trailers
            .get_all("x-response-trailer")
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(values, ["preserved", "also-preserved"]);
    };

    let ((writing, forwarding_body), ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serving, client_side)
    })
    .await
    .expect("streaming bodies and trailers must not stall");
    writing.unwrap();
    forwarding_body.unwrap();
}

#[tokio::test]
async fn sends_headers_before_request_body_finishes() {
    let (client, server) = connection_pair();
    let serving = serve(fixture_router(), server);
    let client_side = async move {
        let (writer, reader) = client.open_bi().await.unwrap();
        let mut request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{}", RESPOND_THEN_READ.path))
            .body(ArcWndBuf::new(8))
            .unwrap()
            .into();
        request.set_trailer(
            http::HeaderName::from_static("x-request-trailer"),
            http::HeaderValue::from_static("preserved"),
        );

        let uploading = tokio::spawn(writer.write_request(request.clone(), client.qpack().clone()));
        request.write_all(b"request-").await.unwrap();

        let mut response: Response<R> = tokio::time::timeout(
            Duration::from_secs(1),
            reader.read_response(Method::POST, client.qpack().clone()),
        )
        .await
        .expect("response headers must arrive before the request body finishes")
        .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()["x-handler-mode"],
            "respond-then-read-request"
        );

        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), response.read(&mut byte))
                .await
                .is_err()
        );

        request.write_all(b"body").await.unwrap();
        request.shutdown().await.unwrap();
        uploading.await.unwrap().unwrap();

        let mut bytes = Vec::new();
        response.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"request-body");
        assert_eq!(
            response.trailers()["x-response-trailer"],
            "request-consumed"
        );
    };

    let ((writing, forwarding_body), ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serving, client_side)
    })
    .await
    .expect("response-first handling must not stall");
    writing.unwrap();
    forwarding_body.unwrap();
}

#[tokio::test]
async fn cancelling_response_unblocks_guest() {
    let (client, server) = connection_pair();
    let serving = serve(fixture_router(), server);
    let client_side = async move {
        let (writer, reader) = client.open_bi().await.unwrap();
        let mut request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri(format!(
                "https://example.com{}",
                STREAM_UNTIL_CANCELLED.path
            ))
            .body(ArcWndBuf::new(1))
            .unwrap()
            .into();
        request.shutdown().await.unwrap();

        let sending = writer.write_request(request, client.qpack().clone());
        let receiving = reader.read_response(Method::POST, client.qpack().clone());
        let ((), mut response): ((), Response<R>) = tokio::try_join!(sending, receiving).unwrap();

        response.read_exact(&mut [0]).await.unwrap();
        response.stop(h3x::ErrorCode::RequestCancelled.as_u64());
    };

    let ((writing, forwarding_body), ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serving, client_side)
    })
    .await
    .expect("cancelling the response must unblock the guest");
    assert!(writing.is_err());
    assert!(forwarding_body.is_err());
}

#[tokio::test]
async fn adapter_body_failure_cancels_output_without_poisoning_connection() {
    let router = fixture_router()
        .route(FAILING_ADAPTER_PATH, post(failing_adapter_response))
        .route(HEALTHY_ADAPTER_PATH, post(healthy_adapter_response));
    let (client, server) = connection_pair();
    let serving = async move {
        let failed = serve(router.clone(), server.clone()).await;
        let healthy = serve(router, server).await;
        (failed, healthy)
    };
    let client_side = async move {
        let (writer, reader) = client.open_bi().await.unwrap();
        let mut request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{FAILING_ADAPTER_PATH}"))
            .body(ArcWndBuf::new(1))
            .unwrap()
            .into();
        request.shutdown().await.unwrap();
        let ((), mut response): ((), Response<R>) = tokio::try_join!(
            writer.write_request(request, client.qpack().clone()),
            reader.read_response(Method::POST, client.qpack().clone()),
        )
        .unwrap();
        let mut bytes = Vec::new();
        let error = response.read_to_end(&mut bytes).await.unwrap_err();
        assert_eq!(
            h3x::Error::from(error).code,
            h3x::ErrorCode::RequestCancelled
        );
        assert_eq!(bytes, b"partial");

        let (writer, reader) = client.open_bi().await.unwrap();
        let mut request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri(format!("https://example.com{HEALTHY_ADAPTER_PATH}"))
            .body(ArcWndBuf::new(1))
            .unwrap()
            .into();
        request.shutdown().await.unwrap();
        let ((), mut response): ((), Response<R>) = tokio::try_join!(
            writer.write_request(request, client.qpack().clone()),
            reader.read_response(Method::POST, client.qpack().clone()),
        )
        .unwrap();
        let mut bytes = Vec::new();
        response.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"healthy");
    };

    let (((failed_writing, failed_forwarding), (healthy_writing, healthy_forwarding)), ()) =
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(serving, client_side)
        })
        .await
        .expect("an adapter body failure must not stall or poison the connection");
    assert!(failed_writing.is_err());
    assert_eq!(
        failed_forwarding.unwrap_err().to_string(),
        "adapter body failed"
    );
    healthy_writing.unwrap();
    healthy_forwarding.unwrap();
}
