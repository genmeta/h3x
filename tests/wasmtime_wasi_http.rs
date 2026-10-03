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
use h3x::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http::{Method, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};
use support::{Connection, connection_pair};
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

async fn serve(router: Router, server: h3x::H3Connection<Connection>) -> h3x::Result<()> {
    let (writer, reader) = server.accept_bi().await.unwrap();
    let request = reader.read_request(server.qpack().clone()).await.unwrap();
    let method = request.method().clone();
    let mut response = router.oneshot(request.map(AxumBody::new)).await.unwrap();
    let guest = response.extensions_mut().remove::<GuestTask>();
    let result = writer
        .write_response(
            response.map(|body| body.map_err(Into::into).boxed_unsync()),
            method,
            server.qpack().clone(),
        )
        .await;
    if let Some(guest) = guest {
        guest.wait().await;
    }
    result
}

fn request(path: &str, source: h3x::Body) -> http::Request<h3x::Body> {
    http::Request::builder()
        .method(Method::POST)
        .uri(format!("https://example.com{path}"))
        .body(source)
        .unwrap()
}
fn upload(bytes: &'static [u8]) -> h3x::Body {
    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-request-trailer",
        http::HeaderValue::from_static("preserved"),
    );
    StreamBody::new(futures::stream::iter([
        Ok::<_, h3x::BoxError>(Frame::data(Bytes::from_static(bytes))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed_unsync()
}

#[tokio::test]
async fn streams_large_bodies_and_trailers() {
    let (client, server) = connection_pair();
    let client_side = async {
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = request(
            READ_THEN_RESPOND.path,
            upload(b"hello-hello-hello-hello-hello-hello-hello-hello"),
        );
        let ((), response) = tokio::try_join!(
            writer.write_request(request, client.qpack().clone()),
            reader.read_response(Method::POST, client.qpack().clone())
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let received = response.into_body().collect().await.unwrap();
        assert_eq!(
            received
                .trailers()
                .unwrap()
                .get_all("x-response-trailer")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["preserved", "also-preserved"]
        );
        assert_eq!(received.to_bytes(), b"world-world-".repeat(64));
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve(fixture_router(), server), client_side)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn sends_headers_before_request_body_finishes() {
    let (client, server) = connection_pair();
    let client_side = async {
        let (writer, reader) = client.open_bi().await.unwrap();
        let (release, released) = tokio::sync::oneshot::channel();
        let source = StreamBody::new(async_stream::stream! {
            yield Ok::<_, h3x::BoxError>(Frame::data(Bytes::from_static(b"request-")));
            released.await.unwrap();
            let mut rest = upload(b"body");
            while let Some(frame) = rest.frame().await { yield frame; }
        })
        .boxed_unsync();
        let sending = tokio::spawn(writer.write_request(
            request(RESPOND_THEN_READ.path, source),
            client.qpack().clone(),
        ));
        let mut response = reader
            .read_response(Method::POST, client.qpack().clone())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()["x-handler-mode"],
            "respond-then-read-request"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), response.body_mut().frame())
                .await
                .is_err()
        );
        release.send(()).unwrap();
        let received = response.into_body().collect().await.unwrap();
        assert_eq!(
            received.trailers().unwrap()["x-response-trailer"],
            "request-consumed"
        );
        assert_eq!(received.to_bytes(), "request-body");
        sending.await.unwrap().unwrap();
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve(fixture_router(), server), client_side)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn cancelling_response_unblocks_guest() {
    let (client, server) = connection_pair();
    let client_side = async {
        let (writer, reader) = client.open_bi().await.unwrap();
        let request = request(STREAM_UNTIL_CANCELLED.path, h3x::Body::default());
        let ((), mut response) = tokio::try_join!(
            writer.write_request(request, client.qpack().clone()),
            reader.read_response(Method::POST, client.qpack().clone())
        )
        .unwrap();
        assert!(
            response
                .body_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .is_data()
        );
        drop(response);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serve(fixture_router(), server), client_side)
    })
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().code, h3x::ErrorCode::NoError);
}

#[tokio::test]
async fn adapter_body_failure_cancels_output_without_poisoning_connection() {
    let router = fixture_router()
        .route(FAILING_ADAPTER_PATH, post(failing_adapter_response))
        .route(HEALTHY_ADAPTER_PATH, post(healthy_adapter_response));
    let (client, server) = connection_pair();
    let serving = async {
        let failed = serve(router.clone(), server.clone()).await;
        let healthy = serve(router, server).await;
        assert_eq!(failed.unwrap_err().code, h3x::ErrorCode::RequestCancelled);
        healthy.unwrap();
    };
    let client_side = async {
        for (path, failed) in [(FAILING_ADAPTER_PATH, true), (HEALTHY_ADAPTER_PATH, false)] {
            let (writer, reader) = client.open_bi().await.unwrap();
            writer
                .write_request(request(path, h3x::Body::default()), client.qpack().clone())
                .await
                .unwrap();
            let response = reader
                .read_response(Method::POST, client.qpack().clone())
                .await;
            if failed {
                let error = match response {
                    Err(error) => error,
                    Ok(response) => *response
                        .into_body()
                        .collect()
                        .await
                        .unwrap_err()
                        .downcast::<h3x::Error>()
                        .unwrap(),
                };
                assert_eq!(error.code, h3x::ErrorCode::RequestCancelled);
            } else {
                assert_eq!(
                    response
                        .unwrap()
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes(),
                    "healthy"
                );
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(serving, client_side);
    })
    .await
    .unwrap();
}
