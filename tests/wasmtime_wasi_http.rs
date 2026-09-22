mod support;

use h3x::{
    ArcWndBuf, R, ReadRequest, ReadResponse, Request, Response, Trailers, W, WriteRequest,
    WriteResponse,
};
use http::{Method, StatusCode};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};
use support::connection_pair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

struct ServerState {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
}

struct WasmHttpHandler {
    store: Store<ServerState>,
    proxy: Proxy,
}

struct WasmHttpResponse {
    response: http::Response<wasmtime_wasi_http::p2::body::HyperOutgoingBody>,
    execution: tokio::task::JoinHandle<wasmtime::Result<()>>,
}

impl WasmHttpHandler {
    async fn new() -> Self {
        let engine = Engine::default();
        let component =
            Component::from_binary(&engine, include_bytes!("fixtures/wasi-http-handler.wasm"))
                .unwrap();
        let mut linker = Linker::new(&engine);
        wasmtime_wasi_http::p2::add_to_linker_async(&mut linker).unwrap();
        let mut store = Store::new(
            &engine,
            ServerState {
                table: ResourceTable::new(),
                wasi: WasiCtx::builder().build(),
                http: WasiHttpCtx::new(),
            },
        );
        let proxy = Proxy::instantiate_async(&mut store, &component, &linker)
            .await
            .unwrap();
        Self { store, proxy }
    }

    async fn handle<B>(
        mut self,
        scheme: types::Scheme,
        request: http::Request<B>,
    ) -> WasmHttpResponse
    where
        B: Body<Data = bytes::Bytes> + Send + 'static,
        B::Error: Into<types::ErrorCode>,
    {
        let request = self
            .store
            .data_mut()
            .http()
            .new_incoming_request(scheme, request)
            .unwrap();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let outparam = self
            .store
            .data_mut()
            .http()
            .new_response_outparam(sender)
            .unwrap();

        // The guest can set the response outparam and then block when its bounded
        // outgoing-body channel fills. Drive it independently so the host can
        // consume that body before the guest handler returns.
        let execution = tokio::spawn(async move {
            self.proxy
                .wasi_http_incoming_handler()
                .call_handle(&mut self.store, request, outparam)
                .await
        });
        let response = receiver.await.unwrap().unwrap();
        WasmHttpResponse {
            response,
            execution,
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

#[tokio::test]
async fn http3_and_wasi_http_stream_large_bodies_and_trailers() {
    const REQUEST_BODY: &[u8] = b"hello-hello-hello-hello-hello-hello-hello-hello";
    const RESPONSE_CHUNK: &[u8] = b"world-world-";
    const RESPONSE_CHUNKS: usize = 64;

    let handler = WasmHttpHandler::new().await;
    let (client, server) = connection_pair();
    let (client_ws, client_rs) = client.open_bi().await.unwrap();

    let serving = async move {
        let (server_ws, server_rs) = server.accept_bi().await.unwrap();
        let request: Request<R> = server_rs
            .read_request(server.qpack().clone())
            .await
            .unwrap();
        let request_method = request.method().clone();
        let (mut parts, body) = request.into_parts();
        let trailers = parts.extensions.remove::<Trailers>().unwrap();
        let body = futures::stream::try_unfold(
            (body, trailers, false),
            |(mut body, trailers, trailers_sent)| async move {
                if trailers_sent {
                    return Ok::<_, types::ErrorCode>(None);
                }

                let mut chunk = [0; 3];
                let len = body
                    .read(&mut chunk)
                    .await
                    .map_err(|error| types::ErrorCode::InternalError(Some(error.to_string())))?;
                if len != 0 {
                    return Ok(Some((
                        Frame::data(bytes::Bytes::copy_from_slice(&chunk[..len])),
                        (body, trailers, false),
                    )));
                }

                let fields = trailers.headers();
                if fields.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some((Frame::trailers(fields), (body, trailers, true))))
                }
            },
        );
        let request = http::Request::from_parts(parts, StreamBody::new(body));

        let WasmHttpResponse {
            response,
            execution,
        } = handler.handle(types::Scheme::Https, request).await;

        let (parts, mut body) = response.into_parts();
        let window = ArcWndBuf::new(8);
        let mut response: Response<W> = Response::from_parts(parts, window);
        let outgoing = response.clone();
        let writing = server_ws.write_response(outgoing, request_method, server.qpack().clone());
        let pumping = async move {
            while let Some(frame) = body.frame().await {
                let frame = frame.unwrap();
                match frame.into_data() {
                    Ok(data) => {
                        response.write_all(&data).await.unwrap();
                        // Keep the WASI body consumer slower than the guest writer.
                        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    }
                    Err(frame) => {
                        let trailers = frame.into_trailers().unwrap();
                        for (name, value) in &trailers {
                            response.append_trailer(name.clone(), value.clone());
                        }
                    }
                }
            }
            response.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(writing, pumping);
        result.unwrap();
        // Retain and observe the guest task until after its body has drained.
        execution.await.unwrap().unwrap();
    };

    let client_side = async move {
        let window = ArcWndBuf::new(8);
        let mut producer = window.clone();
        let request: Request<W> = http::Request::builder()
            .method(Method::POST)
            .uri("https://example.com/run?mode=test")
            .header("content-type", "text/plain")
            .header("x-request-id", "123")
            .body(window)
            .unwrap()
            .into();
        request.set_trailer(
            http::HeaderName::from_static("x-request-trailer"),
            http::HeaderValue::from_static("preserved"),
        );

        let writing = client_ws.write_request(request, client.qpack().clone());
        let producing = async move {
            producer.write_all(REQUEST_BODY).await?;
            producer.shutdown().await.map_err(h3x::Error::from)
        };
        let receiving = client_rs.read_response(Method::POST, client.qpack().clone());
        let ((), (), mut response): ((), (), Response<R>) =
            tokio::try_join!(writing, producing, receiving).unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let mut body = Vec::new();
        response.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, RESPONSE_CHUNK.repeat(RESPONSE_CHUNKS));
        assert_eq!(response.trailers()["x-response-trailer"], "preserved");
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(serving, client_side)
    })
    .await
    .expect("streaming bridge must not stall when a body exceeds its window");
}

#[tokio::test]
async fn cancelling_wasi_http_response_unblocks_guest_execution() {
    let handler = WasmHttpHandler::new().await;
    let body = StreamBody::new(futures::stream::empty::<
        Result<Frame<bytes::Bytes>, types::ErrorCode>,
    >());
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/cancel")
        .body(body)
        .unwrap();

    let WasmHttpResponse {
        response,
        execution,
    } = handler.handle(types::Scheme::Https, request).await;
    let (_, mut body) = response.into_parts();
    let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(!first.is_empty());
    drop(body);

    tokio::time::timeout(std::time::Duration::from_secs(1), execution)
        .await
        .expect("dropping the response body must unblock guest execution")
        .unwrap()
        .unwrap();
}
