mod support;

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use bytes::Bytes;
use h3x::{ReadRequest, ReadResponse, WriteRequest, WriteResponse};
use http::{HeaderValue, Method};
use http_body::Frame;
use http_body_util::{BodyExt, Empty};
use support::{Connection, connection_pair};
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};
use wasmtime_wasi_http::{
    WasiHttpCtx,
    p2::{
        HttpResult, WasiHttpCtxView, WasiHttpHooks, WasiHttpView,
        bindings::{Proxy, http::types},
        body::HyperOutgoingBody,
        types::{HostFutureIncomingResponse, IncomingResponse, OutgoingRequestConfig},
    },
};

const CHUNK_SIZE: usize = 4096;
const CHUNKS: usize = 40;

fn fixture() -> &'static (Engine, Component) {
    static FIXTURE: OnceLock<(Engine, Component)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let engine = Engine::default();
        let component = Component::from_binary(
            &engine,
            include_bytes!("fixtures/wasi-http-outgoing-client.wasm"),
        )
        .unwrap();
        (engine, component)
    })
}

type UploadJob = tokio::task::JoinHandle<h3x::Result<()>>;

struct H3Hooks {
    connection: h3x::H3Connection<Connection>,
    uploads: Arc<Mutex<Vec<UploadJob>>>,
}

fn body_error(error: impl std::fmt::Display) -> types::ErrorCode {
    types::ErrorCode::InternalError(Some(error.to_string()))
}

// A test-only WASI HTTP -> h3x adapter. Upload and response headers progress
// independently, so receiving headers never requires finishing the upload.
impl WasiHttpHooks for H3Hooks {
    fn send_request(
        &mut self,
        request: http::Request<HyperOutgoingBody>,
        config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        assert!(config.use_tls);
        let connection = self.connection.clone();
        let uploads = self.uploads.clone();
        Ok(HostFutureIncomingResponse::pending(
            wasmtime_wasi::runtime::spawn(async move {
                let result = async {
                    let (writer, reader) = connection.open_bi().await.map_err(body_error)?;
                    let method = request.method().clone();
                    let request = request.map(|source| {
                        source
                            .map_err(|error| -> h3x::BoxError {
                                std::io::Error::other(error.to_string()).into()
                            })
                            .boxed_unsync()
                    });
                    uploads.lock().unwrap().push(tokio::spawn(
                        writer.write_request(request, connection.qpack().clone()),
                    ));
                    let response = reader
                        .read_response(method, connection.qpack().clone())
                        .await
                        .map_err(body_error)?;
                    Ok(IncomingResponse {
                        resp: response.map(|source| source.map_err(body_error).boxed_unsync()),
                        worker: None,
                        between_bytes_timeout: config.between_bytes_timeout,
                    })
                }
                .await;
                Ok(result)
            }),
        ))
    }
}

struct State {
    table: ResourceTable,
    wasi: WasiCtx,
    http: WasiHttpCtx,
    hooks: H3Hooks,
}

impl WasiView for State {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for State {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.hooks,
        }
    }
}

async fn guest(client: h3x::H3Connection<Connection>, path: &str) {
    let (engine, component) = fixture();
    let mut linker = Linker::new(engine);
    wasmtime_wasi_http::p2::add_to_linker_async(&mut linker).unwrap();
    let uploads = Arc::new(Mutex::new(Vec::new()));
    let mut store = Store::new(
        engine,
        State {
            table: ResourceTable::new(),
            wasi: WasiCtx::builder().build(),
            http: WasiHttpCtx::new(),
            hooks: H3Hooks {
                connection: client,
                uploads: uploads.clone(),
            },
        },
    );
    let proxy = Proxy::instantiate_async(&mut store, component, &linker)
        .await
        .unwrap();
    let request = http::Request::builder()
        .uri(format!("https://trigger.test{path}"))
        .body(Empty::<Bytes>::new().map_err(|error| -> types::ErrorCode { match error {} }))
        .unwrap();
    let request = store
        .data_mut()
        .http()
        .new_incoming_request(types::Scheme::Https, request)
        .unwrap();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let out = store
        .data_mut()
        .http()
        .new_response_outparam(sender)
        .unwrap();
    proxy
        .wasi_http_incoming_handler()
        .call_handle(&mut store, request, out)
        .await
        .unwrap();
    assert_eq!(receiver.await.unwrap().unwrap().status(), 204);
    let jobs = std::mem::take(&mut *uploads.lock().unwrap());
    assert_eq!(
        jobs.len(),
        2,
        "scenario and healthy follow-up must both use h3x"
    );
    for (index, job) in jobs.into_iter().enumerate() {
        let writing = job.await.unwrap();
        if index == 0 && path.starts_with("/stopped-no-error/") {
            assert_eq!(writing.unwrap_err().code, h3x::ErrorCode::NoError);
        } else if index == 0 && (path.starts_with("/abort/") || path.starts_with("/stopped/")) {
            assert!(writing.is_err());
        } else {
            writing.unwrap();
        }
    }
}

async fn serve_one(server: &h3x::H3Connection<Connection>, path: &str) {
    let modes: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let (upload, download, order) = (
        modes[0].to_owned(),
        modes[1].to_owned(),
        modes[2].to_owned(),
    );
    let (writer, reader) = server.accept_bi().await.unwrap();
    let request = reader.read_request(server.qpack().clone()).await.unwrap();
    assert_eq!(
        request.method(),
        if download == "head" {
            Method::HEAD
        } else {
            Method::POST
        }
    );
    assert_eq!(
        request.uri().to_string(),
        format!("https://example.com:443{path}")
    );
    assert_eq!(request.headers()["x-guest"], "wasm");
    assert_eq!(
        request
            .headers()
            .get_all("x-repeat")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    if upload == "fixed" {
        assert_eq!(
            request.headers()["content-length"],
            (CHUNK_SIZE * CHUNKS).to_string()
        );
    }
    let method = request.method().clone();
    let (consumed, consumption) =
        tokio::sync::oneshot::channel::<Result<Option<h3x::Body>, h3x::BoxError>>();
    let read_upload = upload.clone();
    let duplex = order == "duplex";
    let reading = async move {
        let mut source = request.into_body();
        let result = if read_upload == "stopped" || read_upload == "stopped-no-error" {
            assert!(source.frame().await.unwrap().unwrap().is_data());
            drop(source);
            if read_upload == "stopped" {
                Err(std::io::Error::other("server cancelled upload").into())
            } else {
                Ok(None)
            }
        } else if duplex {
            Ok(Some(source))
        } else {
            match source.collect().await {
                Err(error) => {
                    assert_eq!(read_upload, "abort");
                    assert_eq!(
                        error.downcast_ref::<h3x::Error>().unwrap().code,
                        h3x::ErrorCode::RequestCancelled
                    );
                    Err(error)
                }
                Ok(received) => {
                    if read_upload == "trailers" || read_upload == "trailers-only" {
                        assert_eq!(
                            received
                                .trailers()
                                .unwrap()
                                .get_all("x-upload-trailer")
                                .iter()
                                .map(|v| v.to_str().unwrap())
                                .collect::<Vec<_>>(),
                            ["one", "two"]
                        );
                    } else {
                        assert!(received.trailers().is_none());
                    }
                    let expected = match read_upload.as_str() {
                        "small" => b"request".to_vec(),
                        "stream" | "fixed" | "trailers" => vec![b'q'; CHUNK_SIZE * CHUNKS],
                        _ => Vec::new(),
                    };
                    assert_eq!(received.to_bytes(), expected);
                    Ok(None)
                }
            }
        };
        let _ = consumed.send(result);
    };
    let writing = async move {
        let mut response = http::Response::builder()
            .status(if download == "no-content" { 204 } else { 200 })
            .header("x-server", "h3x");
        if download == "fixed" || download == "head" {
            response = response.header(
                http::header::CONTENT_LENGTH,
                (CHUNK_SIZE * CHUNKS).to_string(),
            );
        }
        let mut consumption = Some(consumption);
        let ready = if order == "normal" {
            Some(consumption.take().unwrap().await.unwrap())
        } else {
            None
        };
        let fails =
            download == "cancel" || download == "reset" || upload == "abort" || upload == "stopped";
        let frames = async_stream::try_stream! {
            let request = match ready {
                Some(result) => result?,
                None => consumption.take().unwrap().await.unwrap()?,
            };
            if let Some(mut source) = request {
                let mut count = 0;
                while let Some(frame) = source.frame().await {
                    let data = frame?.into_data().expect("duplex DATA");
                    assert!(data.iter().all(|&byte| byte == b'q'));
                    count += data.len();
                    yield Frame::data(data);
                }
                assert_eq!(count, CHUNK_SIZE * CHUNKS);
            } else if download == "cancel" {
                loop { yield Frame::data(Bytes::from(vec![b'r'; CHUNK_SIZE])); }
            } else if download == "reset" {
                yield Frame::data(Bytes::from_static(b"partial"));
                Err::<(), h3x::BoxError>(std::io::Error::other("server reset response").into())?;
            } else {
                match download.as_str() {
                    "small" => { yield Frame::data(Bytes::from_static(b"response")); }
                    "stream" | "fixed" | "trailers" => {
                        for _ in 0..CHUNKS { yield Frame::data(Bytes::from(vec![b'r'; CHUNK_SIZE])); }
                    }
                    _ => {}
                }
            }
            if download == "trailers" || download == "trailers-only" {
                let mut trailers = http::HeaderMap::new();
                for value in ["one", "two"] { trailers.append("x-download-trailer", HeaderValue::from_static(value)); }
                yield Frame::trailers(trailers);
            }
        };
        let source: h3x::Body = http_body_util::StreamBody::new(frames).boxed_unsync();
        let result = writer
            .write_response(
                response.body(source).unwrap(),
                method,
                server.qpack().clone(),
            )
            .await;
        if fails {
            assert!(result.is_err());
        } else {
            result.unwrap();
        }
    };
    tokio::join!(reading, writing);
}

async fn scenario(path: &str) {
    // Compile outside the timeout so slow CI compilation isn't mistaken for a
    // streaming deadlock. Every task owned by the adapter is joined by guest().
    fixture();
    let (client, server) = connection_pair();
    tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(guest(client, path), async {
            serve_one(&server, path).await;
            serve_one(&server, "/absent/small/normal").await;
        });
    })
    .await
    .unwrap_or_else(|_| panic!("WASM outgoing scenario stalled: {path}"));
}

#[tokio::test]
async fn outgoing_body_combinations() {
    for upload in [
        "absent",
        "empty",
        "small",
        "stream",
        "fixed",
        "trailers",
        "trailers-only",
    ] {
        for download in [
            "empty",
            "small",
            "stream",
            "fixed",
            "trailers",
            "trailers-only",
        ] {
            scenario(&format!("/{upload}/{download}/normal")).await;
        }
    }
}

#[tokio::test]
async fn outgoing_bodyless_response_semantics() {
    scenario("/absent/head/normal").await;
    scenario("/stream/no-content/normal").await;
}

#[tokio::test]
async fn outgoing_response_headers_before_upload() {
    scenario("/trailers/small/early").await;
}

#[tokio::test]
async fn outgoing_full_duplex_body() {
    scenario("/stream/stream/duplex").await;
}

#[tokio::test]
async fn outgoing_abandoned_upload() {
    scenario("/abort/small/early").await;
}

#[tokio::test]
async fn outgoing_peer_stops_upload() {
    scenario("/stopped/small/early").await;
}

#[tokio::test]
async fn outgoing_guest_drops_response() {
    scenario("/absent/cancel/normal").await;
}

#[tokio::test]
async fn outgoing_peer_resets_response() {
    scenario("/small/reset/early").await;
}

#[tokio::test]
async fn outgoing_no_error_stop_preserves_response() {
    // "normal": stop the upload before sending response headers.
    // "early": the guest receives headers before starting its upload.
    // In both cases it must observe the stopped writer, then read a complete
    // response (including trailers), and reuse the same connection.
    for order in ["normal", "early"] {
        for download in [
            "empty",
            "small",
            "stream",
            "fixed",
            "trailers",
            "trailers-only",
            "no-content",
        ] {
            scenario(&format!("/stopped-no-error/{download}/{order}")).await;
        }
    }
}
