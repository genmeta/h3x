mod support;

use std::{
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use h3x::{
    ArcWndBuf, R, ReadRequest, ReadResponse, Request, Response, W, WriteRequest, WriteResponse,
};
use http::{HeaderName, HeaderValue, Method};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Empty};
use qrecovery::{recv::StopSending, send::CancelStream};
use support::{Connection, connection_pair};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
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
const CANCEL: u64 = h3x::ErrorCode::RequestCancelled.as_u64();

type UploadJob = tokio::task::JoinHandle<(h3x::Result<()>, std::io::Result<()>)>;

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
                    let (parts, mut body) = request.into_parts();
                    let method = parts.method.clone();
                    let mut request: Request<W> =
                        http::Request::from_parts(parts, ArcWndBuf::new(257)).into();
                    let sending = writer.write_request(request.clone(), connection.qpack().clone());
                    let forwarding = async move {
                        let result = async {
                            while let Some(frame) = body.frame().await {
                                let frame = frame
                                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                                match frame.into_data() {
                                    Ok(data) => request.write_all(&data).await?,
                                    Err(frame) => {
                                        for (name, value) in
                                            &frame.into_trailers().expect("body trailer frame")
                                        {
                                            request.append_trailer(name.clone(), value.clone());
                                        }
                                    }
                                }
                            }
                            request.shutdown().await
                        }
                        .await;
                        if result.is_err() {
                            request.cancel(CANCEL);
                        }
                        result
                    };
                    uploads.lock().unwrap().push(tokio::spawn(async move {
                        tokio::join!(sending, forwarding)
                    }));
                    let response: Response<R> = reader
                        .read_response(method, connection.qpack().clone())
                        .await
                        .map_err(body_error)?;
                    let (parts, body) = response.into_parts();
                    let response = Response::from_parts(parts.clone(), body);
                    let body = H3ResponseBody {
                        response,
                        finished: false,
                    }
                    .boxed_unsync();
                    Ok(IncomingResponse {
                        resp: http::Response::from_parts(parts, body),
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

// Dropping a WASI incoming body must stop its H3 stream, even if EOF was never
// polled. Reading EOF exposes trailers exactly once.
struct H3ResponseBody {
    response: Response<R>,
    finished: bool,
}

impl Body for H3ResponseBody {
    type Data = Bytes;
    type Error = types::ErrorCode;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        let mut bytes = [0; 4096];
        let mut buffer = ReadBuf::new(&mut bytes);
        match Pin::new(&mut self.response).poll_read(cx, &mut buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.finished = true;
                Poll::Ready(Some(Err(body_error(error))))
            }
            Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                self.finished = true;
                let trailers = self.response.trailers();
                Poll::Ready((!trailers.is_empty()).then(|| Ok(Frame::trailers(trailers))))
            }
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                buffer.filled(),
            ))))),
        }
    }
}

impl Drop for H3ResponseBody {
    fn drop(&mut self) {
        if !self.finished {
            self.response.stop(CANCEL);
        }
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
        let (writing, forwarding) = job.await.unwrap();
        if index == 0 && path.starts_with("/stopped-no-error/") {
            assert_eq!(writing.unwrap_err().code, h3x::ErrorCode::NoError);
            assert_eq!(
                h3x::Error::from(forwarding.unwrap_err()).code,
                h3x::ErrorCode::NoError
            );
        } else if index == 0 && (path.starts_with("/abort/") || path.starts_with("/stopped/")) {
            assert!(writing.is_err());
            assert!(forwarding.is_err());
        } else {
            writing.unwrap();
            forwarding.unwrap();
        }
    }
}

async fn serve_one(server: &h3x::H3Connection<Connection>, path: &str) {
    let modes: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let (upload, download, order) = (modes[0], modes[1], modes[2]);
    let (writer, reader) = server.accept_bi().await.unwrap();
    let mut request = reader.read_request(server.qpack().clone()).await.unwrap();
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
    let mut response: Response<W> = http::Response::builder()
        .status(if download == "no-content" { 204 } else { 200 })
        .header("x-server", "h3x")
        .body(ArcWndBuf::new(257))
        .unwrap()
        .into();
    if download == "fixed" || download == "head" {
        response.set_header(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&(CHUNK_SIZE * CHUNKS).to_string()).unwrap(),
        );
    }
    let (consumed, consumption) = tokio::sync::oneshot::channel();
    let reading = async move {
        if upload == "stopped" || upload == "stopped-no-error" {
            request.read_exact(&mut [0]).await.unwrap();
            request.stop(if upload == "stopped-no-error" {
                h3x::ErrorCode::NoError.as_u64()
            } else {
                CANCEL
            });
        } else if order != "duplex" {
            let mut bytes = Vec::new();
            let result = request.read_to_end(&mut bytes).await;
            if upload == "abort" {
                assert_eq!(
                    h3x::Error::from(result.unwrap_err()).code,
                    h3x::ErrorCode::RequestCancelled
                );
            } else {
                result.unwrap();
                let expected = match upload {
                    "small" => b"request".to_vec(),
                    "stream" | "fixed" | "trailers" => vec![b'q'; CHUNK_SIZE * CHUNKS],
                    _ => Vec::new(),
                };
                assert_eq!(bytes, expected);
                let trailers = request.trailers();
                if upload == "trailers" || upload == "trailers-only" {
                    assert_eq!(
                        trailers
                            .get_all("x-upload-trailer")
                            .iter()
                            .map(|v| v.to_str().unwrap())
                            .collect::<Vec<_>>(),
                        ["one", "two"]
                    );
                } else {
                    assert!(trailers.is_empty());
                }
            }
        }
        consumed.send(request).ok();
    };
    let writing = async {
        // Normal responses cannot send headers until EOF; early and duplex
        // responses must send headers before the guest produces its body.
        let mut consumption = Some(consumption);
        let request = if order == "normal" {
            Some(consumption.take().unwrap().await.unwrap())
        } else {
            None
        };
        let sending = writer.write_response(response.clone(), method, server.qpack().clone());
        let producing = async move {
            if order == "early" {
                consumption.take().unwrap().await.unwrap();
            }
            if order == "duplex" {
                let mut request = match request {
                    Some(r) => r,
                    None => consumption.take().unwrap().await.unwrap(),
                };
                for _ in 0..CHUNKS {
                    let mut chunk = vec![0; CHUNK_SIZE];
                    request.read_exact(&mut chunk).await.unwrap();
                    assert_eq!(chunk, vec![b'q'; CHUNK_SIZE]);
                    response.write_all(&chunk).await.unwrap();
                }
                assert_eq!(request.read(&mut [0]).await.unwrap(), 0);
            } else if download == "cancel" || upload == "abort" || upload == "stopped" {
                loop {
                    if let Err(error) = response.write_all(&[b'r'; CHUNK_SIZE]).await {
                        assert_eq!(
                            h3x::Error::from(error).code,
                            h3x::ErrorCode::RequestCancelled
                        );
                        return;
                    }
                }
            } else if download == "reset" {
                response.write_all(b"partial").await.unwrap();
                response.cancel(CANCEL);
                return;
            } else {
                match download {
                    "small" => response.write_all(b"response").await.unwrap(),
                    "stream" | "fixed" | "trailers" => {
                        for _ in 0..CHUNKS {
                            response.write_all(&[b'r'; CHUNK_SIZE]).await.unwrap();
                        }
                    }
                    _ => {}
                }
            }
            if download == "trailers" || download == "trailers-only" {
                for value in ["one", "two"] {
                    response.append_trailer(
                        HeaderName::from_static("x-download-trailer"),
                        HeaderValue::from_static(value),
                    );
                }
            }
            response.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(sending, producing);
        if download == "cancel" || download == "reset" || upload == "abort" || upload == "stopped" {
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
