use std::io::{Read, Write};

use wasip2::http::{outgoing_handler, types::*};

struct Handler;

const CHUNK: &[u8] = &[b'q'; 4096];
const CHUNKS: usize = 40;

fn wait_response(future: &FutureIncomingResponse) -> IncomingResponse {
    future.subscribe().block();
    future.get().unwrap().unwrap().unwrap()
}

fn run(path: &str) {
    let modes: Vec<_> = path.trim_start_matches('/').split('/').collect();
    let (upload, download, order) = (modes[0], modes[1], modes[2]);
    let headers = Fields::new();
    headers.append("x-guest", b"wasm").unwrap();
    headers.append("x-repeat", b"one").unwrap();
    headers.append("x-repeat", b"two").unwrap();
    if upload == "fixed" {
        headers
            .append(
                "content-length",
                (CHUNK.len() * CHUNKS).to_string().as_bytes(),
            )
            .unwrap();
    }
    let request = OutgoingRequest::new(headers);
    request
        .set_method(&if download == "head" {
            Method::Head
        } else {
            Method::Post
        })
        .unwrap();
    request.set_scheme(Some(&Scheme::Https)).unwrap();
    request.set_authority(Some("example.com:443")).unwrap();
    request.set_path_with_query(Some(path)).unwrap();
    let body = (upload != "absent").then(|| request.body().unwrap());
    let future = outgoing_handler::handle(request, None).unwrap();
    // Waiting here proves the host does not wait for upload EOF to expose headers.
    let mut response = (order == "early" || order == "duplex").then(|| wait_response(&future));
    let mut duplex_body = if order == "duplex" {
        Some(response.as_ref().unwrap().consume().unwrap())
    } else {
        None
    };
    let mut duplex_input = duplex_body.as_ref().map(|body| body.stream().unwrap());
    if let Some(body) = body {
        let mut output = body.write().unwrap();
        match upload {
            "empty" | "trailers-only" => {}
            "small" => output.write_all(b"request").unwrap(),
            "stream" | "fixed" | "trailers" => {
                for _ in 0..CHUNKS {
                    output.write_all(CHUNK).unwrap();
                    if let Some(input) = &mut duplex_input {
                        output.flush().unwrap();
                        let mut echoed = vec![0; CHUNK.len()];
                        input.read_exact(&mut echoed).unwrap();
                        assert_eq!(echoed, CHUNK);
                    }
                }
            }
            "abort" => output.write_all(b"partial").unwrap(),
            "stopped" | "stopped-no-error" => {
                // The peer stops reading after receiving a byte; the bounded
                // host bridge must propagate that failure to this WASM writer.
                while output.write_all(CHUNK).is_ok() {}
            }
            _ => panic!("unknown upload mode"),
        }
        drop(output);
        if upload == "abort" || upload == "stopped" || upload == "stopped-no-error" {
            drop(body);
        } else {
            let trailers = if upload == "trailers" || upload == "trailers-only" {
                let fields = Fields::new();
                fields.append("x-upload-trailer", b"one").unwrap();
                fields.append("x-upload-trailer", b"two").unwrap();
                Some(fields)
            } else {
                None
            };
            OutgoingBody::finish(body, trailers).unwrap();
        }
    }
    let response = response.take().unwrap_or_else(|| wait_response(&future));
    assert_eq!(
        response.status(),
        if download == "no-content" { 204 } else { 200 }
    );
    assert_eq!(response.headers().get("x-server"), [b"h3x"]);
    if download == "fixed" || download == "head" {
        assert_eq!(
            response.headers().get("content-length"),
            [(CHUNK.len() * CHUNKS).to_string().into_bytes()]
        );
    }
    let body = duplex_body
        .take()
        .unwrap_or_else(|| response.consume().unwrap());
    let mut input = duplex_input
        .take()
        .unwrap_or_else(|| body.stream().unwrap());
    if download == "cancel" {
        input.read_exact(&mut [0]).unwrap();
        drop(input);
        drop(body);
        return;
    }
    let mut received = Vec::new();
    let result = input.read_to_end(&mut received);
    if download == "reset" || upload == "abort" || upload == "stopped" {
        assert!(
            result.is_err(),
            "peer reset must reach WASM as a body error"
        );
        return;
    }
    result.unwrap();
    let expected = match download {
        "small" => b"response".to_vec(),
        "stream" | "fixed" | "trailers" if order != "duplex" => vec![b'r'; CHUNK.len() * CHUNKS],
        _ => Vec::new(),
    };
    assert_eq!(received, expected);
    drop(input);
    let trailers = IncomingBody::finish(body);
    trailers.subscribe().block();
    let trailers = trailers.get().unwrap().unwrap().unwrap();
    if download == "trailers" || download == "trailers-only" {
        assert_eq!(
            trailers.unwrap().get("x-download-trailer"),
            [b"one", b"two"]
        );
    } else if let Some(trailers) = trailers {
        assert!(trailers.entries().is_empty());
    }
}

impl wasip2::exports::http::incoming_handler::Guest for Handler {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        let path = request.path_with_query().unwrap();
        run(&path);
        // Every scenario also checks a healthy follow-up on the same connection.
        run("/absent/small/normal");
        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(204).unwrap();
        ResponseOutparam::set(response_out, Ok(response));
    }
}

wasip2::http::proxy::export!(Handler);
