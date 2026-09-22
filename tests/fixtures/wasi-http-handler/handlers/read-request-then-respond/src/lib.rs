use std::io::{Read, Write};

use wasip2::http::types::{
    Fields, IncomingBody, IncomingRequest, Method, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Handler;

impl wasip2::exports::http::incoming_handler::Guest for Handler {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        assert!(matches!(request.method(), Method::Post));

        let request_body = request.consume().unwrap();
        let mut input = request_body.stream().unwrap();
        let mut received = Vec::new();
        input.read_to_end(&mut received).unwrap();
        drop(input);
        let trailers = IncomingBody::finish(request_body);
        trailers.subscribe().block();
        let trailers = trailers.get().unwrap().unwrap().unwrap().unwrap();
        assert_eq!(trailers.get("x-request-trailer"), [b"preserved"]);
        assert_eq!(received, b"hello-hello-hello-hello-hello-hello-hello-hello");

        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(201).unwrap();
        let response_body = response.body().unwrap();
        ResponseOutparam::set(response_out, Ok(response));

        let mut output = response_body.write().unwrap();
        // Separate writes deliberately exceed Wasmtime's bounded output channel.
        for _ in 0..64 {
            output.write_all(b"world-world-").unwrap();
        }
        output.flush().unwrap();
        drop(output);
        let trailers = Fields::new();
        trailers.append("x-response-trailer", b"preserved").unwrap();
        trailers.append("x-response-trailer", b"also-preserved").unwrap();
        OutgoingBody::finish(response_body, Some(trailers)).unwrap();
    }
}

wasip2::http::proxy::export!(Handler);
