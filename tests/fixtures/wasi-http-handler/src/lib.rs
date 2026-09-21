use std::io::{Read, Write};

use wasip2::http::types::{
    Fields, IncomingBody, IncomingRequest, Method, OutgoingBody, OutgoingResponse, ResponseOutparam,
};

struct Handler;

impl wasip2::exports::http::incoming_handler::Guest for Handler {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        assert!(matches!(request.method(), Method::Post));

        let body = request.consume().unwrap();
        let mut input = body.stream().unwrap();
        let mut request_body = Vec::new();
        input.read_to_end(&mut request_body).unwrap();
        drop(input);
        let trailers = IncomingBody::finish(body);
        trailers.subscribe().block();
        let trailers = trailers.get().unwrap().unwrap().unwrap().unwrap();
        assert_eq!(trailers.get("x-request-trailer"), [b"preserved"]);
        assert_eq!(
            request_body,
            b"hello-hello-hello-hello-hello-hello-hello-hello"
        );

        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(201).unwrap();
        let body = response.body().unwrap();
        ResponseOutparam::set(response_out, Ok(response));

        let mut output = body.write().unwrap();
        output
            .write_all(b"world-world-world-world-world-world-world-world")
            .unwrap();
        output.flush().unwrap();
        drop(output);
        let trailers = Fields::new();
        trailers
            .append("x-response-trailer", b"preserved")
            .unwrap();
        OutgoingBody::finish(body, Some(trailers)).unwrap();
    }
}

wasip2::http::proxy::export!(Handler);
