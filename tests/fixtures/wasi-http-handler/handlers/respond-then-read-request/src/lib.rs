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

        let headers = Fields::new();
        headers
            .append("x-handler-mode", b"respond-then-read-request")
            .unwrap();
        let response = OutgoingResponse::new(headers);
        response.set_status_code(201).unwrap();
        let response_body = response.body().unwrap();

        // Commit the status and headers while the request body is still open.
        ResponseOutparam::set(response_out, Ok(response));

        // The response body is intentionally held back until the request body and
        // its trailers have been consumed completely.
        let mut received = Vec::new();
        input.read_to_end(&mut received).unwrap();
        drop(input);
        let trailers = IncomingBody::finish(request_body);
        trailers.subscribe().block();
        let trailers = trailers.get().unwrap().unwrap().unwrap().unwrap();
        assert_eq!(trailers.get("x-request-trailer"), [b"preserved"]);

        let mut output = response_body.write().unwrap();
        output.write_all(&received).unwrap();
        output.flush().unwrap();
        drop(output);
        let trailers = Fields::new();
        trailers
            .append("x-response-trailer", b"request-consumed")
            .unwrap();
        OutgoingBody::finish(response_body, Some(trailers)).unwrap();
    }
}

wasip2::http::proxy::export!(Handler);
