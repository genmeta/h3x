use std::io::Write;

use wasip2::http::types::{Fields, IncomingRequest, Method, OutgoingResponse, ResponseOutparam};

struct Handler;

impl wasip2::exports::http::incoming_handler::Guest for Handler {
    fn handle(request: IncomingRequest, response_out: ResponseOutparam) {
        assert!(matches!(request.method(), Method::Post));

        let response = OutgoingResponse::new(Fields::new());
        response.set_status_code(201).unwrap();
        let response_body = response.body().unwrap();
        ResponseOutparam::set(response_out, Ok(response));

        let mut output = response_body.write().unwrap();
        loop {
            if output.write_all(b"world-world-").is_err() {
                return;
            }
        }
    }
}

wasip2::http::proxy::export!(Handler);
