use std::{io::Cursor, sync::Arc};

use http::{HeaderValue, Method, header};
use tokio::io::duplex;

use super::*;
use crate::{
    ReadStream,
    common::message::{
        ReadBody, ReadRequest, ReadResponse, WriteBody, WriteRequest, WriteResponse, WriteStream,
    },
    protocol::qpack::{self, WriteFieldSection},
};

mod lifecycle;
mod request;
mod response;

fn request_frames(body: &[u8], length: Option<&'static str>) -> Vec<u8> {
    let mut fields = vec![
        qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":method"),
            value: Bytes::from_static(b"POST"),
        },
        qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":scheme"),
            value: Bytes::from_static(b"https"),
        },
        qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":authority"),
            value: Bytes::from_static(b"example.com"),
        },
        qpack::Field {
            never_index: false,
            name: Bytes::from_static(b":path"),
            value: Bytes::from_static(b"/echo?q=1"),
        },
    ];
    if let Some(length) = length {
        fields.push(qpack::Field {
            never_index: false,
            name: Bytes::from_static(b"content-length"),
            value: Bytes::from_static(length.as_bytes()),
        });
    }
    let mut encoded = Vec::new();
    let mut field_section = Vec::new();
    field_section.put_field_section(fields).unwrap();
    let field_section = Bytes::from(field_section);
    encoded.put_frame(&Frame::<Headers>::new(Headers { field_section }).unwrap());
    if !body.is_empty() {
        encoded.put_frame(&Frame::<Data>::new(Data(body.len())).unwrap());
        encoded.extend_from_slice(body);
    }
    encoded
}

use super::read_request as accept;
use crate::common::message::ArcMessage;
/// Send one response on the accepted request's matching send stream.
///
/// For streaming responses, retain a producer clone until it finishes or resets
/// the body. Dropping the last unfinished producer cancels sending.
///
/// `request_method` must be the original request's method so HEAD responses can
/// preserve `Content-Length` without sending a body.
/// Applications finish or reset streaming bodies explicitly.
fn respond<WS, R>(
    response: R,
    send: H3WriteStream<WS>,
    qpack: ArcQpack,
    request_method: &Method,
) -> impl Future<Output = Result<()>>
where
    WS: qrecovery::send::CancelStream + AsyncWrite + Unpin,
    R: Into<common::Response<Write>>,
{
    let response = response.into();

    async move {
        match response {
            common::Response::Bytes(response) => {
                write_bytes_response(response, send, qpack, request_method).await
            }
            common::Response::Streaming(response) => {
                write_streaming_response(response, send, qpack, request_method).await
            }
        }
    }
}
