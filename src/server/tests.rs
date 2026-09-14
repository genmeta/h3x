use std::io::Cursor;

use http::{Method, header};
use tokio::io::duplex;

use super::*;
use crate::{
    ReadStream,
    common::message::{
        ReadRequest, ReadResponse, WriteBody, WriteRequest, WriteResponse, WriteStream,
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
