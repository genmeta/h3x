use bytes::Bytes;

use super::*;

fn fields(values: &[(&'static str, &'static str)]) -> Vec<Field> {
    values
        .iter()
        .map(|(name, value)| Field {
            name: Bytes::from_static(name.as_bytes()),
            value: Bytes::from_static(value.as_bytes()),
            never_index: false,
        })
        .collect()
}

fn parse(values: &[(&'static str, &'static str)]) -> Result<Request<Read>> {
    Request::from_fields(fields(values), ArcWndBuf::new(1))
}

#[test]
fn rejects_malformed_request_pseudo_headers() {
    for values in [
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
            (":status", "200"),
        ][..],
        &[
            (":method", "GET"),
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
        ],
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            ("x-tag", "a"),
            (":path", "/"),
        ],
        &[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "example.com"),
            (":path", "/"),
            ("X-Tag", "a"),
        ],
    ] {
        assert!(matches!(
            parse(values),
            Err(error) if error.code == ErrorCode::MessageError
        ));
    }
}

#[test]
fn accepts_flexible_connect_pseudo_headers() {
    let connect = parse(&[(":method", "CONNECT")]).unwrap();
    assert_eq!(connect.authority(), "");

    let connect = parse(&[(":method", "CONNECT"), (":authority", "example.com:443")]).unwrap();
    assert_eq!(connect.authority(), "example.com:443");
    assert_eq!(connect.scheme(), "");
    assert_eq!(connect.path(), "");

    let extended = parse(&[
        (":method", "CONNECT"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/chat"),
        (":protocol", "websocket"),
    ])
    .unwrap();
    assert_eq!(extended.protocol(), Some("websocket"));

    parse(&[
        (":method", "CONNECT"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/"),
    ])
    .unwrap();
    parse(&[
        (":method", "CONNECT"),
        (":authority", "example.com"),
        (":protocol", "websocket"),
    ])
    .unwrap();
}
