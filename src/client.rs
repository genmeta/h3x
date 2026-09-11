//! Initiating requests and receiving authenticated responses.
//! These roles apply per request, independently of the QUIC connection role.
use bytes::Bytes;
use http::StatusCode;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use crate::{
    ArcWndBuf, Error, Result,
    common::{
        self, Read, Write,
        message::{ArcMessage, Message, ReadBody, ReadStream, WriteResponse},
    },
    protocol::{
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers, qpack,
        qpack::WriteFieldSection,
        stream::{H3ReadStream, H3WriteStream},
    },
};

/// Outgoing request selected by body storage.
pub type Request<B = Bytes> = crate::common::request::Request<Write, B>;
/// Incoming response selected by the peer's body framing.
pub type Response = crate::common::Response<Read>;

/// Send one request and read its response on an existing bidirectional stream.
pub async fn request<RS, WS, R>(request: R, recv: RS, send: WS) -> Result<Response>
where
    RS: AsyncRead + Unpin + Send + 'static,
    WS: AsyncWrite + Unpin,
    R: Into<common::Request<Write>>,
{
    let sending = async move {
        match request.into() {
            common::Request::Bytes(request) => write_bytes_request(&request, send.into()).await,
            common::Request::Streaming(request) => {
                write_streaming_request(&request, send.into()).await
            }
        }
    };
    let (_, response) = tokio::try_join!(sending, read_response(recv.into()))?;
    Ok(response)
}

async fn write_bytes_request<WS: AsyncWrite + Unpin>(
    req: &Request<Bytes>,
    mut ws: H3WriteStream<WS>,
) -> Result<()> {
    let req: common::request::Request<Read, Bytes> = req.message.clone().into();
    let (mut fields, body) = {
        let message = req.message.0.lock().unwrap();
        let fields: Vec<_> = message
            .headers()
            .map(|(name, value)| qpack::Field {
                never_index: value.is_sensitive(),
                name: Bytes::copy_from_slice(name.as_bytes()),
                value: Bytes::copy_from_slice(value.as_bytes()),
            })
            .collect();
        (fields, message.body())
    };
    fields.sort_by_key(|field| !field.name.starts_with(b":"));
    let parts = headers::request_parts(fields.clone())?;
    if headers::content_length(&parts.headers)?.is_some_and(|length| length != body.len() as u64) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    // static QPACK only; dynamic compression requires connection encoder state.
    let mut field_section = Vec::new();
    field_section.put_field_section(fields)?;
    let field_section = Bytes::from(field_section);
    let mut frame = Vec::new();
    frame.put_frame(&Frame::<Headers>::new(Headers { field_section })?);
    ws.write_all(&frame).await?;
    if !body.is_empty() {
        frame.clear();
        frame.put_frame(&Frame::<Data>::new(Data(body.len()))?);
        ws.write_all(&frame).await?;
        ws.write_all(&body).await?;
    }
    ws.shutdown().await?;
    Ok(())
}

async fn write_streaming_request<WS: AsyncWrite + Unpin>(
    req: &Request<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
) -> Result<()> {
    let mut req: common::request::Request<Read, ArcWndBuf> = req.message.clone().into();
    let result = async {
        let mut fields: Vec<_> = req
            .message
            .0
            .lock()
            .unwrap()
            .headers()
            .map(|(name, value)| qpack::Field {
                never_index: value.is_sensitive(),
                name: Bytes::copy_from_slice(name.as_bytes()),
                value: Bytes::copy_from_slice(value.as_bytes()),
            })
            .collect();
        fields.sort_by_key(|field| !field.name.starts_with(b":"));
        let parts = headers::request_parts(fields.clone())?;
        let length = headers::content_length(&parts.headers)?;
        // static QPACK only; dynamic compression requires connection encoder state.
        let mut field_section = Vec::new();
        field_section.put_field_section(fields)?;
        let field_section = Bytes::from(field_section);
        let mut frame = Vec::new();
        frame.put_frame(&Frame::<Headers>::new(Headers { field_section })?);
        ws.write_all(&frame).await?;

        let mut buf = [0; frame::MAX_DATA_CHUNK];
        let mut sent = 0u64;
        loop {
            let count = req.read(&mut buf).await?;
            sent = sent
                .checked_add(count as u64)
                .ok_or(Error::H3_MESSAGE_ERROR)?;
            if length.is_some_and(|length| sent > length || (count == 0 && sent != length)) {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if count == 0 {
                ws.shutdown().await?;
                return Ok(());
            }
            frame.clear();
            frame.put_frame(&Frame::<Data>::new(Data(count))?);
            ws.write_all(&frame).await?;
            ws.write_all(&buf[..count]).await?;
        }
    }
    .await;
    if result.is_err() {
        // Wake a producer blocked on the bounded body when sending fails.
        req.stop().await;
    }
    result
}

/// Reads ordinary responses; HEAD and CONNECT semantics require request-method context.
async fn read_response<RS: AsyncRead + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
) -> Result<crate::common::Response<Read>> {
    let mut rs = BufReader::new(rs);
    let (parts, length) = loop {
        let H3Frame::Headers(frame) = be_frame(&mut rs).await? else {
            return Err(Error::H3_FRAME_UNEXPECTED);
        };
        // static QPACK only; dynamic references require connection decoder state.
        let (_, fields) = qpack::be_field_section(&frame.payload.field_section)?;
        let parts = headers::response_parts(fields)?;
        let length = headers::content_length(&parts.headers)?;
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if (parts.status.is_informational() || parts.status == StatusCode::NO_CONTENT)
            && length.is_some()
        {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if !parts.status.is_informational() {
            break (parts, length);
        }
    };
    let no_content = matches!(
        parts.status,
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    );
    let mut message = Message::<Bytes>::default();
    message.set_status(parts.status);
    for (name, value) in &parts.headers {
        message.set_header(name.clone(), value.clone());
    }
    if length.is_some() || no_content {
        let mut body = Vec::new();
        read_response_body(&mut rs, &mut body, length, no_content).await?;
        Ok(crate::common::Response::Bytes(
            ArcMessage::from(message.with_body(Bytes::from(body))).into(),
        ))
    } else {
        let mut body = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let response = ArcMessage::from(message.with_body(body.clone())).into();
        tokio::spawn(async move {
            if let Err(error) = read_response_body(&mut rs, &mut body, None, false).await {
                body.set_error(error);
            }
        });
        Ok(crate::common::Response::Streaming(response))
    }
}

async fn read_response_body<RS: AsyncBufRead + Unpin, WS: AsyncWrite + Unpin>(
    rs: &mut RS,
    body: &mut WS,
    mut remaining: Option<u64>,
    no_content: bool,
) -> Result<()> {
    if no_content {
        remaining = None;
    }
    let mut trailers = false;
    let mut buf = [0; frame::MAX_DATA_CHUNK];
    while !rs.fill_buf().await?.is_empty() {
        match be_frame(rs).await? {
            H3Frame::Data(frame) => {
                if trailers || no_content {
                    return Err(Error::H3_FRAME_UNEXPECTED);
                }
                let mut count = frame.length.into_u64();
                if let Some(left) = &mut remaining {
                    *left = left.checked_sub(count).ok_or(Error::H3_MESSAGE_ERROR)?;
                }
                while count != 0 {
                    let chunk = count.min(buf.len() as u64) as usize;
                    rs.read_exact(&mut buf[..chunk])
                        .await
                        .map_err(|_| Error::H3_FRAME_ERROR)?;
                    body.write_all(&buf[..chunk]).await?;
                    count -= chunk as u64;
                }
            }
            H3Frame::Headers(frame) => {
                if trailers || no_content {
                    return Err(Error::H3_FRAME_UNEXPECTED);
                }
                if remaining.is_some_and(|left| left != 0) {
                    return Err(Error::H3_MESSAGE_ERROR);
                }
                headers::trailer_fields(qpack::be_field_section(&frame.payload.field_section)?.1)?;
                trailers = true;
            }
            _ => {
                return Err(Error::H3_FRAME_UNEXPECTED);
            }
        }
    }
    if remaining.is_some_and(|left| left != 0) {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    body.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use http::{HeaderValue, Method, header};
    use tokio::io::{AsyncReadExt, duplex};

    use super::*;
    use crate::common::message::{ReadResponse, WriteRequest, WriteStream};

    fn be_request(input: &[u8]) -> Result<(&[u8], http::request::Parts)> {
        let (input, fields) = qpack::be_field_section(input)?;
        Ok((input, headers::request_parts(fields)?))
    }

    #[tokio::test]
    async fn request_frames_and_errors() {
        for (method, url, body) in [
            (
                Method::POST,
                "https://example.com/a?q=1",
                Bytes::from_static(b"hello"),
            ),
            (Method::GET, "https://example.com/", Bytes::new()),
            (Method::CONNECT, "example.com:443", Bytes::new()),
        ] {
            let req = Request::new(url, method.clone())
                .unwrap()
                .header(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"))
                .body(body.clone());
            // A tiny buffer forces partial writes and backpressure.
            let (writer, mut reader) = duplex(3);
            let (sent, received) = tokio::join!(write_bytes_request(&req, writer.into()), async {
                let mut received = Vec::new();
                reader.read_to_end(&mut received).await.unwrap();
                received
            });
            sent.unwrap();
            let mut input = received.as_slice();
            let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
                panic!("expected HEADERS")
            };
            let (_, parts) = be_request(&frame.payload.field_section).unwrap();
            assert_eq!(parts.method, method);
            assert_eq!(parts.uri.to_string(), url);
            assert_eq!(parts.headers[header::CONTENT_TYPE], "text/plain");
            if !body.is_empty() {
                let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
                    panic!("expected DATA")
                };
                assert_eq!(frame.length.into_u64(), body.len() as u64);
                assert_eq!(input, body.as_ref());
                input = &input[body.len()..];
            }
            assert!(input.is_empty());
        }
        let req = Request::<Bytes>::get("https://example.com/")
            .unwrap()
            .header(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        let mut output = Vec::new();
        assert_eq!(
            write_bytes_request(&req, (&mut output).into())
                .await
                .unwrap_err(),
            Error::H3_MESSAGE_ERROR
        );
        assert!(output.is_empty());
        let req = Request::<Bytes>::get("https://example.com/").unwrap();
        let (writer, reader) = duplex(3);
        drop(reader);
        assert_eq!(
            write_bytes_request(&req, writer.into()).await.unwrap_err(),
            Error::H3_INTERNAL_ERROR
        );
    }
    #[tokio::test]
    async fn streaming_request_frames_and_errors() {
        for (body, length, valid) in [
            (&b"hello"[..], None, true),
            (&b"hello"[..], Some("5"), true),
            (&b""[..], Some("0"), true),
            (&b"hello"[..], Some("2"), false),
            (&b"hello"[..], Some("6"), false),
            (&b"hello"[..], Some("invalid"), false),
        ] {
            let mut message = Message::<Bytes>::post("https://example.com/upload").unwrap();
            if let Some(length) = length {
                message.set_header(header::CONTENT_LENGTH, length.parse().unwrap());
            }
            let req = Request::from(ArcMessage::from(message.with_body(ArcWndBuf::new(2))));
            let mut producer = Request::from(req.message.clone());
            let (writer, mut reader) = duplex(3);
            let (sent, produced, received) = tokio::join!(
                write_streaming_request(&req, writer.into()),
                async {
                    let mut remaining = body;
                    while !remaining.is_empty() {
                        let count = producer.write(remaining).await?;
                        remaining = &remaining[count..];
                    }
                    producer.finish().await
                },
                async {
                    let mut bytes = Vec::new();
                    reader.read_to_end(&mut bytes).await.unwrap();
                    bytes
                }
            );
            if !valid {
                assert_eq!(sent.unwrap_err(), Error::H3_MESSAGE_ERROR);
                assert_eq!(
                    producer.write(b"x").await.unwrap_err(),
                    Error::H3_REQUEST_CANCELLED
                );
                continue;
            }
            sent.unwrap();
            produced.unwrap();
            let mut input = received.as_slice();
            let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
                panic!("expected HEADERS")
            };
            let (_, parts) = be_request(&frame.payload.field_section).unwrap();
            assert_eq!(parts.uri, "https://example.com/upload");
            let mut decoded = Vec::new();
            while !input.is_empty() {
                let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
                    panic!("expected DATA")
                };
                let count = frame.length.into_u64() as usize;
                assert!((1..=2).contains(&count));
                decoded.extend_from_slice(&input[..count]);
                input = &input[count..];
            }
            assert_eq!(decoded, body);
        }
        let req = Request::from(ArcMessage::from(
            Message::<Bytes>::post("https://example.com/")
                .unwrap()
                .with_body(ArcWndBuf::new(1)),
        ));
        let mut producer = Request::from(req.message.clone());
        let (writer, reader) = duplex(1);
        drop(reader);
        let (sent, produced) = tokio::join!(write_streaming_request(&req, writer.into()), async {
            producer.write(b"a").await?;
            producer.write(b"b").await
        });
        assert_eq!(sent.unwrap_err(), Error::H3_INTERNAL_ERROR);
        assert_eq!(produced.unwrap_err(), Error::H3_REQUEST_CANCELLED);
    }
    #[tokio::test]
    async fn response_content_length_and_streaming() {
        fn headers(output: &mut Vec<u8>, status: &'static str, length: Option<&'static str>) {
            let mut fields = vec![qpack::Field {
                never_index: false,
                name: Bytes::from_static(b":status"),
                value: Bytes::from_static(status.as_bytes()),
            }];
            if let Some(length) = length {
                fields.push(qpack::Field {
                    never_index: false,
                    name: Bytes::from_static(b"content-length"),
                    value: Bytes::from_static(length.as_bytes()),
                });
            }
            let mut field_section = Vec::new();
            field_section.put_field_section(fields).unwrap();
            let field_section = Bytes::from(field_section);
            output.put_frame(&Frame::<Headers>::new(Headers { field_section }).unwrap());
        }
        for length in [Some("5"), None] {
            let mut encoded = Vec::new();
            headers(&mut encoded, "103", None);
            headers(&mut encoded, "200", length);
            for chunk in [&b"he"[..], &b"llo"[..]] {
                encoded.put_frame(&Frame::<Data>::new(Data(chunk.len())).unwrap());
                encoded.extend_from_slice(chunk);
            }
            let (mut writer, reader) = duplex(2);
            let ((), ()) = tokio::join!(
                async {
                    writer.write_all(&encoded).await.unwrap();
                    writer.shutdown().await.unwrap();
                },
                async {
                    match read_response(reader.into()).await.unwrap() {
                        crate::common::Response::Bytes(response) => {
                            assert!(length.is_some());
                            assert_eq!(response.status(), StatusCode::OK);
                            assert_eq!(response.body(), "hello");
                        }
                        crate::common::Response::Streaming(mut response) => {
                            assert!(length.is_none());
                            assert_eq!(response.status(), StatusCode::OK);
                            let mut buf = [0; 8];
                            assert_eq!(response.read_all(&mut buf).await.unwrap(), 5);
                            assert_eq!(&buf[..5], b"hello");
                        }
                    }
                }
            );
        }
        for length in ["0", "2", "6", "invalid"] {
            let mut encoded = Vec::new();
            headers(&mut encoded, "200", Some(length));
            encoded.put_frame(&Frame::<Data>::new(Data(5)).unwrap());
            encoded.extend_from_slice(b"hello");
            let result = read_response(Cursor::new(encoded).into()).await;
            assert!(matches!(result, Err(Error::H3_MESSAGE_ERROR)));
        }
        for (status, length) in [("200", Some("0")), ("204", None), ("304", Some("100"))] {
            let mut encoded = Vec::new();
            headers(&mut encoded, status, length);
            let crate::common::Response::Bytes(response) =
                read_response(Cursor::new(encoded).into()).await.unwrap()
            else {
                panic!("expected empty fixed body")
            };
            assert!(response.body().is_empty());
        }
        // Unknown-length responses return after HEADERS, before body bytes arrive.
        let (mut writer, reader) = duplex(1024);
        let mut encoded = Vec::new();
        headers(&mut encoded, "200", None);
        writer.write_all(&encoded).await.unwrap();
        let crate::common::Response::Streaming(mut response) =
            read_response(reader.into()).await.unwrap()
        else {
            panic!("expected streaming")
        };
        encoded.clear();
        encoded.put_frame(&Frame::<Data>::new(Data(5)).unwrap());
        encoded.extend_from_slice(b"hi");
        writer.write_all(&encoded).await.unwrap();
        writer.shutdown().await.unwrap();
        assert_eq!(
            response.read(&mut [0; 5]).await.unwrap_err(),
            Error::H3_FRAME_ERROR
        );

        let mut encoded = Vec::new();
        headers(&mut encoded, "200", Some("0"));
        encoded.push(0x40); // Truncated frame type is not a clean EOF.
        assert!(matches!(
            read_response(Cursor::new(encoded).into()).await,
            Err(Error::H3_FRAME_ERROR)
        ));
    }

    #[tokio::test]
    async fn body_trailers_enforce_order_and_content_length() {
        let mut trailers = Vec::new();
        let mut field_section = Vec::new();
        field_section
            .put_field_section(vec![qpack::Field {
                never_index: false,
                name: Bytes::from_static(b"x-checksum"),
                value: Bytes::from_static(b"ok"),
            }])
            .unwrap();
        trailers.put_frame(
            &Frame::new(Headers {
                field_section: field_section.into(),
            })
            .unwrap(),
        );
        for (suffix, length, expected) in [
            (&[][..], None, Ok(())),
            (&[][..], Some(0), Ok(())),
            (&[][..], Some(1), Err(Error::H3_MESSAGE_ERROR)),
            (trailers.as_slice(), None, Err(Error::H3_FRAME_UNEXPECTED)),
            (&[0, 0][..], None, Err(Error::H3_FRAME_UNEXPECTED)),
        ] {
            let encoded = [trailers.as_slice(), suffix].concat();
            let mut input = encoded.as_slice();
            let mut body = Vec::new();
            assert_eq!(
                read_response_body(&mut input, &mut body, length, false).await,
                expected
            );
            assert!(body.is_empty());
        }
        let mut input = &[7, 1, 0][..]; // GOAWAY is forbidden in a message body.
        let mut body = Vec::new();
        let length = None;
        assert_eq!(
            read_response_body(&mut input, &mut body, length, false).await,
            Err(Error::H3_FRAME_UNEXPECTED)
        );
    }
}
