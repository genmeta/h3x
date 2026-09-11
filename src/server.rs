//! Incoming requests and responses on the original stream.

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use crate::{
    ArcWndBuf, Error, Result,
    common::{
        self, Read, Write,
        message::{ArcMessage, Message, ReadBody, ReadStream},
    },
    protocol::{
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers, qpack,
        qpack::WriteFieldSection,
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Parse one request from an accepted stream.
pub async fn accept<RS>(recv: RS) -> Result<Request>
where
    RS: AsyncRead + Unpin + Send + 'static,
{
    read_request(recv.into()).await
}

/// Send one response on the accepted request's matching send stream.
pub async fn respond<WS, R>(response: R, send: WS) -> Result<()>
where
    WS: AsyncWrite + Unpin,
    R: Into<common::Response<Write>>,
{
    match response.into() {
        common::Response::Bytes(response) => write_bytes_response(&response, send.into()).await,
        common::Response::Streaming(response) => {
            write_streaming_response(&response, send.into()).await
        }
    }
}

async fn read_request<RS: AsyncRead + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
) -> Result<crate::common::Request<Read>> {
    let mut rs = BufReader::new(rs);
    let (message, length) = read_request_head(&mut rs).await?;
    if length.is_some() {
        let mut body = Vec::new();
        read_request_body(&mut rs, &mut body, length).await?;
        Ok(crate::common::Request::Bytes(
            ArcMessage::from(message.with_body(Bytes::from(body))).into(),
        ))
    } else {
        let mut body = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let request = ArcMessage::from(message.with_body(body.clone())).into();
        tokio::spawn(async move {
            if let Err(error) = read_request_body(&mut rs, &mut body, None).await {
                body.set_error(error);
            }
        });
        Ok(crate::common::Request::Streaming(request))
    }
}

async fn read_request_head<RS: AsyncBufRead + Unpin>(
    rs: &mut RS,
) -> Result<(Message<Bytes>, Option<u64>)> {
    let H3Frame::Headers(frame) = be_frame(rs).await? else {
        return Err(Error::H3_FRAME_UNEXPECTED);
    };
    // static QPACK only; dynamic references require connection decoder state.
    let (_, fields) = qpack::be_field_section(&frame.payload.field_section)?;
    let parts = headers::request_parts(fields)?;
    let length = headers::content_length(&parts.headers)?;

    let mut message = Message::<Bytes>::default();
    message.set_pseudo_header(
        ":method",
        HeaderValue::from_bytes(parts.method.as_str().as_bytes()).unwrap(),
    );
    if let Some(value) = parts.uri.authority() {
        message.set_pseudo_header(
            ":authority",
            HeaderValue::from_bytes(value.as_str().as_bytes()).unwrap(),
        );
    }
    if let Some(value) = parts.uri.scheme_str() {
        message.set_pseudo_header(
            ":scheme",
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
    }
    if let Some(value) = parts.uri.path_and_query() {
        message.set_pseudo_header(
            ":path",
            HeaderValue::from_bytes(value.as_str().as_bytes()).unwrap(),
        );
    }
    for (name, value) in &parts.headers {
        message.set_header(name.clone(), value.clone());
    }
    Ok((message, length))
}

async fn read_request_body<RS: AsyncBufRead + Unpin, WS: AsyncWrite + Unpin>(
    rs: &mut RS,
    body: &mut WS,
    mut remaining: Option<u64>,
) -> Result<()> {
    let mut trailers = false;
    let mut buf = [0; frame::MAX_DATA_CHUNK];
    while !rs.fill_buf().await?.is_empty() {
        match be_frame(rs).await? {
            H3Frame::Data(frame) => {
                if trailers {
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
                if trailers {
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

/// Writes an ordinary response.
async fn write_bytes_response<WS: AsyncWrite + Unpin>(
    response: &Response<Bytes>,
    mut ws: H3WriteStream<WS>,
) -> Result<()> {
    let response: common::response::Response<Read, Bytes> = response.message.clone().into();
    let (fields, length, no_content, body) = {
        let message = response.message.0.lock().unwrap();
        let (fields, length, no_content) = response_head(&message)?;
        (fields, length, no_content, message.body())
    };
    if no_content && !body.is_empty() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    if !no_content && length.is_some_and(|length| length != body.len() as u64) {
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

/// Writes a streaming response; HEAD and CONNECT semantics require request-method context.
async fn write_streaming_response<WS: AsyncWrite + Unpin>(
    response: &Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
) -> Result<()> {
    let mut response: common::response::Response<Read, ArcWndBuf> = response.message.clone().into();
    let result = async {
        let (fields, length, no_content) = response_head(&response.message.0.lock().unwrap())?;
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
            let count = response.read(&mut buf).await?;
            sent = sent
                .checked_add(count as u64)
                .ok_or(Error::H3_MESSAGE_ERROR)?;
            if no_content && count != 0 {
                return Err(Error::H3_MESSAGE_ERROR);
            }
            if !no_content
                && length.is_some_and(|length| sent > length || (count == 0 && sent != length))
            {
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
        response.stop().await;
    }
    result
}

fn response_head<B>(message: &Message<B>) -> Result<(Vec<qpack::Field>, Option<u64>, bool)> {
    let mut fields: Vec<_> = message
        .headers()
        .map(|(name, value)| qpack::Field {
            never_index: value.is_sensitive(),
            name: Bytes::copy_from_slice(name.as_bytes()),
            value: Bytes::copy_from_slice(value.as_bytes()),
        })
        .collect();
    fields.sort_by_key(|field| !field.name.starts_with(b":"));
    let parts = headers::response_parts(fields.clone())?;
    let length = headers::content_length(&parts.headers)?;
    if parts.status.is_informational() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    if parts.status == StatusCode::NO_CONTENT && length.is_some() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let no_content = matches!(
        parts.status,
        StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED
    );
    Ok((fields, length, no_content))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use http::{Method, header};
    use tokio::io::duplex;

    use super::*;
    use crate::common::message::{
        ReadRequest, ReadResponse, WriteBody, WriteRequest, WriteResponse, WriteStream,
    };

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

    #[tokio::test]
    async fn server_views_share_buffered_and_streaming_messages() {
        let message = Message::<Bytes>::post("https://example.com/echo?q=1").unwrap();
        let request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
        let mut incoming = common::request::Request::<Write, _>::from(request.message.clone());
        incoming.set_body(Bytes::from_static(b"request"));
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.authority(), "example.com");
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.path(), "/echo?q=1");
        assert_eq!(request.body(), Bytes::from_static(b"request"));

        let mut response = Response::default();
        let outgoing = common::response::Response::<Read, _>::from(response.message.clone());
        response
            .set_status(StatusCode::CREATED)
            .set_body(request.body());
        assert_eq!(outgoing.status(), StatusCode::CREATED);
        assert_eq!(outgoing.body(), Bytes::from_static(b"request"));

        let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(2));
        let mut request = common::request::Request::<Read, _>::from(ArcMessage::from(message));
        let mut incoming = common::request::Request::<Write, _>::from(request.message.clone());
        let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(2));
        let mut response = Response::from(ArcMessage::from(message));
        let mut outgoing = common::response::Response::<Read, _>::from(response.message.clone());
        response.set_status(StatusCode::OK);
        let ((), (), ()) = tokio::join!(
            async {
                assert_eq!(incoming.write(b"ping").await.unwrap(), 2);
                assert_eq!(incoming.write(b"ng").await.unwrap(), 2);
                incoming.finish().await.unwrap();
            },
            async {
                let mut buf = [0; 2];
                while request.read_all(&mut buf).await.unwrap() != 0 {
                    assert_eq!(response.write(buf).await.unwrap(), 2);
                }
                response.finish().await.unwrap();
            },
            async {
                let mut buf = [0; 4];
                assert_eq!(outgoing.read_all(&mut buf).await.unwrap(), 4);
                assert_eq!(&buf, b"ping");
                assert_eq!(outgoing.read(&mut buf).await.unwrap(), 0);
                assert_eq!(outgoing.status(), StatusCode::OK);
            }
        );
        request.stop().await;
        assert_eq!(
            incoming.write(b"x").await.unwrap_err(),
            Error::H3_REQUEST_CANCELLED
        );
        response.reset().await.unwrap();
        assert_eq!(
            outgoing.read(&mut [0]).await.unwrap_err(),
            Error::H3_REQUEST_CANCELLED
        );
    }

    #[tokio::test]
    async fn reads_buffered_and_streaming_request_frames() {
        let crate::common::Request::Bytes(request) =
            read_request(Cursor::new(request_frames(b"hello", Some("5"))).into())
                .await
                .unwrap()
        else {
            panic!("expected bytes request")
        };
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.authority(), "example.com");
        assert_eq!(request.scheme(), "https");
        assert_eq!(request.path(), "/echo?q=1");
        assert_eq!(request.body(), "hello");

        let crate::common::Request::Streaming(mut request) =
            read_request(Cursor::new(request_frames(b"streaming", None)).into())
                .await
                .unwrap()
        else {
            panic!("expected streaming request")
        };
        let mut body = [0; 9];
        assert_eq!(request.read_all(&mut body).await.unwrap(), body.len());
        assert_eq!(&body, b"streaming");

        assert_eq!(
            read_request(Cursor::new(request_frames(b"short", Some("6"))).into())
                .await
                .err()
                .unwrap(),
            Error::H3_MESSAGE_ERROR
        );
        let mut encoded = request_frames(b"short", None);
        encoded.pop();
        let crate::common::Request::Streaming(mut request) =
            read_request(Cursor::new(encoded).into()).await.unwrap()
        else {
            panic!("expected streaming request")
        };
        assert_eq!(
            request.read_all(&mut [0; 5]).await.unwrap_err(),
            Error::H3_FRAME_ERROR
        );
    }

    #[tokio::test]
    async fn writes_buffered_and_streaming_response_frames() {
        let mut fixed_response = Response::default();
        fixed_response
            .set_status(StatusCode::CREATED)
            .set_body(Bytes::from_static(b"hello"));
        fixed_response
            .message
            .0
            .lock()
            .unwrap()
            .set_header(header::CONTENT_LENGTH, HeaderValue::from_static("5"));
        let mut encoded = Vec::new();
        write_bytes_response(&fixed_response, (&mut encoded).into())
            .await
            .unwrap();
        let mut input = encoded.as_slice();
        let H3Frame::Headers(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS")
        };
        assert_eq!(
            headers::response_parts(
                qpack::be_field_section(&frame.payload.field_section)
                    .unwrap()
                    .1
            )
            .unwrap()
            .status,
            StatusCode::CREATED
        );
        let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
            panic!("expected DATA")
        };
        assert_eq!(frame.length.into_u64(), 5);
        assert_eq!(input, b"hello");

        let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(2));
        let mut response = Response::from(ArcMessage::from(message));
        response.set_status(StatusCode::OK);
        let mut producer = Response::from(response.message.clone());
        let mut encoded = Vec::new();
        let (sent, produced) = tokio::join!(
            write_streaming_response(&response, (&mut encoded).into()),
            async {
                let mut body = &b"stream"[..];
                while !body.is_empty() {
                    let count = producer.write(body).await?;
                    body = &body[count..];
                }
                producer.finish().await
            }
        );
        sent.unwrap();
        produced.unwrap();
        let mut input = encoded.as_slice();
        let H3Frame::Headers(_) = be_frame(&mut input).await.unwrap() else {
            panic!("expected HEADERS")
        };
        let mut body = Vec::new();
        while !input.is_empty() {
            let H3Frame::Data(frame) = be_frame(&mut input).await.unwrap() else {
                panic!("expected DATA")
            };
            let count = frame.length.into_u64() as usize;
            body.extend_from_slice(&input[..count]);
            input = &input[count..];
        }
        assert_eq!(body, b"stream");

        fixed_response
            .message
            .0
            .lock()
            .unwrap()
            .set_header(header::CONTENT_LENGTH, HeaderValue::from_static("1"));
        let mut output = Vec::new();
        assert_eq!(
            write_bytes_response(&fixed_response, (&mut output).into())
                .await
                .unwrap_err(),
            Error::H3_MESSAGE_ERROR
        );
        assert!(output.is_empty());

        let message = Message::<Bytes>::default().with_body(ArcWndBuf::new(1));
        let mut response = Response::from(ArcMessage::from(message));
        response.set_status(StatusCode::OK);
        let mut producer = Response::from(response.message.clone());
        let (writer, reader) = duplex(1);
        drop(reader);
        let (sent, produced) =
            tokio::join!(write_streaming_response(&response, writer.into()), async {
                producer.write(b"a").await?;
                producer.write(b"b").await
            });
        assert_eq!(sent.unwrap_err(), Error::H3_INTERNAL_ERROR);
        assert_eq!(produced.unwrap_err(), Error::H3_REQUEST_CANCELLED);
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
                read_request_body(&mut input, &mut body, length).await,
                expected
            );
            assert!(body.is_empty());
        }
        let mut input = &[7, 1, 0][..]; // GOAWAY is forbidden in a message body.
        let mut body = Vec::new();
        let length = None;
        assert_eq!(
            read_request_body(&mut input, &mut body, length).await,
            Err(Error::H3_FRAME_UNEXPECTED)
        );
    }
}
