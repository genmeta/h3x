//! Incoming requests and responses on the original stream.

use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
};

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::{
    ArcWndBuf, Error, Result,
    common::{
        self, Read, Write,
        message::{ArcMessage, Message, ReadBody},
    },
    protocol::{
        body::{self, BodyMode},
        frame::{self, Data, Frame, H3Frame, Headers, Write as _, be_frame},
        headers,
        qpack::Qpack,
        stream::{H3ReadStream, H3WriteStream},
    },
};

pub type Request = crate::common::Request<Read>;
pub type Response<B = Bytes> = crate::common::response::Response<Write, B>;

/// Send one response on the accepted request's matching send stream.
pub async fn respond<WS, R>(response: R, send: H3WriteStream<WS>, qpack: Arc<Qpack>) -> Result<()>
where
    WS: AsyncWrite + Unpin,
    R: Into<common::Response<Write>>,
{
    let response = response.into();
    tokio::select! {
        biased;
        error = qpack.terminated() => Err(error),
        result = async {
            match response {
                common::Response::Bytes(response) => {
                    write_bytes_response(&response, send, &qpack).await
                }
                common::Response::Streaming(response) => {
                    write_streaming_response(&response, send, &qpack).await
                }
            }
        } => result,
    }
}

/// Read an HTTP request using the receive stream's ID and explicit QPACK.
pub async fn accept<RS: AsyncRead + Unpin + Send + 'static>(
    rs: H3ReadStream<RS>,
    qpack: Arc<Qpack>,
) -> Result<crate::common::Request<Read>> {
    let stream_id = rs.stream_id();
    let mut rs = BufReader::new(rs);
    let (message, length) = async {
        let H3Frame::Headers(frame) = be_frame(&mut rs).await? else {
            return Err(Error::H3_FRAME_UNEXPECTED);
        };
        let fields = frame.decode(&qpack, stream_id).await?;
        let parts = headers::request_parts(fields)?;
        let length = headers::content_length(&parts.headers)?;

        let mut message = Message::<Bytes>::default();
        for (name, value) in [
            (":method", Some(parts.method.as_str())),
            (":authority", parts.uri.authority().map(|value| value.as_str())),
            (":scheme", parts.uri.scheme_str()),
            (":path", parts.uri.path_and_query().map(|value| value.as_str())),
        ] {
            if let Some(value) = value {
                message.set_pseudo_header(name, HeaderValue::from_str(value).unwrap());
            }
        }
        for (name, value) in &parts.headers {
            message.set_header(name.clone(), value.clone());
        }
        Ok((message, length))
    }
    .await
    .inspect_err(|error| {
        let _ = qpack.cancel(stream_id);
        qpack.on_error(*error);
    })?;
    let mode = BodyMode::Allowed {
        content_length: length,
    };
    if !mode.streaming() {
        let mut body = Vec::new();
        body::read_body(&mut rs, &mut body, mode, &qpack)
            .await
            .inspect_err(|error| {
                let _ = qpack.cancel(stream_id);
                qpack.on_error(*error);
            })?;
        let request: common::request::Request<Read, _> =
            ArcMessage::from(message.with_body(Bytes::from(body))).into();
        Ok(common::Request::Bytes(request))
    } else {
        let mut body = ArcWndBuf::new(frame::MAX_DATA_CHUNK);
        let request: common::request::Request<Read, _> =
            ArcMessage::from(message.with_body(body.clone().cancel_on_drop())).into();
        tokio::spawn(async move {
            let signal = body.clone();
            let result = {
                let receive = body::read_body(&mut rs, &mut body, mode, &qpack);
                tokio::pin!(receive);
                tokio::select! {
                    biased;
                    error = qpack.terminated() => Err(error),
                    result = poll_fn(|cx| {
                        if let Err(error) = signal.poll_error(cx) {
                            return Poll::Ready(Err(error));
                        }
                        receive.as_mut().poll(cx)
                    }) => result,
                }
            };
            match result {
                Ok(()) => {}
                Err(error) => {
                    let _ = qpack.cancel(stream_id);
                    qpack.on_error(error);
                    body.set_error(error);
                }
            }
        });
        Ok(crate::common::Request::Streaming(request))
    }
}

/// Writes an ordinary response.
async fn write_bytes_response<WS: AsyncWrite + Unpin>(
    response: &Response<Bytes>,
    mut ws: H3WriteStream<WS>,
    qpack: &Qpack,
) -> Result<()> {
    let (fields, mode, body) = {
        let message = response.message.0.lock().unwrap();
        let fields = message.fields();
        let parts = headers::response_parts(fields.clone())?;
        let length = headers::content_length(&parts.headers)?;
        if parts.status.is_informational() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if parts.status == StatusCode::NO_CONTENT && length.is_some() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::response(None, parts.status, length);
        (fields, mode, message.body())
    };
    if mode.is_forbidden() && !body.is_empty() {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    if mode
        .content_length()
        .is_some_and(|length| length != body.len() as u64)
    {
        return Err(Error::H3_MESSAGE_ERROR);
    }
    let mut frame = Vec::new();
    frame.put_frame(&Frame::<Headers>::encode(fields, qpack, ws.stream_id())?);
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

/// Writes a streaming response; HEAD and CONNECT semantics require request-method input.
async fn write_streaming_response<WS: AsyncWrite + Unpin>(
    response: &Response<ArcWndBuf>,
    mut ws: H3WriteStream<WS>,
    qpack: &Qpack,
) -> Result<()> {
    let mut body = response
        .message
        .0
        .lock()
        .unwrap()
        .body_stream()
        .cancel_on_drop();
    let (fields, mode) = {
        let message = response.message.0.lock().unwrap();
        let fields = message.fields();
        let parts = headers::response_parts(fields.clone())?;
        let length = headers::content_length(&parts.headers)?;
        if parts.status.is_informational() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        if parts.status == StatusCode::NO_CONTENT && length.is_some() {
            return Err(Error::H3_MESSAGE_ERROR);
        }
        let mode = BodyMode::response(None, parts.status, length);
        (fields, mode)
    };
    let mut frame = Vec::new();
    frame.put_frame(&Frame::<Headers>::encode(fields, qpack, ws.stream_id())?);
    ws.write_all(&frame).await?;
    body::write_body(&mut body, &mut ws, mode).await?;
    body.complete();
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{ReadStream, protocol::qpack};
    async fn write_bytes_response<W: AsyncWrite + Unpin>(
        response: &Response<Bytes>,
        send: W,
    ) -> Result<()> {
        super::write_bytes_response(response, H3WriteStream::new(0, send), &Qpack::default()).await
    }
    async fn write_streaming_response<W: AsyncWrite + Unpin>(
        response: &Response<ArcWndBuf>,
        send: W,
    ) -> Result<()> {
        super::write_streaming_response(response, H3WriteStream::new(0, send), &Qpack::default())
            .await
    }
    async fn read_request<R: AsyncRead + Unpin + Send + 'static>(recv: R) -> Result<Request> {
        super::accept(H3ReadStream::new(0, recv), Arc::new(Qpack::default())).await
    }

    use std::io::Cursor;

    use http::{Method, header};
    use tokio::io::duplex;

    use super::*;
    use crate::{
        common::message::{
            ReadRequest, ReadResponse, WriteBody, WriteRequest, WriteResponse, WriteStream,
        },
        protocol::qpack::WriteFieldSection,
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
            read_request(Cursor::new(request_frames(b"hello", Some("5"))))
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
            read_request(Cursor::new(request_frames(b"streaming", None)))
                .await
                .unwrap()
        else {
            panic!("expected streaming request")
        };
        let mut body = [0; 9];
        assert_eq!(request.read_all(&mut body).await.unwrap(), body.len());
        assert_eq!(&body, b"streaming");

        assert_eq!(
            read_request(Cursor::new(request_frames(b"short", Some("6"))))
                .await
                .err()
                .unwrap(),
            Error::H3_MESSAGE_ERROR
        );
        let mut encoded = request_frames(b"short", None);
        encoded.pop();
        let crate::common::Request::Streaming(mut request) =
            read_request(Cursor::new(encoded)).await.unwrap()
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
        write_bytes_response(&fixed_response, &mut encoded)
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
        let (sent, produced) =
            tokio::join!(write_streaming_response(&response, &mut encoded), async {
                let mut body = &b"stream"[..];
                while !body.is_empty() {
                    let count = producer.write(body).await?;
                    body = &body[count..];
                }
                producer.finish().await
            });
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
            write_bytes_response(&fixed_response, &mut output)
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
        let (sent, produced) = tokio::join!(write_streaming_response(&response, writer), async {
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
                body::read_body(
                    &mut BufReader::new(H3ReadStream::new(0, &mut input)),
                    &mut body,
                    BodyMode::Allowed {
                        content_length: length
                    },
                    &Qpack::default()
                )
                .await,
                expected
            );
            assert!(body.is_empty());
        }
        let mut input = &[7, 1, 0][..]; // GOAWAY is forbidden in a message body.
        let mut body = Vec::new();
        let length = None;
        assert_eq!(
            body::read_body(
                &mut BufReader::new(H3ReadStream::new(0, &mut input)),
                &mut body,
                BodyMode::Allowed {
                    content_length: length
                },
                &Qpack::default()
            )
            .await,
            Err(Error::H3_FRAME_UNEXPECTED)
        );
    }
    #[tokio::test]
    async fn dropping_streaming_request_stops_a_pump_waiting_on_network() {
        let (mut send, recv) = duplex(64);
        send.write_all(&request_frames(b"", None)).await.unwrap();
        let request = super::accept(H3ReadStream::new(4, recv), Arc::new(Qpack::default()))
            .await
            .unwrap();
        assert!(matches!(&request, Request::Streaming(_)));
        tokio::task::yield_now().await; // Let the receive pump wait for another frame.
        drop(request);
        tokio::task::yield_now().await;
        assert!(send.write_all(b"x").await.is_err());
    }
}
