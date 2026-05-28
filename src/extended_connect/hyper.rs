use std::sync::Arc;

use bytes::Bytes;
use http::{Method, StatusCode};
use http_body::Body;
use http_body_util::Empty;
use snafu::{OptionExt, ResultExt, Snafu, ensure};

use crate::{
    connection::ConnectionState,
    extended_connect::{EstablishedConnect, PendingWriteStreamError},
    message::stream::{ReadStream, WriteStream, hyper::upgrade::TakeoverError},
    qpack::field::Protocol,
    quic,
    stream_id::StreamId,
};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum EstablishError {
    #[snafu(display("extended connect response was rejected with status {status}"))]
    Rejected { status: StatusCode },
    #[snafu(display("extended connect response is missing stream ID metadata"))]
    MissingStreamId,
    #[snafu(display("extended connect response is missing connection metadata"))]
    MissingConnection,
    #[snafu(display("failed to take over extended connect read stream"))]
    TakeRead { source: TakeoverError },
    #[snafu(display("failed to take over extended connect write stream"))]
    TakeWrite { source: TakeoverError },
}

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum AcceptError {
    #[snafu(display("request method {method} is not extended connect"))]
    NotConnect { method: Method },
    #[snafu(display("extended connect request is missing stream ID metadata"))]
    MissingStreamId,
    #[snafu(display("extended connect request is missing connection metadata"))]
    MissingConnection,
    #[snafu(display("failed to take over extended connect read stream"))]
    TakeRead { source: TakeoverError },
}

fn pending_write_error(error: TakeoverError) -> PendingWriteStreamError {
    match error {
        TakeoverError::Unsupported => PendingWriteStreamError::Unsupported,
        TakeoverError::AlreadyTaken => PendingWriteStreamError::AlreadyTaken,
        TakeoverError::Aborted => PendingWriteStreamError::Aborted,
        TakeoverError::BodyNotReleased => PendingWriteStreamError::BodyNotReleased,
    }
}

pub async fn establish<B>(
    mut response: http::Response<B>,
) -> Result<EstablishedConnect, EstablishError>
where
    B: Body + Unpin + Send + 'static,
{
    ensure!(
        response.status().is_success(),
        establish_error::RejectedSnafu {
            status: response.status(),
        }
    );

    let stream_id = *response
        .extensions()
        .get::<StreamId>()
        .context(establish_error::MissingStreamIdSnafu)?;
    let connection = response
        .extensions()
        .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()
        .cloned()
        .context(establish_error::MissingConnectionSnafu)?;
    let protocol = response.extensions().get::<Protocol>().cloned();

    let read = crate::hyper::upgrade::take::<ReadStream>(&mut response)
        .await
        .context(establish_error::TakeReadSnafu)?;
    let write = crate::hyper::upgrade::take::<WriteStream>(&mut response)
        .await
        .context(establish_error::TakeWriteSnafu)?;

    Ok(EstablishedConnect::ready(
        stream_id, protocol, connection, read, write,
    ))
}

pub async fn accept<B>(
    mut request: http::Request<B>,
) -> Result<(http::Response<Empty<Bytes>>, EstablishedConnect), AcceptError>
where
    B: Body + Unpin + Send + 'static,
{
    ensure!(
        request.method() == Method::CONNECT,
        accept_error::NotConnectSnafu {
            method: request.method().clone(),
        }
    );

    let stream_id = *request
        .extensions()
        .get::<StreamId>()
        .context(accept_error::MissingStreamIdSnafu)?;
    let connection = request
        .extensions()
        .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()
        .cloned()
        .context(accept_error::MissingConnectionSnafu)?;
    let protocol = request.extensions().get::<Protocol>().cloned();

    let read = crate::hyper::upgrade::take::<ReadStream>(&mut request)
        .await
        .context(accept_error::TakeReadSnafu)?;

    let write = async move {
        match crate::hyper::upgrade::take::<WriteStream>(&mut request).await {
            Ok(write) => Ok(write),
            Err(error) => Err(pending_write_error(error)),
        }
    };

    let response = http::Response::builder()
        .status(StatusCode::OK)
        .body(Empty::<Bytes>::new())
        .expect("200 OK response with empty body is valid");

    let connect = EstablishedConnect::pending(stream_id, protocol, connection, read, write);
    Ok((response, connect))
}

#[cfg(test)]
mod tests {
    use std::{
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use http::{Request, Response, StatusCode};
    use http_body::Body;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        message::{
            stream::hyper::upgrade::{RemainStream, TakeoverSlot},
            test::{read_stream_for_test, write_stream_for_test},
        },
        protocol::Protocols,
        qpack::field::Protocol,
        varint::VarInt,
    };

    #[derive(Debug, Clone)]
    struct ErrorBody;

    impl Body for ErrorBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            Poll::Ready(Some(Err(std::io::Error::other("body error"))))
        }
    }

    fn state_for_test() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic;
        Arc::new(ConnectionState::new_for_test(
            erased,
            Arc::new(Protocols::new()),
        ))
    }

    #[tokio::test]
    async fn establish_rejects_non_success_status() {
        let response = Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        let error = match establish(response).await {
            Ok(_) => panic!("non-2xx CONNECT is rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, EstablishError::Rejected { status } if status == StatusCode::BAD_REQUEST)
        );
    }

    #[tokio::test]
    async fn establish_requires_stream_id_metadata() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        let error = match establish(response).await {
            Ok(_) => panic!("stream ID metadata is required"),
            Err(error) => error,
        };
        assert!(matches!(error, EstablishError::MissingStreamId));
    }

    #[tokio::test]
    async fn establish_requires_connection_metadata() {
        let stream_id = StreamId::from(VarInt::from_u32(4));
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        response.extensions_mut().insert(stream_id);
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let error = match establish(response).await {
            Ok(_) => panic!("connection metadata is required"),
            Err(error) => error,
        };
        assert!(matches!(error, EstablishError::MissingConnection));
    }

    #[tokio::test]
    async fn establish_returns_ready_connect_with_protocol_and_streams() {
        let stream_id = StreamId::from(VarInt::from_u32(8));
        let state = state_for_test();
        let protocol = Protocol::new("webtransport-h3");
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        response.extensions_mut().insert(stream_id);
        response.extensions_mut().insert(state.clone());
        response.extensions_mut().insert(protocol.clone());
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let connect = establish(response).await.expect("establish should succeed");
        assert!(Arc::ptr_eq(connect.connection(), &state));
        assert_eq!(connect.stream_id(), stream_id);
        assert_eq!(
            connect.protocol().map(Protocol::as_str),
            Some("webtransport-h3")
        );

        let (_read, _write) = connect
            .into_streams()
            .await
            .expect("establish should provide streams");
    }

    #[tokio::test]
    async fn establish_missing_protocol_defaults_to_none() {
        let stream_id = StreamId::from(VarInt::from_u32(12));
        let state = state_for_test();
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        response.extensions_mut().insert(stream_id);
        response.extensions_mut().insert(state);
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let connect = establish(response).await.expect("establish should succeed");
        assert_eq!(connect.protocol(), None);
        assert_eq!(connect.stream_id(), stream_id);
    }

    #[tokio::test]
    async fn establish_fails_when_write_slot_is_missing() {
        let stream_id = StreamId::from(VarInt::from_u32(16));
        let state = state_for_test();
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        response.extensions_mut().insert(stream_id);
        response.extensions_mut().insert(state);
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));

        let error = match establish(response).await {
            Ok(_) => panic!("missing write takeover slot should fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            EstablishError::TakeWrite {
                source: TakeoverError::Unsupported
            }
        ));
    }

    #[tokio::test]
    async fn establish_fails_when_read_slot_is_missing() {
        let stream_id = StreamId::from(VarInt::from_u32(18));
        let state = state_for_test();
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Empty::<Bytes>::new())
            .expect("valid response");

        response.extensions_mut().insert(stream_id);
        response.extensions_mut().insert(state);
        response
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let error = establish(response)
            .await
            .err()
            .expect("missing read takeover slot should fail");
        assert!(matches!(
            error,
            EstablishError::TakeRead {
                source: TakeoverError::Unsupported
            }
        ));
    }

    #[tokio::test]
    async fn accept_rejects_non_connect_request() {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .extension(Protocol::new("webtransport-h3"))
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        let error = match accept(request).await {
            Ok(_) => panic!("only CONNECT can be accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, AcceptError::NotConnect { method } if method == http::Method::GET));
    }

    #[tokio::test]
    async fn accept_requires_stream_id_metadata() {
        let request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        let error = match accept(request).await {
            Ok(_) => panic!("stream ID metadata is required"),
            Err(error) => error,
        };
        assert!(matches!(error, AcceptError::MissingStreamId));
    }

    #[tokio::test]
    async fn accept_requires_connection_metadata() {
        let stream_id = StreamId::from(VarInt::from_u32(20));
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let error = match accept(request).await {
            Ok(_) => panic!("connection metadata is required"),
            Err(error) => error,
        };
        assert!(matches!(error, AcceptError::MissingConnection));
    }

    #[tokio::test]
    async fn accept_returns_ok_response_and_connect_with_streams() {
        let stream_id = StreamId::from(VarInt::from_u32(24));
        let state = state_for_test();
        let protocol = Protocol::new("webtransport-h3");
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request.extensions_mut().insert(state.clone());
        request.extensions_mut().insert(protocol.clone());
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let (response, connect) = accept(request).await.expect("accept should succeed");
        assert_eq!(response.status(), StatusCode::OK);

        assert_eq!(connect.stream_id(), stream_id);
        assert_eq!(
            connect.protocol().map(Protocol::as_str),
            Some("webtransport-h3")
        );
        assert!(Arc::ptr_eq(connect.connection(), &state));

        let (_read, _write) = connect
            .into_streams()
            .await
            .expect("streams should be ready");
    }

    #[tokio::test]
    async fn accept_missing_protocol_defaults_to_none() {
        let stream_id = StreamId::from(VarInt::from_u32(28));
        let state = state_for_test();
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request.extensions_mut().insert(state);
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let (_response, connect) = accept(request).await.expect("accept should succeed");
        assert_eq!(connect.protocol(), None);
    }

    #[tokio::test]
    async fn accept_fails_when_read_takeover_fails() {
        let stream_id = StreamId::from(VarInt::from_u32(32));
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(ErrorBody)
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request.extensions_mut().insert(state_for_test());
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                write_stream_for_test(stream_id.0),
            )));

        let error = match accept(request).await {
            Ok(_) => panic!("read body errors should fail takeover"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AcceptError::TakeRead {
                source: TakeoverError::BodyNotReleased
            }
        ));
    }

    #[tokio::test]
    async fn accept_into_streams_reports_missing_write_takeover_as_pending_error() {
        let stream_id = StreamId::from(VarInt::from_u32(36));
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request.extensions_mut().insert(state_for_test());
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));

        let (_response, connect) = accept(request).await.expect("accept should parse request");
        let error = match connect.into_streams().await {
            Ok(_) => panic!("write takeover should be unsupported"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            crate::extended_connect::IntoStreamsError::PendingWriteStream {
                source: crate::extended_connect::PendingWriteStreamError::Unsupported
            }
        ));
    }

    #[tokio::test]
    async fn accept_into_streams_reports_aborted_write_takeover_as_pending_error() {
        let stream_id = StreamId::from(VarInt::from_u32(40));
        let mut request = Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://example.test/session")
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        request.extensions_mut().insert(stream_id);
        request.extensions_mut().insert(state_for_test());
        request
            .extensions_mut()
            .insert(TakeoverSlot::new(RemainStream::immediately(
                read_stream_for_test(stream_id.0),
            )));
        let (write_tx, write) = RemainStream::<WriteStream>::pending();
        request.extensions_mut().insert(TakeoverSlot::new(write));
        drop(write_tx);

        let (_response, connect) = accept(request).await.expect("accept should parse request");
        let error = connect
            .into_streams()
            .await
            .err()
            .expect("write takeover should be aborted");
        assert!(matches!(
            error,
            crate::extended_connect::IntoStreamsError::PendingWriteStream {
                source: crate::extended_connect::PendingWriteStreamError::Aborted
            }
        ));
    }
}
