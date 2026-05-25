use std::sync::Arc;

use http::{Method, StatusCode};
use http_body::Body;
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

#[allow(dead_code)]
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

pub async fn accept<B>(request: http::Request<B>) -> Result<(), AcceptError>
where
    B: Body + Unpin + Send + 'static,
{
    ensure!(
        request.method() == Method::CONNECT,
        accept_error::NotConnectSnafu {
            method: request.method().clone(),
        }
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use http_body_util::Empty;

    use super::*;
    use crate::qpack::field::Protocol;

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
    async fn accept_rejects_non_connect_request() {
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("https://example.test/")
            .extension(Protocol::new("webtransport-h3"))
            .body(Empty::<Bytes>::new())
            .expect("valid request");

        let error = accept(request)
            .await
            .expect_err("only CONNECT can be accepted");
        assert!(matches!(error, AcceptError::NotConnect { method } if method == http::Method::GET));
    }
}
