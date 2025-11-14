use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{FutureExt, Sink, Stream, future::BoxFuture};

use crate::{
    error::{ApplicationError, Code, ConnectionError, StreamError, TransportError},
    quic::{CancelStream, GetStreamId, StopSending},
    varint::VarInt,
};

fn convert_varint(varint: gm_quic::prelude::VarInt) -> VarInt {
    VarInt::try_from(varint.into_inner()).unwrap()
}

fn convert_connection_error(error: gm_quic::prelude::Error) -> ConnectionError {
    match error {
        gm_quic::prelude::Error::Quic(quic_error) => ConnectionError::from(TransportError {
            kind: convert_varint(quic_error.kind().into()),
            frame_type: match quic_error.frame_type() {
                gm_quic::qbase::error::ErrorFrameType::V1(frame_type) => {
                    convert_varint(frame_type.into())
                }
                gm_quic::qbase::error::ErrorFrameType::Ext(varint) => convert_varint(varint),
            },
            reason: quic_error.reason().to_owned().into(),
        }),
        gm_quic::prelude::Error::App(app_error) => ConnectionError::from(ApplicationError {
            code: Code::new(VarInt::try_from(app_error.error_code()).unwrap()),
            reason: app_error.reason().to_owned().into(),
        }),
    }
}

fn convert_stream_error(error: gm_quic::prelude::StreamError) -> StreamError {
    match error {
        gm_quic::prelude::StreamError::Connection(error) => {
            StreamError::from(convert_connection_error(error))
        }
        gm_quic::prelude::StreamError::Reset(reset_stream_error) => StreamError::Reset {
            code: VarInt::try_from(reset_stream_error.error_code()).unwrap(),
        },
        gm_quic::prelude::StreamError::EosSent => unreachable!("h3x write data after shutdown"),
    }
}

pin_project_lite::pin_project! {
    pub struct StreamReader {
        stream_id: VarInt,
        #[pin]
        reader: gm_quic::prelude::StreamReader,
    }
}

impl GetStreamId for StreamReader {
    fn poll_stream_id(self: Pin<&mut Self>, _: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Stream for StreamReader {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project()
            .reader
            .poll_next(cx)
            .map_ok(|bytes| bytes)
            .map_err(convert_stream_error)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.reader.size_hint()
    }
}

impl StopSending for StreamReader {
    fn poll_stop_sending(
        self: Pin<&mut Self>,
        _: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        gm_quic::prelude::StopSending::stop(&mut self.get_mut().reader, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

pin_project_lite::pin_project! {
    pub struct StreamWriter {
        stream_id: VarInt,
        #[pin]
        writer: gm_quic::prelude::StreamWriter,
    }
}

impl GetStreamId for StreamWriter {
    fn poll_stream_id(self: Pin<&mut Self>, _: &mut Context) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Sink<Bytes> for StreamWriter {
    type Error = StreamError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .writer
            .poll_ready(cx)
            .map_err(convert_stream_error)
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        self.project()
            .writer
            .start_send(item)
            .map_err(convert_stream_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .writer
            .poll_flush(cx)
            .map_err(convert_stream_error)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .writer
            .poll_close(cx)
            .map_err(convert_stream_error)
    }
}

impl CancelStream for StreamWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        gm_quic::prelude::CancelStream::cancel(&mut self.get_mut().writer, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

// TOOD: remove Arc
impl super::QuicConnect for Arc<gm_quic::prelude::Connection> {
    type StreamWriter = StreamWriter;

    type StreamReader = StreamReader;

    fn open_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let connection = self.clone();
        async move {
            let (stream_id, (reader, writer)) = connection
                .open_bi_stream()
                .await
                .map_err(convert_connection_error)?
                .expect("TODO: handle stream_id run out");
            let stream_id = convert_varint(stream_id.into());

            Ok((
                StreamReader { stream_id, reader },
                StreamWriter { stream_id, writer },
            ))
        }
        .boxed()
    }

    fn open_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamWriter, ConnectionError>> {
        let connection = self.clone();
        async move {
            let (stream_id, writer) = connection
                .open_uni_stream()
                .await
                .map_err(convert_connection_error)?
                .expect("TODO: handle stream_id run out");
            let stream_id = convert_varint(stream_id.into());

            Ok(StreamWriter { stream_id, writer })
        }
        .boxed()
    }

    fn accept_bi(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<(Self::StreamReader, Self::StreamWriter), ConnectionError>> {
        let connection = self.clone();
        async move {
            let (stream_id, (reader, writer)) = connection
                .accept_bi_stream()
                .await
                .map_err(convert_connection_error)?;
            let stream_id = convert_varint(stream_id.into());

            Ok((
                StreamReader { stream_id, reader },
                StreamWriter { stream_id, writer },
            ))
        }
        .boxed()
    }

    fn accept_uni(
        self: Pin<&mut Self>,
    ) -> BoxFuture<'static, Result<Self::StreamReader, ConnectionError>> {
        let connection = self.clone();
        async move {
            let (stream_id, reader) = connection
                .accept_uni_stream()
                .await
                .map_err(convert_connection_error)?;
            let stream_id = convert_varint(stream_id.into());

            Ok(StreamReader { stream_id, reader })
        }
        .boxed()
    }

    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>) {
        _ = gm_quic::prelude::Connection::close(&self, reason, code.into_inner().into_inner());
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::{body::Body, routing::get};
    use gm_quic::prelude::{
        BindUri, QuicClient, QuicIO, QuicListeners,
        handy::{ToCertificate, ToPrivateKey},
    };
    use http::Request;
    use http_body_util::BodyExt;
    use tower::{Service, ServiceExt};
    use tracing::Instrument;

    use super::*;
    use crate::{connection::Connection, qpack::settings::Settings};

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    const HELLO_GENMETA: &str = "Hello, genemta network!";

    fn quic_client() -> QuicClient {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(CA_CERT.to_certificate());
        QuicClient::builder()
            .with_root_certificates(roots)
            .without_cert()
            .enable_sslkeylog()
            .build()
    }

    fn quic_listeners() -> (Arc<QuicListeners>, SocketAddr) {
        let quic_listeners = QuicListeners::builder()
            .unwrap()
            .without_client_cert_verifier()
            .listen(128);

        quic_listeners
            .add_server(
                "localhost",
                SERVER_CERT.to_certificate(),
                SERVER_KEY.to_private_key(),
                [BindUri::from("inet://[::1]:0").alloc_port()],
                None,
            )
            .unwrap();

        let listen_addr = quic_listeners
            .get_server("localhost")
            .unwrap()
            .bind_interfaces()
            .iter()
            .next()
            .unwrap()
            .1
            .borrow()
            .unwrap()
            .real_addr()
            .unwrap()
            .try_into()
            .unwrap();

        (quic_listeners, listen_addr)
    }

    #[tokio::test]
    async fn simple_axum_server() {
        _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();

        let (listeners, server_listen) = quic_listeners();

        tokio::spawn(
            async move {
                async fn hello_world() -> &'static str {
                    HELLO_GENMETA
                }

                let mut router = axum::Router::new().route("/hello_world", get(hello_world));

                let (connection, ..) = listeners.accept().await.unwrap();
                let connection = Connection::new(Settings::default(), connection)
                    .await
                    .unwrap();

                let (mut response_sender, request_reader) = connection.accept().await.unwrap();
                let request = request_reader.read_request().await.unwrap();
                tracing::info!("Received request: {} {}", request.method(), request.uri());

                let response = router
                    .as_service()
                    .ready()
                    .await
                    .unwrap()
                    .call(request)
                    .await
                    .unwrap();

                response_sender.send_response(response).await.unwrap();
                tracing::info!("Sent response");
                response_sender.shutdown().await.unwrap();

                std::future::pending::<()>().await
            }
            .instrument(tracing::info_span!("server")),
        );

        async move {
            let client = quic_client();

            let connection = client.connect("localhost", [server_listen]).unwrap();
            let connection = Connection::new(Settings::default(), connection)
                .await
                .unwrap();

            let request = Request::builder()
                .uri("/hello_world")
                .body(Body::empty())
                .unwrap();
            let (mut request_writer, response_reader) = connection.open().await.unwrap();

            request_writer.send_request(request).await.unwrap();
            tracing::info!("Sent request");
            request_writer.shutdown().await.unwrap();

            let mut response_reader = response_reader.await.unwrap();
            let response = response_reader.read_response().await.unwrap().unwrap();
            tracing::info!("Sent request");
            let response = response.into_body().collect().await.unwrap().to_bytes();

            println!("Response: {}", std::str::from_utf8(&response).unwrap());
            assert_eq!(&response[..], HELLO_GENMETA.as_bytes());
        }
        .instrument(tracing::info_span!("client"))
        .await;
    }
}
