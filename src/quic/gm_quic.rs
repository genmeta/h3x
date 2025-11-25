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

impl super::Close for Arc<gm_quic::prelude::Connection> {
    fn close(self: Pin<&mut Self>, code: Code, reason: Cow<'static, str>) {
        _ = gm_quic::prelude::Connection::close(&self, reason, code.into_inner().into_inner());
    }
}

// TOOD: remove Arc
impl super::Connect for Arc<gm_quic::prelude::Connection> {
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
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::BytesMut;
    use gm_quic::prelude::{
        BindUri, QuicClient, QuicIO, QuicListeners,
        handy::{ToCertificate, ToPrivateKey},
    };
    use http::{StatusCode, Uri};
    use tracing::Instrument;

    use super::*;
    use crate::connection::{Connection, settings::Settings};

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn init_tracing() {
        _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    }

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
    async fn message2() {
        init_tracing();

        let (listeners, server_listen) = quic_listeners();

        tokio::spawn(
            async move {
                let (connection, ..) = listeners.accept().await?;

                let connection = Connection::new(Settings::default(), connection).await?;

                let unresolved_request = connection.accept_request().await?;

                let (request, mut response) = unresolved_request.await?;

                let Some(user_agent) = request.header("User-Agent") else {
                    response
                        .set_status(StatusCode::NOT_FOUND)
                        .set_header("A", "B")?
                        .end()
                        .await?;
                    return Ok(());
                };

                if user_agent != "h3x-test-client" {
                    response.set_status(StatusCode::NOT_FOUND).end().await?;
                    return Ok(());
                }

                response.set_status(StatusCode::OK).end().await?;

                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
            .instrument(tracing::info_span!("server")),
        );

        async move {
            let client = quic_client();

            let connection = client.connect("localhost", [server_listen]).unwrap();
            let connection = Connection::new(Settings::default(), connection)
                .await
                .unwrap();
            let uri = Uri::try_from("/hello_world").unwrap();

            let (_, mut response) = (connection.get(uri).await?)
                .set_header("User-Agent", "h3x-test-client")?
                .set_body(Bytes::copy_from_slice(b"Hello from client"))
                .await?;

            if response.status() != StatusCode::OK {
                panic!("Unexpected response status: {}", response.status());
            }

            let body: BytesMut = response.read_all().await?;
            println!("Response: {}", std::str::from_utf8(&body).unwrap());

            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .instrument(tracing::info_span!("client"))
        .await
        .unwrap();
    }
}
