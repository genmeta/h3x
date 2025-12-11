use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{FutureExt, Sink, Stream, TryFutureExt, future::BoxFuture};
use rustls::{pki_types::CertificateDer, sign::CertifiedKey};

use crate::{
    agent::{LocalAgent, RemoteAgent},
    error::Code,
    quic,
    quic::CancelStream,
    varint::VarInt,
};

pub fn convert_varint(varint: gm_quic::prelude::VarInt) -> VarInt {
    unsafe { VarInt::from_u64_unchecked(varint.into_inner()) }
}

pub fn convert_connection_error(error: gm_quic::prelude::Error) -> quic::ConnectionError {
    match error {
        gm_quic::prelude::Error::Quic(quic_error) => {
            quic::ConnectionError::from(quic::TransportError {
                kind: convert_varint(quic_error.kind().into()),
                frame_type: match quic_error.frame_type() {
                    gm_quic::qbase::error::ErrorFrameType::V1(frame_type) => {
                        convert_varint(frame_type.into())
                    }
                    gm_quic::qbase::error::ErrorFrameType::Ext(varint) => convert_varint(varint),
                },
                reason: quic_error.reason().to_owned().into(),
            })
        }
        gm_quic::prelude::Error::App(app_error) => {
            quic::ConnectionError::from(quic::ApplicationError {
                code: Code::new(VarInt::try_from(app_error.error_code()).unwrap()),
                reason: app_error.reason().to_owned().into(),
            })
        }
    }
}

pub fn convert_stream_error(error: gm_quic::prelude::StreamError) -> quic::StreamError {
    match error {
        gm_quic::prelude::StreamError::Connection(error) => {
            quic::StreamError::from(convert_connection_error(error))
        }
        gm_quic::prelude::StreamError::Reset(reset_stream_error) => quic::StreamError::Reset {
            code: VarInt::try_from(reset_stream_error.error_code()).unwrap(),
        },
        gm_quic::prelude::StreamError::EosSent => {
            unreachable!("h3x write data after shutdown")
        }
    }
}

pin_project_lite::pin_project! {
    pub struct StreamReader {
        pub(super) stream_id: VarInt,
        #[pin]
        pub(super) reader: gm_quic::prelude::StreamReader,
    }
}

impl quic::GetStreamId for StreamReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Stream for StreamReader {
    type Item = Result<Bytes, quic::StreamError>;

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

impl quic::StopStream for StreamReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        _: &mut Context,
        code: VarInt,
    ) -> Poll<Result<(), quic::StreamError>> {
        gm_quic::prelude::StopSending::stop(&mut self.get_mut().reader, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

pin_project_lite::pin_project! {
    pub struct StreamWriter {
        pub(super) stream_id: VarInt,
        #[pin]
        pub(super) writer: gm_quic::prelude::StreamWriter,
    }
}

impl quic::GetStreamId for StreamWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _: &mut Context,
    ) -> Poll<Result<VarInt, quic::StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl Sink<Bytes> for StreamWriter {
    type Error = quic::StreamError;

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
    ) -> Poll<Result<(), quic::StreamError>> {
        gm_quic::prelude::CancelStream::cancel(&mut self.get_mut().writer, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

impl quic::ManageStream for gm_quic::prelude::Connection {
    type StreamWriter = StreamWriter;

    type StreamReader = StreamReader;

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError>>
    {
        self.open_bi_stream()
            .map_ok(|stream| {
                let (stream_id, (reader, writer)) = stream.expect("TODO: handle stream id run out");
                let stream_id = convert_varint(stream_id.into());
                let reader = StreamReader { stream_id, reader };
                let writer = StreamWriter { stream_id, writer };
                (reader, writer)
            })
            .map_err(convert_connection_error)
            .boxed()
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<Self::StreamWriter, quic::ConnectionError>> {
        self.open_uni_stream()
            .map_ok(|stream| {
                let (stream_id, writer) = stream.expect("TODO: handle stream id run out");
                let stream_id = convert_varint(stream_id.into());
                StreamWriter { stream_id, writer }
            })
            .map_err(convert_connection_error)
            .boxed()
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError>>
    {
        self.accept_bi_stream()
            .map_ok(|(stream_id, (reader, writer))| {
                let stream_id = convert_varint(stream_id.into());
                let reader = StreamReader { stream_id, reader };
                let writer = StreamWriter { stream_id, writer };
                (reader, writer)
            })
            .map_err(convert_connection_error)
            .boxed()
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<Self::StreamReader, quic::ConnectionError>> {
        self.accept_uni_stream()
            .map_ok(|(stream_id, reader)| {
                let stream_id = convert_varint(stream_id.into());
                StreamReader { stream_id, reader }
            })
            .map_err(convert_connection_error)
            .boxed()
    }
}

impl quic::WithLocalAgent for gm_quic::prelude::Connection {
    fn local_agent(&self) -> BoxFuture<'_, Result<Option<LocalAgent>, quic::ConnectionError>> {
        self.local_agent()
            .map_ok(|local_agent| {
                local_agent.map(|local_agent| {
                    let name = AsRef::<Arc<str>>::as_ref(&local_agent).clone();
                    let certified_key = AsRef::<Arc<CertifiedKey>>::as_ref(&local_agent).clone();
                    LocalAgent::new(name, certified_key)
                })
            })
            .map_err(convert_connection_error)
            .boxed()
    }
}

impl quic::WithRemoteAgent for gm_quic::prelude::Connection {
    fn remote_agent(&self) -> BoxFuture<'_, Result<Option<RemoteAgent>, quic::ConnectionError>> {
        self.remote_agent()
            .map_ok(|remote_agent| {
                remote_agent.map(|remote_agent| {
                    let name = AsRef::<Arc<str>>::as_ref(&remote_agent).clone();
                    let cert = AsRef::<Arc<[CertificateDer]>>::as_ref(&remote_agent).clone();
                    RemoteAgent::new(name, cert)
                })
            })
            .map_err(convert_connection_error)
            .boxed()
    }
}

impl quic::Close for gm_quic::prelude::Connection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        _ = gm_quic::prelude::Connection::close(self, reason, code.into_inner().into_inner());
    }
}

impl quic::Listen for gm_quic::prelude::QuicListeners {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ListenersShutdown;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        self.accept().map_ok(|(connection, ..)| connection).boxed()
    }
}

impl quic::Listen for Arc<gm_quic::prelude::QuicListeners> {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ListenersShutdown;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        self.as_ref()
            .accept()
            .map_ok(|(connection, ..)| connection)
            .boxed()
    }
}

impl quic::Connect for gm_quic::prelude::QuicClient {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ConnectServerError;

    fn connect(&self, name: &str) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        self.connect(name).boxed()
    }
}

impl quic::Connect for Arc<gm_quic::prelude::QuicClient> {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ConnectServerError;

    fn connect(&self, name: &str) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        self.as_ref().connect(name).boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use bytes::Buf;
    use gm_quic::prelude::{
        BindUri, QuicClient, QuicIO, QuicListeners,
        handy::{ToCertificate, ToPrivateKey},
    };
    use http::StatusCode;
    use tracing::Instrument;

    use crate::endpoint::{
        client::Client,
        server::{self, Router, Servers},
    };

    const CA_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/ca.cert");
    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn init_tracing() {
        _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
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
        tracing::info!(target: "test", "Listening on {listen_addr}");

        (quic_listeners, listen_addr)
    }

    type BoxError = Box<dyn std::error::Error + Send + Sync>;

    #[tokio::test]
    async fn simple_echo() -> Result<(), BoxError> {
        init_tracing();

        let (quic_listeners, listen_addr) = quic_listeners();
        let servers = Servers::builder().acceptor(quic_listeners.clone()).build();
        let client = Client::builder().connector(quic_client()).build();

        let server = async move {
            let echo_service = async |mut req: server::Request, mut resp: server::Response| {
                tracing::info!("Echo service called");
                resp.set_status(StatusCode::OK).unwrap();
                while let Some(body_part) = req.read().await.transpose().unwrap() {
                    tracing::info!("Echoing back request body part({} bytes)", body_part.len());
                    resp.write(body_part).await.unwrap();
                }
                resp.close().await.unwrap();
                tracing::info!("Echo done");
            };
            servers
                .serve("localhost", Router::new().route("/echo", echo_service))
                .run()
                .await;
            Ok::<_, BoxError>(())
        }
        .instrument(tracing::info_span!("server"));

        let client = async move {
            let port = listen_addr.port();
            let (mut req, mut resp) = client
                .new_request()
                .set_uri(format!("https://localhost:{port}/echo").parse()?)
                .post()
                .await?;
            tracing::info!("Request header sent");

            let content = include_bytes!("./gm_quic.rs").as_slice();
            req.write(content).await?.close().await?;
            tracing::info!("Request sent");

            assert_eq!(resp.status().await?, StatusCode::OK);
            let mut response = resp.read_all().await?;
            tracing::info!("Response received");
            let response = response.copy_to_bytes(response.remaining());
            assert!(response.as_ref() == content);

            quic_listeners.shutdown();
            Ok::<_, BoxError>(())
        }
        .instrument(tracing::info_span!("client"));

        tokio::try_join!(client, server)?;
        Ok(())
    }
}
