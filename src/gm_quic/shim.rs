use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{
    FutureExt, Sink, Stream, TryFutureExt,
    future::{self, BoxFuture},
};
use rustls::{SignatureScheme, pki_types::CertificateDer, sign::CertifiedKey};

use crate::{
    error::Code,
    quic,
    quic::{
        CancelStream,
        agent::{self, SignError},
    },
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
        // FIXME: gm-quic StreamWriter::poll_flush pending until all data acked, which is very bad for h3x.
        // self.project()
        //     .writer
        //     .poll_flush(cx)
        //     .map_err(convert_stream_error)
        _ = cx;
        Poll::Ready(Ok(()))
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
                let (stream_id, (reader, writer)) = stream.expect("todo: handle stream id run out");
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
                let (stream_id, writer) = stream.expect("todo: handle stream id run out");
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

#[derive(Debug)]
pub struct GmQuicLocalAgent {
    name: Arc<str>,
    certified_key: Arc<CertifiedKey>,
}

impl agent::LocalAgent for GmQuicLocalAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        self.certified_key.cert.as_slice()
    }

    fn sign_algorithm(&self) -> rustls::SignatureAlgorithm {
        self.certified_key.key.algorithm()
    }

    fn sign(
        &self,
        scheme: SignatureScheme,
        data: &[u8],
    ) -> BoxFuture<'_, Result<Vec<u8>, SignError>> {
        let result = agent::sign_with_key(self.certified_key.key.as_ref(), scheme, data);
        Box::pin(std::future::ready(result))
    }
}

#[derive(Debug)]
pub struct GmQuicRemoteAgent {
    name: Arc<str>,
    cert_chain: Arc<[CertificateDer<'static>]>,
}

impl agent::RemoteAgent for GmQuicRemoteAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }
}

impl quic::WithLocalAgent for gm_quic::prelude::Connection {
    type LocalAgent = GmQuicLocalAgent;

    fn local_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<GmQuicLocalAgent>, quic::ConnectionError>> {
        self.local_agent()
            .map_ok(|local_agent| {
                local_agent.map(|local_agent| {
                    let name = AsRef::<Arc<str>>::as_ref(&local_agent).clone();
                    let certified_key = AsRef::<Arc<CertifiedKey>>::as_ref(&local_agent).clone();
                    GmQuicLocalAgent {
                        name,
                        certified_key,
                    }
                })
            })
            .map_err(convert_connection_error)
            .boxed()
    }
}

impl quic::WithRemoteAgent for gm_quic::prelude::Connection {
    type RemoteAgent = GmQuicRemoteAgent;

    fn remote_agent(
        &self,
    ) -> BoxFuture<'_, Result<Option<GmQuicRemoteAgent>, quic::ConnectionError>> {
        self.remote_agent()
            .map_ok(|remote_agent| {
                remote_agent.map(|remote_agent| {
                    let name = AsRef::<Arc<str>>::as_ref(&remote_agent).clone();
                    let cert_chain = AsRef::<Arc<[CertificateDer]>>::as_ref(&remote_agent).clone();
                    GmQuicRemoteAgent { name, cert_chain }
                })
            })
            .map_err(convert_connection_error)
            .boxed()
    }
}

impl quic::Lifecycle for gm_quic::prelude::Connection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        _ = gm_quic::prelude::Connection::close(self, reason, code.into_inner().into_inner());
    }

    fn check(&self) -> Result<(), quic::ConnectionError> {
        self.validate().map_err(convert_connection_error)
    }

    fn closed(&self) -> BoxFuture<'_, quic::ConnectionError> {
        Box::pin(gm_quic::prelude::Connection::terminated(self).map(convert_connection_error))
    }
}

impl quic::Listen for gm_quic::prelude::QuicListeners {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ListenersShutdown;

    fn accept(&self) -> BoxFuture<'_, Result<Self::Connection, Self::Error>> {
        self.accept().map_ok(|(connection, ..)| connection).boxed()
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), Self::Error>> {
        self.shutdown();
        Box::pin(future::always_ready(|| Ok(())))
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

    fn shutdown(&self) -> BoxFuture<'_, Result<(), Self::Error>> {
        self.as_ref().shutdown();
        Box::pin(future::always_ready(|| Ok(())))
    }
}

impl quic::Connect for Arc<gm_quic::prelude::QuicClient> {
    type Connection = gm_quic::prelude::Connection;

    type Error = gm_quic::prelude::ConnectServerError;

    fn connect<'a>(
        &'a self,
        server: &'a http::uri::Authority,
    ) -> BoxFuture<'a, Result<Self::Connection, Self::Error>> {
        let name = if let Some(port) = server.port_u16() {
            format!("{}:{}", server.host(), port)
        } else {
            server.host().to_string()
        };
        async move { gm_quic::prelude::QuicClient::connect(self, &name).await }.boxed()
    }
}
