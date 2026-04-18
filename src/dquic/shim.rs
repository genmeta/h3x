use std::{
    borrow::Cow,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, future::BoxFuture};
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

pub fn convert_varint(varint: dquic::prelude::VarInt) -> VarInt {
    // dquic's VarInt is already bounds-checked to RFC 9000 spec (< 2^62)
    VarInt::from_u64(varint.into_inner()).expect("dquic VarInt is within valid range")
}

pub fn convert_connection_error(error: dquic::prelude::Error) -> quic::ConnectionError {
    match error {
        dquic::prelude::Error::Quic(quic_error) => {
            quic::ConnectionError::from(quic::TransportError {
                kind: convert_varint(quic_error.kind().into()),
                frame_type: match quic_error.frame_type() {
                    dquic::qbase::error::ErrorFrameType::V1(frame_type) => {
                        convert_varint(frame_type.into())
                    }
                    dquic::qbase::error::ErrorFrameType::Ext(varint) => convert_varint(varint),
                },
                reason: quic_error.reason().to_owned().into(),
            })
        }
        dquic::prelude::Error::App(app_error) => {
            quic::ConnectionError::from(quic::ApplicationError {
                code: Code::new(
                    VarInt::try_from(app_error.error_code())
                        .expect("QUIC application error code fits in VarInt range"),
                ),
                reason: app_error.reason().to_owned().into(),
            })
        }
    }
}

pub fn convert_stream_error(error: dquic::prelude::StreamError) -> quic::StreamError {
    match error {
        dquic::prelude::StreamError::Connection(error) => {
            quic::StreamError::from(convert_connection_error(error))
        }
        dquic::prelude::StreamError::Reset(reset_stream_error) => quic::StreamError::Reset {
            code: VarInt::try_from(reset_stream_error.error_code())
                .expect("QUIC reset error code fits in VarInt range"),
        },
        dquic::prelude::StreamError::EosSent => {
            unreachable!("h3x write data after shutdown")
        }
    }
}

pin_project_lite::pin_project! {
    pub struct StreamReader {
        pub(super) stream_id: VarInt,
        #[pin]
        pub(super) reader: dquic::prelude::StreamReader,
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
        dquic::prelude::StopSending::stop(&mut self.get_mut().reader, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

pin_project_lite::pin_project! {
    pub struct StreamWriter {
        pub(super) stream_id: VarInt,
        #[pin]
        pub(super) writer: dquic::prelude::StreamWriter,
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
        // FIXME: dquic StreamWriter::poll_flush pending until all data acked, which is very bad for h3x.
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
        dquic::prelude::CancelStream::cancel(&mut self.get_mut().writer, code.into_inner());
        Poll::Ready(Ok(()))
    }
}

impl quic::ManageStream for dquic::prelude::Connection {
    type StreamWriter = StreamWriter;

    type StreamReader = StreamReader;

    async fn open_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
        let stream = self
            .open_bi_stream()
            .await
            .map_err(convert_connection_error)?;
        let (stream_id, (reader, writer)) = stream.ok_or_else(|| {
            quic::ConnectionError::from(quic::TransportError {
                kind: VarInt::from_u32(0x04), // STREAM_LIMIT_ERROR
                frame_type: VarInt::from_u32(0),
                reason: "stream ID space exhausted".into(),
            })
        })?;
        let stream_id = convert_varint(stream_id.into());
        let reader = StreamReader { stream_id, reader };
        let writer = StreamWriter { stream_id, writer };
        Ok((reader, writer))
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
        let stream = self
            .open_uni_stream()
            .await
            .map_err(convert_connection_error)?;
        let (stream_id, writer) = stream.ok_or_else(|| {
            quic::ConnectionError::from(quic::TransportError {
                kind: VarInt::from_u32(0x04), // STREAM_LIMIT_ERROR
                frame_type: VarInt::from_u32(0),
                reason: "stream ID space exhausted".into(),
            })
        })?;
        let stream_id = convert_varint(stream_id.into());
        Ok(StreamWriter { stream_id, writer })
    }

    async fn accept_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
        let (stream_id, (reader, writer)) = self
            .accept_bi_stream()
            .await
            .map_err(convert_connection_error)?;
        let stream_id = convert_varint(stream_id.into());
        let reader = StreamReader { stream_id, reader };
        let writer = StreamWriter { stream_id, writer };
        Ok((reader, writer))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
        let (stream_id, reader) = self
            .accept_uni_stream()
            .await
            .map_err(convert_connection_error)?;
        let stream_id = convert_varint(stream_id.into());
        Ok(StreamReader { stream_id, reader })
    }
}

#[derive(Debug)]
pub struct DquicLocalAgent {
    name: Arc<str>,
    certified_key: Arc<CertifiedKey>,
}

impl agent::LocalAgent for DquicLocalAgent {
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
pub struct DquicRemoteAgent {
    name: Arc<str>,
    cert_chain: Arc<[CertificateDer<'static>]>,
}

impl agent::RemoteAgent for DquicRemoteAgent {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }
}

impl quic::WithLocalAgent for dquic::prelude::Connection {
    type LocalAgent = DquicLocalAgent;

    async fn local_agent(&self) -> Result<Option<DquicLocalAgent>, quic::ConnectionError> {
        let local_agent = self.local_agent().await.map_err(convert_connection_error)?;
        Ok(local_agent.map(|local_agent| {
            let name = AsRef::<Arc<str>>::as_ref(&local_agent).clone();
            let certified_key = AsRef::<Arc<CertifiedKey>>::as_ref(&local_agent).clone();
            DquicLocalAgent {
                name,
                certified_key,
            }
        }))
    }
}

impl quic::WithRemoteAgent for dquic::prelude::Connection {
    type RemoteAgent = DquicRemoteAgent;

    async fn remote_agent(&self) -> Result<Option<DquicRemoteAgent>, quic::ConnectionError> {
        let remote_agent = self
            .remote_agent()
            .await
            .map_err(convert_connection_error)?;
        Ok(remote_agent.map(|remote_agent| {
            let name = AsRef::<Arc<str>>::as_ref(&remote_agent).clone();
            let cert_chain = AsRef::<Arc<[CertificateDer]>>::as_ref(&remote_agent).clone();
            DquicRemoteAgent { name, cert_chain }
        }))
    }
}

impl quic::Lifecycle for dquic::prelude::Connection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        _ = dquic::prelude::Connection::close(self, reason, code.into_inner().into_inner());
    }

    fn check(&self) -> Result<(), quic::ConnectionError> {
        self.validate().map_err(convert_connection_error)
    }

    async fn closed(&self) -> quic::ConnectionError {
        convert_connection_error(dquic::prelude::Connection::terminated(self).await)
    }
}

impl quic::Listen for dquic::prelude::QuicListeners {
    type Connection = dquic::prelude::Connection;

    type Error = dquic::prelude::ListenersShutdown;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        let (connection, ..) = dquic::prelude::QuicListeners::accept(self).await?;
        Ok(connection)
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        dquic::prelude::QuicListeners::shutdown(self);
        Ok(())
    }
}

impl quic::Listen for Arc<dquic::prelude::QuicListeners> {
    type Connection = dquic::prelude::Connection;

    type Error = dquic::prelude::ListenersShutdown;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        let (connection, ..) = self.as_ref().accept().await?;
        Ok(connection)
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        self.as_ref().shutdown();
        Ok(())
    }
}

impl quic::Connect for Arc<dquic::prelude::QuicClient> {
    type Connection = dquic::prelude::Connection;

    type Error = dquic::prelude::ConnectServerError;

    async fn connect(
        &self,
        server: &http::uri::Authority,
    ) -> Result<Arc<Self::Connection>, Self::Error> {
        let name = if let Some(port) = server.port_u16() {
            format!("{}:{}", server.host(), port)
        } else {
            server.host().to_string()
        };
        dquic::prelude::QuicClient::connect(self, &name).await
    }
}
