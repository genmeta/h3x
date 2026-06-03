use std::{
    borrow::Cow,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use dhttp_identity::identity::{self as authority, SignError};
use futures::{Sink, Stream, future::BoxFuture};
use rustls::{SignatureScheme, pki_types::CertificateDer, sign::CertifiedKey};

use crate::{error::Code, quic, quic::ResetStream, varint::VarInt};

pub fn convert_varint(varint: dquic::prelude::VarInt) -> VarInt {
    // dquic's VarInt is already bounds-checked to RFC 9000 spec (< 2^62)
    VarInt::from_u64(varint.into_u64()).expect("dquic VarInt is within valid range")
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

type DquicConnectionId = dquic::qbase::cid::ConnectionId;

#[derive(Clone)]
struct LatchedConnectionError {
    origin_dcid: Option<DquicConnectionId>,
    error: quic::ConnectionError,
}

fn dquic_connection_latches() -> &'static DashMap<usize, LatchedConnectionError> {
    static LATCHES: OnceLock<DashMap<usize, LatchedConnectionError>> = OnceLock::new();
    LATCHES.get_or_init(DashMap::new)
}

fn dquic_connection_key(connection: &dquic::prelude::Connection) -> usize {
    std::ptr::from_ref(connection).cast::<()>() as usize
}

fn dquic_origin_dcid(connection: &dquic::prelude::Connection) -> Option<DquicConnectionId> {
    connection.origin_dcid().ok()
}

fn is_stale_latch(
    stored_origin: Option<DquicConnectionId>,
    current_origin: Option<DquicConnectionId>,
) -> bool {
    match (stored_origin, current_origin) {
        (Some(stored), Some(current)) => stored != current,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn latched_connection_error(
    connection: &dquic::prelude::Connection,
) -> Option<quic::ConnectionError> {
    let key = dquic_connection_key(connection);
    let entry = dquic_connection_latches().get(&key)?;
    if is_stale_latch(entry.origin_dcid, dquic_origin_dcid(connection)) {
        drop(entry);
        dquic_connection_latches().remove(&key);
        None
    } else {
        Some(entry.error.clone())
    }
}

fn latch_connection_error(
    connection: &dquic::prelude::Connection,
    origin_dcid: Option<DquicConnectionId>,
    error: quic::ConnectionError,
) -> quic::ConnectionError {
    let key = dquic_connection_key(connection);
    match dquic_connection_latches().entry(key) {
        Entry::Occupied(mut entry) => {
            if is_stale_latch(entry.get().origin_dcid, origin_dcid) {
                entry.insert(LatchedConnectionError {
                    origin_dcid,
                    error: error.clone(),
                });
                error
            } else {
                entry.get().error.clone()
            }
        }
        Entry::Vacant(entry) => {
            entry.insert(LatchedConnectionError {
                origin_dcid,
                error: error.clone(),
            });
            error
        }
    }
}

fn convert_and_latch_connection_error(
    connection: &dquic::prelude::Connection,
    error: dquic::prelude::Error,
) -> quic::ConnectionError {
    let origin_dcid = dquic_origin_dcid(connection);
    latch_connection_error(connection, origin_dcid, convert_connection_error(error))
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

impl ResetStream for StreamWriter {
    fn poll_reset(
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
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        let (stream_id, (reader, writer)) = stream.ok_or_else(|| {
            latch_connection_error(
                self,
                dquic_origin_dcid(self),
                quic::ConnectionError::from(quic::TransportError {
                    kind: VarInt::from_u32(0x04), // STREAM_LIMIT_ERROR
                    frame_type: VarInt::from_u32(0),
                    reason: "stream ID space exhausted".into(),
                }),
            )
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
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        let (stream_id, writer) = stream.ok_or_else(|| {
            latch_connection_error(
                self,
                dquic_origin_dcid(self),
                quic::ConnectionError::from(quic::TransportError {
                    kind: VarInt::from_u32(0x04), // STREAM_LIMIT_ERROR
                    frame_type: VarInt::from_u32(0),
                    reason: "stream ID space exhausted".into(),
                }),
            )
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
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        let stream_id = convert_varint(stream_id.into());
        let reader = StreamReader { stream_id, reader };
        let writer = StreamWriter { stream_id, writer };
        Ok((reader, writer))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
        let (stream_id, reader) = self
            .accept_uni_stream()
            .await
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        let stream_id = convert_varint(stream_id.into());
        Ok(StreamReader { stream_id, reader })
    }
}

#[derive(Debug)]
pub struct DquicLocalAuthority {
    name: Arc<str>,
    certified_key: Arc<CertifiedKey>,
}

impl authority::LocalAuthority for DquicLocalAuthority {
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
        let result = authority::sign_with_key(self.certified_key.key.as_ref(), scheme, data);
        Box::pin(std::future::ready(result))
    }
}

#[derive(Debug)]
pub struct DquicRemoteAuthority {
    name: Arc<str>,
    cert_chain: Arc<[CertificateDer<'static>]>,
}

impl authority::RemoteAuthority for DquicRemoteAuthority {
    fn name(&self) -> &str {
        &self.name
    }

    fn cert_chain(&self) -> &[CertificateDer<'static>] {
        &self.cert_chain
    }
}

impl quic::WithLocalAuthority for dquic::prelude::Connection {
    type LocalAuthority = DquicLocalAuthority;

    async fn local_authority(&self) -> Result<Option<DquicLocalAuthority>, quic::ConnectionError> {
        let authority = self
            .local_authority()
            .await
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        Ok(authority.map(|authority| {
            let name = AsRef::<Arc<str>>::as_ref(&authority).clone();
            let certified_key = AsRef::<Arc<CertifiedKey>>::as_ref(&authority).clone();
            DquicLocalAuthority {
                name,
                certified_key,
            }
        }))
    }
}

impl quic::WithRemoteAuthority for dquic::prelude::Connection {
    type RemoteAuthority = DquicRemoteAuthority;

    async fn remote_authority(
        &self,
    ) -> Result<Option<DquicRemoteAuthority>, quic::ConnectionError> {
        let authority = self
            .remote_authority()
            .await
            .map_err(|error| convert_and_latch_connection_error(self, error))?;
        Ok(authority.map(|authority| {
            let name = AsRef::<Arc<str>>::as_ref(&authority).clone();
            let cert_chain = AsRef::<Arc<[CertificateDer]>>::as_ref(&authority).clone();
            DquicRemoteAuthority { name, cert_chain }
        }))
    }
}

impl quic::Lifecycle for dquic::prelude::Connection {
    fn close(&self, code: Code, reason: Cow<'static, str>) {
        _ = dquic::prelude::Connection::close(self, reason, code.into_inner().into_inner());
    }

    fn check(&self) -> Result<(), quic::ConnectionError> {
        if let Some(error) = latched_connection_error(self) {
            return Err(error);
        }
        self.validate()
            .map_err(|error| convert_and_latch_connection_error(self, error))
    }

    async fn closed(&self) -> quic::ConnectionError {
        if let Some(error) = latched_connection_error(self) {
            return error;
        }
        let origin_dcid = dquic_origin_dcid(self);
        let error = convert_connection_error(dquic::prelude::Connection::terminated(self).await);
        latch_connection_error(self, origin_dcid, error)
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

impl quic::Listen for &dquic::prelude::QuicListeners {
    type Connection = dquic::prelude::Connection;

    type Error = dquic::prelude::ListenersShutdown;

    async fn accept(&mut self) -> Result<Arc<Self::Connection>, Self::Error> {
        let (connection, ..) = (*self).accept().await?;
        Ok(connection)
    }

    async fn shutdown(&self) -> Result<(), Self::Error> {
        (*self).shutdown();
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

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        fmt,
        str::FromStr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use dquic::{
        prelude::{
            IO,
            handy::{ToCertificate, ToPrivateKey},
        },
        qbase::{
            error::{AppError, Error as DquicError, ErrorFrameType, ErrorKind, QuicError},
            frame::{FrameType, ResetStreamError},
            varint::VarInt as DquicVarInt,
        },
        qrecovery::streams::error::StreamError as DquicStreamError,
    };
    use futures::{FutureExt, SinkExt, StreamExt, stream};
    use http::uri::Authority;
    use tokio::time;

    use super::*;
    use crate::{
        dquic::resolver::{Record, Resolve, ResolveFuture},
        quic::{GetStreamIdExt, Lifecycle, ResetStreamExt, StopStreamExt},
    };

    const SERVER_CERT: &[u8] = include_bytes!("../../tests/keychain/localhost/server.cert");
    const SERVER_KEY: &[u8] = include_bytes!("../../tests/keychain/localhost/server.key");

    fn make_identity() -> crate::dquic::identity::Identity {
        crate::dquic::identity::Identity::new(
            "localhost".parse().expect("valid identity name"),
            SERVER_CERT.to_certificate(),
            SERVER_KEY.to_private_key(),
        )
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    async fn with_timeout<T>(future: impl Future<Output = T>) -> T {
        time::timeout(TEST_TIMEOUT, future)
            .await
            .expect("test operation timed out")
    }

    async fn make_server_endpoint() -> (crate::dquic::QuicEndpoint, Authority) {
        let identity = Arc::new(make_identity());
        let network = crate::dquic::Network::builder().build();
        let endpoint = crate::dquic::QuicEndpoint::builder()
            .network(network.clone())
            .identity(identity)
            .bind(Arc::new(vec![
                crate::dquic::binds::BindPattern::from_str("127.0.0.1:0")
                    .expect("valid bind pattern"),
            ]))
            .build()
            .await;
        let bind_iface = network
            .quic()
            .interfaces()
            .into_iter()
            .next()
            .expect("server should bind an interface");
        let port = bind_iface
            .borrow()
            .bound_addr()
            .expect("server interface should have a bound address")
            .port();
        let authority =
            Authority::from_maybe_shared(format!("localhost:{port}")).expect("valid authority");
        (endpoint, authority)
    }

    fn make_raw_listeners() -> Arc<dquic::prelude::QuicListeners> {
        dquic::prelude::QuicListeners::builder()
            .with_router(Arc::new(
                dquic::qinterface::component::route::QuicRouter::default(),
            ))
            .with_locations(Arc::new(
                dquic::qinterface::component::location::Locations::new(),
            ))
            .without_client_cert_verifier()
            .listen(1)
            .expect("raw listeners start")
    }

    struct ConnectedPair {
        _client_endpoint: crate::dquic::QuicEndpoint,
        _server_endpoint: crate::dquic::QuicEndpoint,
        client: Arc<dquic::prelude::Connection>,
        server: Arc<dquic::prelude::Connection>,
    }

    async fn connected_pair() -> ConnectedPair {
        let client_endpoint = crate::dquic::QuicEndpoint::builder().build().await;
        let (server_endpoint, authority) = make_server_endpoint().await;
        let (server_connection, client_connection) = with_timeout(async {
            tokio::join!(
                server_endpoint.accept(),
                quic::Connect::connect(&client_endpoint, &authority)
            )
        })
        .await;
        ConnectedPair {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            client: client_connection.expect("client should connect"),
            server: server_connection.expect("server should accept"),
        }
    }

    fn close_pair(pair: &ConnectedPair) {
        Lifecycle::close(pair.client.as_ref(), Code::H3_NO_ERROR, Cow::Borrowed(""));
        Lifecycle::close(pair.server.as_ref(), Code::H3_NO_ERROR, Cow::Borrowed(""));
    }

    #[derive(Debug, Default)]
    struct RecordingResolver {
        names: Mutex<Vec<String>>,
    }

    impl RecordingResolver {
        fn names(&self) -> Vec<String> {
            self.names.lock().unwrap().clone()
        }
    }

    impl fmt::Display for RecordingResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("recording resolver")
        }
    }

    impl Resolve for RecordingResolver {
        fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
            self.names.lock().unwrap().push(name.to_owned());
            async { Ok(stream::empty::<Record>().boxed()) }.boxed()
        }
    }

    fn transport_connection_error(kind: u32) -> quic::ConnectionError {
        quic::ConnectionError::from(quic::TransportError {
            kind: VarInt::from_u32(kind),
            frame_type: VarInt::from_u32(0),
            reason: format!("test transport {kind}").into(),
        })
    }

    fn assert_transport_error(
        error: quic::ConnectionError,
        expected_kind: VarInt,
        expected_frame_type: VarInt,
        expected_reason: &str,
    ) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.kind, expected_kind);
        assert_eq!(source.frame_type, expected_frame_type);
        assert_eq!(source.reason, Cow::Borrowed(expected_reason));
    }

    #[test]
    fn convert_varint_preserves_dquic_value() {
        let value = DquicVarInt::from_u64(0x1234_5678).expect("dquic varint");

        assert_eq!(convert_varint(value), VarInt::from_u32(0x1234_5678));
    }

    #[test]
    fn stale_latch_detection_matches_origin_pairs() {
        let first = DquicConnectionId::from_slice(b"first");
        let second = DquicConnectionId::from_slice(b"second");

        assert!(is_stale_latch(Some(first), Some(second)));
        assert!(is_stale_latch(None, Some(first)));
        assert!(!is_stale_latch(Some(first), Some(first)));
        assert!(!is_stale_latch(Some(first), None));
        assert!(!is_stale_latch(None, None));
    }

    #[test]
    fn convert_connection_error_preserves_transport_v1_frame_type() {
        let error = DquicError::Quic(QuicError::new(
            ErrorKind::StreamLimit,
            ErrorFrameType::V1(FrameType::StopSending),
            "stream limit",
        ));

        assert_transport_error(
            convert_connection_error(error),
            VarInt::from_u32(0x04),
            VarInt::from_u32(0x05),
            "stream limit",
        );
    }

    #[test]
    fn convert_connection_error_preserves_transport_extension_frame_type() {
        let extension_frame = DquicVarInt::from_u32(0x21);
        let error = DquicError::Quic(QuicError::new(
            ErrorKind::ProtocolViolation,
            ErrorFrameType::Ext(extension_frame),
            "extension frame",
        ));

        assert_transport_error(
            convert_connection_error(error),
            VarInt::from_u32(0x0a),
            VarInt::from_u32(0x21),
            "extension frame",
        );
    }

    #[test]
    fn convert_connection_error_preserves_application_error() {
        let error = DquicError::App(AppError::new(
            DquicVarInt::from_u32(Code::H3_REQUEST_CANCELLED.into_inner().into_inner() as u32),
            "application close",
        ));

        let quic::ConnectionError::Application { source } = convert_connection_error(error) else {
            panic!("expected application error");
        };
        assert_eq!(source.code, Code::H3_REQUEST_CANCELLED);
        assert_eq!(source.reason, Cow::Borrowed("application close"));
    }

    #[test]
    fn convert_stream_error_preserves_connection_and_reset_errors() {
        let connection = DquicStreamError::Connection(DquicError::Quic(
            QuicError::with_default_fty(ErrorKind::Internal, "connection failed"),
        ));
        let quic::StreamError::Connection { source } = convert_stream_error(connection) else {
            panic!("expected connection stream error");
        };
        assert_transport_error(
            source,
            VarInt::from_u32(0x01),
            VarInt::from_u32(0x00),
            "connection failed",
        );

        let reset = DquicStreamError::Reset(ResetStreamError::new(
            DquicVarInt::from_u32(0x100),
            DquicVarInt::from_u32(0),
        ));
        let quic::StreamError::Reset { code } = convert_stream_error(reset) else {
            panic!("expected reset stream error");
        };
        assert_eq!(code, VarInt::from_u32(0x100));
    }

    #[test]
    #[should_panic(expected = "h3x write data after shutdown")]
    fn convert_stream_error_rejects_eos_sent() {
        _ = convert_stream_error(DquicStreamError::EosSent);
    }

    #[tokio::test]
    async fn connection_agents_are_exposed_from_established_dquic_connection() {
        let pair = connected_pair().await;
        let client = &pair.client;
        let server = &pair.server;

        let client_local = quic::WithLocalAuthority::local_authority(client.as_ref())
            .await
            .expect("client local authority lookup");
        assert!(
            client_local.is_none(),
            "anonymous client has no local authority"
        );

        let client_remote = quic::WithRemoteAuthority::remote_authority(client.as_ref())
            .await
            .expect("client remote authority lookup")
            .expect("client should observe server identity");
        assert_eq!(
            authority::RemoteAuthority::name(&client_remote),
            "localhost"
        );
        assert_eq!(
            authority::RemoteAuthority::cert_chain(&client_remote),
            make_identity().cert_chain()
        );

        let server_local = quic::WithLocalAuthority::local_authority(server.as_ref())
            .await
            .expect("server local authority lookup")
            .expect("server should have local identity");
        assert_eq!(authority::LocalAuthority::name(&server_local), "localhost");
        assert_eq!(
            authority::LocalAuthority::cert_chain(&server_local),
            make_identity().cert_chain()
        );

        let server_remote = quic::WithRemoteAuthority::remote_authority(server.as_ref())
            .await
            .expect("server remote authority lookup");
        assert!(
            server_remote.is_none(),
            "server should not observe an anonymous client identity"
        );
    }

    #[tokio::test]
    async fn lifecycle_close_check_and_closed_report_terminal_error() {
        let pair = connected_pair().await;
        let client = &pair.client;
        let server = &pair.server;
        Lifecycle::check(client.as_ref()).expect("client initially live");
        Lifecycle::check(server.as_ref()).expect("server initially live");

        Lifecycle::close(
            client.as_ref(),
            Code::H3_REQUEST_CANCELLED,
            Cow::Borrowed("done"),
        );

        let error = with_timeout(Lifecycle::closed(server.as_ref())).await;
        assert!(
            error.is_application() || error.is_transport(),
            "closed should report a terminal connection error"
        );
        let checked = Lifecycle::check(server.as_ref()).expect_err("terminal error is latched");
        assert_eq!(checked.to_string(), error.to_string());
        let repeated = Lifecycle::closed(server.as_ref())
            .now_or_never()
            .expect("latched closed should resolve immediately");
        assert_eq!(repeated.to_string(), error.to_string());
    }

    #[tokio::test]
    async fn stale_latched_connection_error_is_discarded() {
        let pair = connected_pair().await;
        let connection = pair.client.as_ref();
        let key = dquic_connection_key(connection);
        let stale_origin = Some(DquicConnectionId::from_slice(b"not-current"));

        latch_connection_error(connection, stale_origin, transport_connection_error(0x31));

        assert!(latched_connection_error(connection).is_none());
        assert!(dquic_connection_latches().get(&key).is_none());
        close_pair(&pair);
    }

    #[tokio::test]
    async fn connection_error_latch_reuses_current_origin_and_replaces_stale_origin() {
        let pair = connected_pair().await;
        let connection = pair.client.as_ref();
        let key = dquic_connection_key(connection);
        let origin = dquic_origin_dcid(connection);
        let stale_origin = Some(DquicConnectionId::from_slice(b"not-current"));
        dquic_connection_latches().remove(&key);

        let first = latch_connection_error(connection, origin, transport_connection_error(0x32));
        assert_transport_error(
            first,
            VarInt::from_u32(0x32),
            VarInt::from_u32(0),
            "test transport 50",
        );

        let reused = latch_connection_error(connection, origin, transport_connection_error(0x33));
        assert_transport_error(
            reused,
            VarInt::from_u32(0x32),
            VarInt::from_u32(0),
            "test transport 50",
        );

        let replaced =
            latch_connection_error(connection, stale_origin, transport_connection_error(0x34));
        assert_transport_error(
            replaced,
            VarInt::from_u32(0x34),
            VarInt::from_u32(0),
            "test transport 52",
        );
        assert!(latched_connection_error(connection).is_none());

        let converted = convert_and_latch_connection_error(
            connection,
            DquicError::Quic(QuicError::with_default_fty(
                ErrorKind::ProtocolViolation,
                "converted failure",
            )),
        );
        assert_transport_error(
            converted,
            VarInt::from_u32(0x0a),
            VarInt::from_u32(0),
            "converted failure",
        );

        dquic_connection_latches().remove(&key);
        close_pair(&pair);
    }

    #[tokio::test]
    async fn listen_impls_for_references_and_arcs_shutdown_accept_queue() {
        let listeners = make_raw_listeners();

        quic::Listen::shutdown(listeners.as_ref())
            .await
            .expect("direct listener shutdown");

        let mut by_ref = listeners.as_ref();
        quic::Listen::shutdown(&by_ref)
            .await
            .expect("reference listener shutdown");
        assert!(quic::Listen::accept(&mut by_ref).await.is_err());

        let mut by_arc = listeners.clone();
        quic::Listen::shutdown(&by_arc)
            .await
            .expect("arc listener shutdown");
        assert!(quic::Listen::accept(&mut by_arc).await.is_err());
    }

    #[tokio::test]
    async fn isolated_raw_listener_configs_allow_concurrent_listener_instances() {
        let first = make_raw_listeners();
        let second = make_raw_listeners();

        quic::Listen::shutdown(first.as_ref())
            .await
            .expect("first isolated listener shutdown");
        quic::Listen::shutdown(second.as_ref())
            .await
            .expect("second isolated listener shutdown");
    }

    #[tokio::test]
    async fn connect_impl_formats_authority_with_and_without_port() {
        let resolver = Arc::new(RecordingResolver::default());
        let client = Arc::new(
            dquic::prelude::QuicClient::builder()
                .with_resolver(resolver.clone())
                .without_verifier()
                .without_cert()
                .build(),
        );
        let with_port = "example.test:8443"
            .parse::<Authority>()
            .expect("authority with port parses");
        let without_port = "example.test"
            .parse::<Authority>()
            .expect("authority without port parses");

        let first = quic::Connect::connect(&client, &with_port)
            .await
            .expect("connect with port");
        let second = quic::Connect::connect(&client, &without_port)
            .await
            .expect("connect without port");

        assert_eq!(
            resolver.names(),
            vec!["example.test:8443".to_owned(), "example.test".to_owned()]
        );
        assert_eq!(format!("{}", resolver.as_ref()), "recording resolver");
        Lifecycle::close(first.as_ref(), Code::H3_NO_ERROR, Cow::Borrowed(""));
        Lifecycle::close(second.as_ref(), Code::H3_NO_ERROR, Cow::Borrowed(""));
    }

    #[tokio::test]
    async fn dquic_local_authority_exposes_identity_and_signing() {
        let identity = make_identity();
        let certified_key =
            crate::dquic::identity::build_certified_key(&identity).expect("test key should load");
        let local = DquicLocalAuthority {
            name: Arc::from(identity.name.as_str()),
            certified_key,
        };

        assert_eq!(authority::LocalAuthority::name(&local), "localhost");
        assert_eq!(
            authority::LocalAuthority::cert_chain(&local),
            identity.cert_chain()
        );
        assert_eq!(
            authority::LocalAuthority::sign_algorithm(&local),
            rustls::SignatureAlgorithm::ECDSA
        );
        assert!(format!("{local:?}").contains("DquicLocalAuthority"));

        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        let signature = authority::LocalAuthority::sign(&local, scheme, b"payload")
            .await
            .expect("signature");
        assert!(
            authority::LocalAuthority::verify(&local, scheme, b"payload", &signature)
                .await
                .expect("verification should run")
        );
        assert!(
            !authority::LocalAuthority::verify(&local, scheme, b"wrong payload", &signature)
                .await
                .expect("verification should run")
        );
    }

    #[tokio::test]
    async fn dquic_local_authority_reports_unsupported_sign_scheme() {
        let identity = make_identity();
        let certified_key =
            crate::dquic::identity::build_certified_key(&identity).expect("test key should load");
        let local = DquicLocalAuthority {
            name: Arc::from(identity.name.as_str()),
            certified_key,
        };

        let error =
            authority::LocalAuthority::sign(&local, SignatureScheme::RSA_PKCS1_SHA256, b"payload")
                .await
                .expect_err("rsa should not be supported by an ecdsa key");
        assert!(matches!(
            error,
            SignError::UnsupportedScheme {
                scheme: SignatureScheme::RSA_PKCS1_SHA256
            }
        ));
    }

    #[tokio::test]
    async fn dquic_remote_authority_exposes_identity_and_verification() {
        let identity = make_identity();
        let certified_key =
            crate::dquic::identity::build_certified_key(&identity).expect("test key should load");
        let local = DquicLocalAuthority {
            name: Arc::from(identity.name.as_str()),
            certified_key,
        };
        let remote = DquicRemoteAuthority {
            name: Arc::from("peer.localhost"),
            cert_chain: Arc::from(identity.cert_chain()),
        };

        assert_eq!(authority::RemoteAuthority::name(&remote), "peer.localhost");
        assert_eq!(
            authority::RemoteAuthority::cert_chain(&remote),
            identity.cert_chain()
        );
        assert_eq!(
            authority::RemoteAuthority::public_key(&remote).as_ref(),
            authority::LocalAuthority::public_key(&local).as_ref()
        );
        assert!(format!("{remote:?}").contains("DquicRemoteAuthority"));

        let scheme = SignatureScheme::ECDSA_NISTP256_SHA256;
        let signature = authority::LocalAuthority::sign(&local, scheme, b"payload")
            .await
            .expect("signature");
        assert!(
            authority::RemoteAuthority::verify(&remote, scheme, b"payload", &signature)
                .await
                .expect("verification should run")
        );
        assert!(
            !authority::RemoteAuthority::verify(&remote, scheme, b"wrong payload", &signature)
                .await
                .expect("verification should run")
        );
    }

    #[tokio::test]
    async fn bidirectional_stream_wrappers_expose_ids_and_transfer_bytes() {
        let pair = connected_pair().await;
        let (mut client_reader, mut client_writer) =
            with_timeout(quic::ManageStream::open_bi(pair.client.as_ref()))
                .await
                .expect("client opens stream");

        let client_reader_id = client_reader.stream_id().await.expect("client reader id");
        let client_writer_id = client_writer.stream_id().await.expect("client writer id");
        assert_eq!(client_reader_id, client_writer_id);

        client_writer
            .send(Bytes::from_static(b"client payload"))
            .await
            .expect("client sends request bytes");

        let (mut server_reader, mut server_writer) =
            with_timeout(quic::ManageStream::accept_bi(pair.server.as_ref()))
                .await
                .expect("server accepts stream");
        let server_reader_id = server_reader.stream_id().await.expect("server reader id");
        let server_writer_id = server_writer.stream_id().await.expect("server writer id");
        assert_eq!(server_reader_id, server_writer_id);
        assert_eq!(client_reader_id, server_reader_id);
        assert_eq!(server_reader.size_hint(), (0, None));

        let received = with_timeout(server_reader.next())
            .await
            .expect("server receives a chunk")
            .expect("server chunk is ok");
        assert_eq!(received, Bytes::from_static(b"client payload"));

        server_writer
            .send(Bytes::from_static(b"server payload"))
            .await
            .expect("server sends response bytes");
        let received = with_timeout(client_reader.next())
            .await
            .expect("client receives a chunk")
            .expect("client chunk is ok");
        assert_eq!(received, Bytes::from_static(b"server payload"));

        with_timeout(client_writer.close())
            .await
            .expect("client writer closes");
        with_timeout(server_writer.close())
            .await
            .expect("server writer closes");
        close_pair(&pair);
    }

    #[tokio::test]
    async fn unidirectional_stream_wrappers_expose_ids_and_transfer_bytes() {
        let pair = connected_pair().await;
        let mut client_writer = with_timeout(quic::ManageStream::open_uni(pair.client.as_ref()))
            .await
            .expect("client opens unidirectional stream");

        let client_stream_id = client_writer.stream_id().await.expect("client writer id");
        client_writer
            .send(Bytes::from_static(b"one-way payload"))
            .await
            .expect("client sends unidirectional bytes");

        let mut server_reader = with_timeout(quic::ManageStream::accept_uni(pair.server.as_ref()))
            .await
            .expect("server accepts unidirectional stream");
        let server_stream_id = server_reader.stream_id().await.expect("server reader id");
        assert_eq!(client_stream_id, server_stream_id);

        let received = with_timeout(server_reader.next())
            .await
            .expect("server receives unidirectional chunk")
            .expect("server unidirectional chunk is ok");
        assert_eq!(received, Bytes::from_static(b"one-way payload"));

        with_timeout(client_writer.close())
            .await
            .expect("client unidirectional writer closes");
        close_pair(&pair);
    }

    #[tokio::test]
    async fn stream_stop_and_reset_wrappers_complete() {
        let pair = connected_pair().await;
        let mut client_writer = with_timeout(quic::ManageStream::open_uni(pair.client.as_ref()))
            .await
            .expect("client opens stream for stop");
        client_writer
            .send(Bytes::from_static(b"stop payload"))
            .await
            .expect("client sends bytes before stop");

        let mut server_reader = with_timeout(quic::ManageStream::accept_uni(pair.server.as_ref()))
            .await
            .expect("server accepts stream for stop");

        server_reader
            .stop(VarInt::from_u32(0x10))
            .await
            .expect("stop-sending completes on reader wrapper");
        client_writer
            .reset(VarInt::from_u32(0x11))
            .await
            .expect("reset completes on writer wrapper");
        close_pair(&pair);
    }
}
