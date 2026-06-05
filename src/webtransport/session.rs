//! WebTransport session handle.
//!
//! A [`WebTransportSession`] is created from an
//! [`EstablishedConnect`](crate::extended_connect::EstablishedConnect) and
//! provides the application-facing API for opening and accepting streams within a
//! WebTransport session.
//!
//! Dropping the session automatically unregisters it from the protocol registry.

use std::{fmt, sync::Arc};

use snafu::ResultExt;
use tokio::{io::AsyncWriteExt, sync::mpsc};
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument;

use super::{
    error::{
        AcceptStreamError, DatagramError, OpenStreamError, RegisterSessionError, SessionClosed,
        UnsupportedSnafu, accept_stream_error, open_stream_error,
    },
    protocol::{WEBTRANSPORT_BIDI_SIGNAL, WEBTRANSPORT_H3, WEBTRANSPORT_UNI_SIGNAL},
    registry::{RegisteredSession, SessionState},
};
use crate::{
    codec::{EncodeExt, EncodeInto, SinkWriter},
    extended_connect::EstablishedConnect,
    quic::{self, BoxQuicStreamReader, BoxQuicStreamWriter},
    stream_id::StreamId,
    varint::VarInt,
};

// ============================================================================
// Stream type aliases
// ============================================================================

/// A routed bidirectional stream (reader + writer) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedBiStream = (BoxQuicStreamReader, BoxQuicStreamWriter);

/// A routed unidirectional stream (reader only) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedUniStream = BoxQuicStreamReader;

// ============================================================================
// WebTransportSession
// ============================================================================

/// Handle for a registered WebTransport session.
///
/// Provides stream management for a single session: accepting streams routed
/// by the protocol layer and opening new streams to the remote peer.
///
/// Dropping the handle automatically unregisters the session from the protocol
/// registry.
pub struct WebTransportSession {
    state: Arc<SessionState>,
    bidi_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedBiStream>>,
    uni_rx: tokio::sync::Mutex<mpsc::Receiver<RoutedUniStream>>,
    conn: Arc<dyn quic::DynConnection>,
    _control_task: AbortOnDropHandle<()>,
}

impl WebTransportSession {
    fn from_registered(
        registered: RegisteredSession,
        conn: Arc<dyn quic::DynConnection>,
        connect: EstablishedConnect,
    ) -> Self {
        let state = registered.state;
        let task_state = Arc::clone(&state);
        let control_task = async move {
            match connect.into_streams().await {
                Ok((mut read, _write)) => loop {
                    match read.read_data_chunk().await {
                        Ok(Some(_chunk)) => {}
                        Ok(None) => break,
                        Err(error) => {
                            tracing::debug!(
                                error = %snafu::Report::from_error(&error),
                                "webtransport connect stream read failed"
                            );
                            break;
                        }
                    }
                },
                Err(error) => {
                    tracing::debug!(
                        error = %snafu::Report::from_error(&error),
                        "failed to take over webtransport connect stream"
                    );
                }
            }
            task_state.close();
        };

        Self {
            state,
            bidi_rx: tokio::sync::Mutex::new(registered.bidi_rx),
            uni_rx: tokio::sync::Mutex::new(registered.uni_rx),
            conn,
            _control_task: AbortOnDropHandle::new(tokio::spawn(control_task.in_current_span())),
        }
    }

    /// The session ID (QUIC stream ID of the CONNECT stream that established
    /// this session).
    pub fn id(&self) -> StreamId {
        self.state.id()
    }

    /// Open a new bidirectional stream within this session.
    ///
    /// Writes the WebTransport bidi signal value (`0x41`) and the session ID as
    /// a routing header, then returns the raw stream pair positioned after the
    /// header.
    pub async fn open_bi(
        &self,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), OpenStreamError> {
        self.state
            .check_open()
            .context(open_stream_error::ClosedSnafu)?;
        let (reader, writer) = self
            .conn
            .open_bi()
            .await
            .context(open_stream_error::OpenSnafu)?;
        let writer = write_header(writer, WEBTRANSPORT_BIDI_SIGNAL, self.id()).await?;
        Ok((reader, writer))
    }

    /// Open a new unidirectional stream within this session.
    ///
    /// Writes the WebTransport uni signal value (`0x54`) and the session ID as
    /// a routing header, then returns the write half positioned after the
    /// header.
    pub async fn open_uni(&self) -> Result<BoxQuicStreamWriter, OpenStreamError> {
        self.state
            .check_open()
            .context(open_stream_error::ClosedSnafu)?;
        let writer = self
            .conn
            .open_uni()
            .await
            .context(open_stream_error::OpenSnafu)?;
        write_header(writer, WEBTRANSPORT_UNI_SIGNAL, self.id()).await
    }

    /// Accept a bidirectional stream routed to this session by the protocol layer.
    pub async fn accept_bi(
        &self,
    ) -> Result<(BoxQuicStreamReader, BoxQuicStreamWriter), AcceptStreamError> {
        self.state
            .check_open()
            .context(accept_stream_error::ClosedSnafu)?;
        let mut rx = self.bidi_rx.lock().await;
        tokio::select! {
            biased;
            source = self.conn.closed() => {
                self.state.close();
                Err(AcceptStreamError::Connection { source })
            }
            stream = rx.recv() => stream.ok_or(SessionClosed).context(accept_stream_error::ClosedSnafu),
        }
    }

    /// Accept a unidirectional stream routed to this session by the protocol layer.
    pub async fn accept_uni(&self) -> Result<BoxQuicStreamReader, AcceptStreamError> {
        self.state
            .check_open()
            .context(accept_stream_error::ClosedSnafu)?;
        let mut rx = self.uni_rx.lock().await;
        tokio::select! {
            biased;
            source = self.conn.closed() => {
                self.state.close();
                Err(AcceptStreamError::Connection { source })
            }
            stream = rx.recv() => stream.ok_or(SessionClosed).context(accept_stream_error::ClosedSnafu),
        }
    }

    /// Send a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn send_datagram(&self, _data: &[u8]) -> Result<(), DatagramError> {
        UnsupportedSnafu.fail()
    }

    /// Receive a datagram within this session.
    ///
    /// **Not yet implemented.** Returns [`DatagramError::Unsupported`].
    pub async fn recv_datagram(&self) -> Result<Vec<u8>, DatagramError> {
        UnsupportedSnafu.fail()
    }
}

impl TryFrom<EstablishedConnect> for WebTransportSession {
    type Error = RegisterSessionError;

    fn try_from(connect: EstablishedConnect) -> Result<Self, Self::Error> {
        let protocol = match connect.protocol() {
            Some(protocol) => protocol,
            None => return Err(RegisterSessionError::MissingProtocol),
        };
        if protocol.as_str() != WEBTRANSPORT_H3 {
            let protocol = protocol.clone();
            return Err(RegisterSessionError::UnexpectedProtocol { protocol });
        }

        let (registered, conn) = {
            let protocol = connect
                .connection()
                .protocol::<super::WebTransportProtocol>()
                .ok_or(RegisterSessionError::ProtocolLayerMissing)?;
            let registered = protocol.register(connect.stream_id())?;
            let conn = protocol.connection();
            (registered, conn)
        };

        Ok(Self::from_registered(registered, conn, connect))
    }
}

// ============================================================================
// Header writing helper
// ============================================================================

/// Write the WebTransport stream routing header (signal + session_id) and flush.
async fn write_header(
    writer: BoxQuicStreamWriter,
    signal: VarInt,
    session_id: StreamId,
) -> Result<BoxQuicStreamWriter, OpenStreamError> {
    let mut codec_writer = SinkWriter::new(writer);
    encode_header_value(&mut codec_writer, signal)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    encode_header_value(&mut codec_writer, session_id)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    flush_header(&mut codec_writer)
        .await
        .context(open_stream_error::WriteHeaderSnafu)?;
    Ok(codec_writer.into_inner())
}

async fn encode_header_value<T>(
    codec_writer: &mut SinkWriter<BoxQuicStreamWriter>,
    value: T,
) -> Result<(), quic::StreamError>
where
    T: Send,
    for<'a> T:
        EncodeInto<&'a mut SinkWriter<BoxQuicStreamWriter>, Error = std::io::Error, Output = ()>,
{
    codec_writer.encode_one(value).await?;
    Ok(())
}

async fn flush_header(
    codec_writer: &mut SinkWriter<BoxQuicStreamWriter>,
) -> Result<(), quic::StreamError> {
    AsyncWriteExt::flush(codec_writer).await?;
    Ok(())
}

// ============================================================================
// Trait impls
// ============================================================================

impl fmt::Debug for WebTransportSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebTransportSession")
            .field("id", &self.id())
            .finish()
    }
}

impl Drop for WebTransportSession {
    fn drop(&mut self) {
        self.state.close();
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use dhttp_identity::identity as authority;
    use futures::{Sink, SinkExt, Stream, StreamExt, future, future::pending};
    use tokio::time::{Duration, timeout};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::{Instrument, Level};

    use super::*;
    use crate::{
        codec::StreamReader,
        connection::{ConnectionState, tests::MockConnection},
        dhttp::{protocol::DHttpProtocol, settings::Settings},
        extended_connect::EstablishedConnect,
        message::{
            stream::{MessageReader, guard},
            test::{read_stream_for_test, write_stream_for_test},
        },
        protocol::Protocols,
        qpack::{field::Protocol, protocol::QPackDecoder},
        quic,
        stream_id::StreamId,
        varint::VarInt,
        webtransport::{WEBTRANSPORT_H3, WebTransportProtocol, registry::Registry},
    };

    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<WebTransportSession>();

    #[derive(Debug, Default)]
    struct StreamState {
        written: Mutex<Vec<u8>>,
        stopped: Mutex<Vec<VarInt>>,
        resets: Mutex<Vec<VarInt>>,
        flushes: Mutex<usize>,
    }

    impl StreamState {
        fn written(&self) -> Vec<u8> {
            self.written.lock().expect("written lock poisoned").clone()
        }

        fn reset_codes(&self) -> Vec<VarInt> {
            self.resets.lock().expect("resets lock poisoned").clone()
        }

        fn stopped_codes(&self) -> Vec<VarInt> {
            self.stopped.lock().expect("stopped lock poisoned").clone()
        }

        fn flushes(&self) -> usize {
            *self.flushes.lock().expect("flushes lock poisoned")
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        state: Arc<StreamState>,
        chunks: VecDeque<Bytes>,
        stream_id: VarInt,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    impl quic::GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .stopped
                .lock()
                .expect("stopped lock poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            let mut flushes = self.state.flushes.lock().expect("flushes lock poisoned");
            *flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum HeaderFailureMode {
        SendOnCall(usize),
        Flush,
    }

    #[derive(Debug)]
    struct HeaderFailWriteStream {
        mode: HeaderFailureMode,
        send_calls: usize,
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for HeaderFailWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.send_calls += 1;
            if matches!(self.mode, HeaderFailureMode::SendOnCall(call) if call == self.send_calls) {
                return Err(quic::StreamError::Reset {
                    code: VarInt::from_u32(0xe0 + self.send_calls as u32),
                });
            }

            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            if matches!(self.mode, HeaderFailureMode::Flush) {
                return Poll::Ready(Err(quic::StreamError::Reset {
                    code: VarInt::from_u32(0xef),
                }));
            }

            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl quic::GetStreamId for HeaderFailWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::ResetStream for HeaderFailWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    impl quic::GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl quic::ResetStream for TestWriteStream {
        fn poll_reset(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            self.state
                .resets
                .lock()
                .expect("resets lock poisoned")
                .push(code);
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestLocalAuthority;

    impl authority::LocalAuthority for TestLocalAuthority {
        fn name(&self) -> &str {
            "test-local"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
        fn sign(
            &self,
            _data: &[u8],
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, authority::SignError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Debug)]
    struct TestRemoteAuthority;

    impl authority::RemoteAuthority for TestRemoteAuthority {
        fn name(&self) -> &str {
            "test-remote"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &[]
        }
    }

    #[derive(Debug)]
    struct TestConnection {
        state: Arc<StreamState>,
    }

    impl quic::ManageStream for TestConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            Ok((
                TestReadStream {
                    state: Arc::clone(&self.state),
                    chunks: VecDeque::new(),
                    stream_id: VarInt::from_u32(9),
                },
                TestWriteStream {
                    state: Arc::clone(&self.state),
                    stream_id: VarInt::from_u32(9),
                },
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(TestWriteStream {
                state: Arc::clone(&self.state),
                stream_id: VarInt::from_u32(10),
            })
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAuthority for TestConnection {
        type LocalAuthority = TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for TestConnection {
        type RemoteAuthority = TestRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for TestConnection {
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    #[derive(Debug)]
    struct HeaderFailConnection {
        mode: HeaderFailureMode,
        state: Arc<StreamState>,
    }

    impl quic::ManageStream for HeaderFailConnection {
        type StreamReader = TestReadStream;
        type StreamWriter = HeaderFailWriteStream;

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            Ok((
                TestReadStream {
                    state: Arc::clone(&self.state),
                    chunks: VecDeque::new(),
                    stream_id: VarInt::from_u32(21),
                },
                HeaderFailWriteStream {
                    mode: self.mode,
                    send_calls: 0,
                    state: Arc::clone(&self.state),
                    stream_id: VarInt::from_u32(21),
                },
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, quic::ConnectionError> {
            Ok(HeaderFailWriteStream {
                mode: self.mode,
                send_calls: 0,
                state: Arc::clone(&self.state),
                stream_id: VarInt::from_u32(22),
            })
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), quic::ConnectionError> {
            pending().await
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, quic::ConnectionError> {
            pending().await
        }
    }

    impl quic::WithLocalAuthority for HeaderFailConnection {
        type LocalAuthority = TestLocalAuthority;

        async fn local_authority(
            &self,
        ) -> Result<Option<Self::LocalAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::WithRemoteAuthority for HeaderFailConnection {
        type RemoteAuthority = TestRemoteAuthority;

        async fn remote_authority(
            &self,
        ) -> Result<Option<Self::RemoteAuthority>, quic::ConnectionError> {
            Ok(None)
        }
    }

    impl quic::Lifecycle for HeaderFailConnection {
        fn close(&self, _code: crate::error::Code, _reason: Cow<'static, str>) {}

        fn check(&self) -> Result<(), quic::ConnectionError> {
            Ok(())
        }

        async fn closed(&self) -> quic::ConnectionError {
            pending().await
        }
    }

    fn enable_debug_tracing_for_test() -> tracing::dispatcher::DefaultGuard {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .with_writer(std::io::sink)
            .finish();
        let dispatch = tracing::Dispatch::new(subscriber);
        tracing::dispatcher::set_default(&dispatch)
    }

    #[tokio::test]
    async fn test_stream_helpers_expose_ids_and_shutdown_codes() {
        use crate::quic::{GetStreamIdExt, ResetStreamExt, StopStreamExt};

        let state = Arc::new(StreamState::default());
        let mut reader = TestReadStream {
            state: Arc::clone(&state),
            chunks: VecDeque::from([Bytes::from_static(&[0x01])]),
            stream_id: VarInt::from_u32(41),
        };
        let mut writer = TestWriteStream {
            state: Arc::clone(&state),
            stream_id: VarInt::from_u32(42),
        };

        assert_eq!(
            reader.stream_id().await.expect("reader id"),
            VarInt::from_u32(41)
        );
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(42)
        );
        reader
            .stop(VarInt::from_u32(0x31))
            .await
            .expect("stop reader");
        writer
            .reset(VarInt::from_u32(0x32))
            .await
            .expect("reset writer");
        writer.close().await.expect("close writer");

        assert_eq!(state.stopped_codes(), vec![VarInt::from_u32(0x31)]);
        assert_eq!(state.reset_codes(), vec![VarInt::from_u32(0x32)]);
    }

    #[tokio::test]
    async fn test_agents_return_static_metadata_and_empty_signature() {
        let local = TestLocalAuthority;
        let remote = TestRemoteAuthority;

        assert_eq!(authority::LocalAuthority::name(&local), "test-local");
        assert!(authority::LocalAuthority::cert_chain(&local).is_empty());
        assert!(
            authority::LocalAuthority::sign(&local, b"payload")
                .await
                .expect("test signer")
                .is_empty()
        );

        assert_eq!(authority::RemoteAuthority::name(&remote), "test-remote");
        assert!(authority::RemoteAuthority::cert_chain(&remote).is_empty());
    }

    #[tokio::test]
    async fn test_connection_trait_methods_are_pending_or_empty() {
        let conn = TestConnection {
            state: Arc::new(StreamState::default()),
        };

        assert!(
            quic::WithLocalAuthority::local_authority(&conn)
                .await
                .expect("local authority")
                .is_none()
        );
        assert!(
            quic::WithRemoteAuthority::remote_authority(&conn)
                .await
                .expect("remote authority")
                .is_none()
        );
        quic::Lifecycle::check(&conn).expect("connection is open");
        quic::Lifecycle::close(
            &conn,
            crate::error::Code::from(VarInt::from_u32(0)),
            Cow::Borrowed("test close"),
        );

        timeout(
            Duration::from_millis(10),
            quic::ManageStream::accept_bi(&conn),
        )
        .await
        .expect_err("accept_bi should stay pending");
        timeout(
            Duration::from_millis(10),
            quic::ManageStream::accept_uni(&conn),
        )
        .await
        .expect_err("accept_uni should stay pending");
        timeout(Duration::from_millis(10), quic::Lifecycle::closed(&conn))
            .await
            .expect_err("closed should stay pending");
    }

    #[tokio::test]
    async fn header_fail_connection_nonfailing_mode_exercises_remaining_traits() {
        use crate::quic::{GetStreamIdExt, ResetStreamExt};

        let state = Arc::new(StreamState::default());
        let conn = HeaderFailConnection {
            mode: HeaderFailureMode::SendOnCall(99),
            state: Arc::clone(&state),
        };

        assert!(
            quic::WithLocalAuthority::local_authority(&conn)
                .await
                .expect("local authority")
                .is_none()
        );
        assert!(
            quic::WithRemoteAuthority::remote_authority(&conn)
                .await
                .expect("remote authority")
                .is_none()
        );
        quic::Lifecycle::check(&conn).expect("connection is open");
        quic::Lifecycle::close(
            &conn,
            crate::error::Code::from(VarInt::from_u32(0)),
            Cow::Borrowed("test close"),
        );
        timeout(
            Duration::from_millis(10),
            quic::ManageStream::accept_bi(&conn),
        )
        .await
        .expect_err("accept_bi should stay pending");
        timeout(
            Duration::from_millis(10),
            quic::ManageStream::accept_uni(&conn),
        )
        .await
        .expect_err("accept_uni should stay pending");
        timeout(Duration::from_millis(10), quic::Lifecycle::closed(&conn))
            .await
            .expect_err("closed should stay pending");

        let (_reader, mut writer) = quic::ManageStream::open_bi(&conn)
            .await
            .expect("open bidi stream");
        assert_eq!(
            writer.stream_id().await.expect("writer id"),
            VarInt::from_u32(21)
        );
        writer
            .send(Bytes::from_static(&[0xaa]))
            .await
            .expect("write payload");
        writer.flush().await.expect("flush writer");
        writer
            .reset(VarInt::from_u32(0x44))
            .await
            .expect("reset writer");
        writer.close().await.expect("close writer");
        assert_eq!(state.written(), vec![0xaa]);
    }

    #[tokio::test]
    async fn header_fail_write_stream_can_fail_after_prior_write() {
        let stream_state = Arc::new(StreamState::default());
        let mut writer = HeaderFailWriteStream {
            mode: HeaderFailureMode::SendOnCall(2),
            state: Arc::clone(&stream_state),
            send_calls: 0,
            stream_id: VarInt::from_u32(23),
        };

        writer
            .send(Bytes::from_static(&[0x40, 0x41]))
            .await
            .expect("first write should succeed");
        let error = writer
            .send(Bytes::from_static(&[0x04]))
            .await
            .expect_err("second write should fail");
        assert!(matches!(error, quic::StreamError::Reset { .. }));
        assert_eq!(stream_state.written(), vec![0x40, 0x41]);
    }

    fn connection_with_webtransport() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        Arc::new(ConnectionState::new_for_test(quic, Arc::new(protocols)).erase())
    }

    fn connect_with_protocol(protocol: Option<Protocol>) -> EstablishedConnect {
        let stream_id = StreamId::from(VarInt::from_u32(4));
        EstablishedConnect::ready(
            stream_id,
            protocol,
            connection_with_webtransport(),
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        )
    }

    fn connect_on_connection(
        connection: Arc<ConnectionState<dyn quic::DynConnection>>,
        stream_id: StreamId,
        protocol: Option<Protocol>,
    ) -> EstablishedConnect {
        EstablishedConnect::ready(
            stream_id,
            protocol,
            connection,
            read_stream_for_test(stream_id.0),
            write_stream_for_test(stream_id.0),
        )
    }

    fn connection_without_webtransport() -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let quic = Arc::new(MockConnection::new());
        Arc::new(ConnectionState::new_for_test(quic.clone(), Arc::new(Protocols::new())).erase())
    }

    fn noop_task() -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async {}.in_current_span()))
    }

    fn session_with_connection(
        session_id: StreamId,
        conn: Arc<dyn quic::DynConnection>,
    ) -> (Registry, WebTransportSession) {
        let registry = Registry::default();
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let session = WebTransportSession {
            state: Arc::clone(&registered.state),
            bidi_rx: tokio::sync::Mutex::new(registered.bidi_rx),
            uni_rx: tokio::sync::Mutex::new(registered.uni_rx),
            conn,
            _control_task: noop_task(),
        };
        (registry, session)
    }

    fn open_session_with_closed_receivers(
        session_id: StreamId,
        conn: Arc<dyn quic::DynConnection>,
    ) -> WebTransportSession {
        let registry = Registry::default();
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let (_bidi_tx, bidi_rx) = mpsc::channel(1);
        let (_uni_tx, uni_rx) = mpsc::channel(1);

        WebTransportSession {
            state: Arc::clone(&registered.state),
            bidi_rx: tokio::sync::Mutex::new(bidi_rx),
            uni_rx: tokio::sync::Mutex::new(uni_rx),
            conn,
            _control_task: noop_task(),
        }
    }

    fn qpack_decoder_sink() -> Pin<
        Box<
            dyn Sink<
                    crate::qpack::decoder::DecoderInstruction,
                    Error = crate::connection::StreamError,
                > + Send,
        >,
    > {
        Box::pin(
            futures::sink::drain::<crate::qpack::decoder::DecoderInstruction>()
                .sink_map_err(|never| match never {}),
        )
    }

    fn qpack_decoder_stream() -> Pin<
        Box<
            dyn Stream<
                    Item = Result<
                        crate::qpack::encoder::EncoderInstruction,
                        crate::connection::StreamError,
                    >,
                > + Send,
        >,
    > {
        Box::pin(futures::stream::empty::<
            Result<crate::qpack::encoder::EncoderInstruction, crate::connection::StreamError>,
        >())
    }

    async fn read_stream_with_bytes(stream_id: u32, bytes: &[u8]) -> MessageReader {
        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        writer
            .send(Bytes::copy_from_slice(bytes))
            .await
            .expect("write test stream bytes");
        writer.close().await.expect("close test stream writer");

        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(quic, Arc::new(protocols)).erase();

        MessageReader::new(
            VarInt::from_u32(stream_id),
            StreamReader::new(guard::GuardedQuicReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state,
        )
    }

    async fn read_stream_with_reset(stream_id: u32, code: VarInt) -> MessageReader {
        use crate::quic::ResetStreamExt;

        let (reader, mut writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        writer
            .reset(code)
            .await
            .expect("send reset to test stream reader");
        drop(writer);

        let quic = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = quic.clone();
        let mut protocols = Protocols::new();
        protocols.insert(DHttpProtocol::new_for_test(erased.clone()));
        let state = ConnectionState::new_for_test(quic, Arc::new(protocols)).erase();

        MessageReader::new(
            VarInt::from_u32(stream_id),
            StreamReader::new(guard::GuardedQuicReader::new(
                Box::pin(reader) as crate::quic::BoxQuicStreamReader
            )),
            Arc::new(QPackDecoder::new(
                Arc::new(Settings::default()),
                qpack_decoder_sink(),
                qpack_decoder_stream(),
            )),
            state,
        )
    }

    async fn wait_until_session_closed(session: &WebTransportSession) {
        timeout(Duration::from_secs(1), async {
            loop {
                if session.state.check_open().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("session should close before timeout");
    }

    fn assert_transport_reason(error: &quic::ConnectionError, expected_reason: &str) {
        match error {
            quic::ConnectionError::Transport { source } => {
                assert_eq!(source.reason.as_ref(), expected_reason);
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn try_from_established_connect_registers_session() {
        let session = WebTransportSession::try_from(connect_with_protocol(Some(Protocol::new(
            WEBTRANSPORT_H3,
        ))))
        .expect("valid webtransport connect registers session");

        assert_eq!(session.id(), StreamId::from(VarInt::from_u32(4)));
    }

    #[tokio::test]
    async fn try_from_rejects_missing_protocol() {
        let error = WebTransportSession::try_from(connect_with_protocol(None))
            .expect_err("missing protocol is invalid");
        assert!(matches!(error, RegisterSessionError::MissingProtocol));
    }

    #[tokio::test]
    async fn try_from_rejects_unexpected_protocol() {
        let error = WebTransportSession::try_from(connect_with_protocol(Some(Protocol::new(
            "other-protocol",
        ))))
        .expect_err("wrong protocol token is invalid");
        assert!(matches!(
            error,
            RegisterSessionError::UnexpectedProtocol { .. }
        ));
    }

    #[tokio::test]
    async fn try_from_rejects_missing_protocol_layer() {
        let error = WebTransportSession::try_from(connect_on_connection(
            connection_without_webtransport(),
            StreamId::from(VarInt::from_u32(4)),
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect_err("missing webtransport protocol layer is invalid");

        assert!(matches!(error, RegisterSessionError::ProtocolLayerMissing));
    }

    #[tokio::test]
    async fn try_from_rejects_duplicate_session_registration() {
        let connection = connection_with_webtransport();
        let stream_id = StreamId::from(VarInt::from_u32(4));

        let first = WebTransportSession::try_from(connect_on_connection(
            Arc::clone(&connection),
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect("first registration should succeed");

        let error = WebTransportSession::try_from(connect_on_connection(
            connection,
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
        ))
        .expect_err("duplicate session id should be rejected");

        assert!(matches!(
            error,
            RegisterSessionError::AlreadyRegistered { session_id } if session_id == stream_id
        ));

        drop(first);
    }

    #[tokio::test]
    async fn debug_includes_session_id() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        let formatted = format!("{session:?}");
        assert!(formatted.contains("WebTransportSession"));
        assert!(formatted.contains(&format!("{:?}", session.id())));
    }

    #[tokio::test]
    async fn open_bi_writes_webtransport_header_and_keeps_writer_usable() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        let (_reader, mut writer) = session.open_bi().await.expect("open_bi should succeed");
        writer
            .send(Bytes::from_static(&[0xaa, 0xbb]))
            .await
            .expect("writer should remain usable after header");

        assert_eq!(stream_state.written(), vec![0x40, 0x41, 0x04, 0xaa, 0xbb]);
        assert!(stream_state.flushes() >= 1);
        assert!(stream_state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn open_bi_maps_header_write_failure_on_first_signal_write() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(HeaderFailConnection {
            mode: HeaderFailureMode::SendOnCall(1),
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session.open_bi().await,
            Err(OpenStreamError::WriteHeader { .. })
        ));
        assert!(stream_state.written().is_empty());
    }

    #[tokio::test]
    async fn open_uni_writes_webtransport_header_and_keeps_writer_usable() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        let mut writer = session.open_uni().await.expect("open_uni should succeed");
        writer
            .send(Bytes::from_static(&[0xcc]))
            .await
            .expect("writer should remain usable after header");

        assert_eq!(stream_state.written(), vec![0x40, 0x54, 0x04, 0xcc]);
        assert!(stream_state.flushes() >= 1);
        assert!(stream_state.reset_codes().is_empty());
    }

    #[tokio::test]
    async fn open_uni_maps_buffered_header_write_failure() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(HeaderFailConnection {
            mode: HeaderFailureMode::SendOnCall(1),
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session.open_uni().await,
            Err(OpenStreamError::WriteHeader { .. })
        ));
        assert!(stream_state.written().is_empty());
    }

    #[tokio::test]
    async fn open_bi_maps_header_flush_failure() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(HeaderFailConnection {
            mode: HeaderFailureMode::Flush,
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session.open_bi().await,
            Err(OpenStreamError::WriteHeader { .. })
        ));
        assert_eq!(stream_state.written(), vec![0x40, 0x41, 0x04]);
    }

    #[tokio::test]
    async fn open_uni_maps_header_flush_failure() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(HeaderFailConnection {
            mode: HeaderFailureMode::Flush,
            state: Arc::clone(&stream_state),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session.open_uni().await,
            Err(OpenStreamError::WriteHeader { .. })
        ));
        assert_eq!(stream_state.written(), vec![0x40, 0x54, 0x04]);
    }

    #[tokio::test]
    async fn open_streams_map_connection_errors() {
        let conn = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = conn.clone();
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        let bi_error = match session.open_bi().await {
            Ok(_) => panic!("open_bi should fail"),
            Err(error) => error,
        };
        let uni_error = match session.open_uni().await {
            Ok(_) => panic!("open_uni should fail"),
            Err(error) => error,
        };

        match bi_error {
            OpenStreamError::Open { source } => {
                assert_transport_reason(&source, "open_bi unavailable");
            }
            other => panic!("expected open error, got {other:?}"),
        }

        match uni_error {
            OpenStreamError::Open { source } => {
                assert_transport_reason(&source, "open_uni unavailable");
            }
            other => panic!("expected open error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closed_session_maps_open_and_accept_to_closed_errors() {
        let conn = Arc::new(MockConnection::new());
        let erased: Arc<dyn quic::DynConnection> = conn.clone();
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);
        session.state.close();

        assert!(matches!(
            session.open_bi().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.open_uni().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.accept_bi().await,
            Err(AcceptStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.accept_uni().await,
            Err(AcceptStreamError::Closed { .. })
        ));
        assert!(conn.stream_calls().is_empty());
    }

    #[tokio::test]
    async fn accept_streams_map_dropped_receivers_to_closed_errors() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let session = open_session_with_closed_receivers(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session.accept_bi().await,
            Err(AcceptStreamError::Closed { .. })
        ));
        assert!(matches!(
            session.accept_uni().await,
            Err(AcceptStreamError::Closed { .. })
        ));
    }

    #[tokio::test]
    async fn drop_unregisters_session_and_rejects_late_routed_streams() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        assert_eq!(registry.len(), 1);

        let session_id = session.id();
        drop(session);

        let routed_state = Arc::new(StreamState::default());
        let rejected = registry.route_uni(
            session_id,
            Box::pin(TestReadStream {
                state: Arc::clone(&routed_state),
                chunks: VecDeque::from([Bytes::from_static(&[0x55])]),
                stream_id: VarInt::from_u32(13),
            }) as BoxQuicStreamReader,
        );

        assert!(rejected.is_err());
        assert_eq!(registry.len(), 0);
        assert!(routed_state.stopped_codes().is_empty());
    }

    #[tokio::test]
    async fn accept_bi_returns_routed_stream() {
        let stream_state = Arc::new(StreamState::default());
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::clone(&stream_state),
        });
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        let routed_state = Arc::new(StreamState::default());

        assert!(
            registry
                .route_bi(
                    session.id(),
                    (
                        Box::pin(TestReadStream {
                            state: Arc::clone(&routed_state),
                            chunks: VecDeque::from([Bytes::from_static(&[0x11, 0x22])]),
                            stream_id: VarInt::from_u32(11),
                        }) as BoxQuicStreamReader,
                        Box::pin(TestWriteStream {
                            state: Arc::clone(&routed_state),
                            stream_id: VarInt::from_u32(11),
                        }) as BoxQuicStreamWriter,
                    ),
                )
                .is_ok()
        );

        let (mut reader, mut writer) = session.accept_bi().await.expect("accept_bi should succeed");
        writer
            .send(Bytes::from_static(&[0x33]))
            .await
            .expect("routed writer should stay usable");

        assert_eq!(
            reader
                .next()
                .await
                .expect("reader should yield a chunk")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x11, 0x22])
        );
        assert_eq!(routed_state.written(), vec![0x33]);
        assert!(stream_state.written().is_empty());
    }

    #[tokio::test]
    async fn accept_uni_returns_routed_stream() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);
        let routed_state = Arc::new(StreamState::default());

        assert!(
            registry
                .route_uni(
                    session.id(),
                    Box::pin(TestReadStream {
                        state: Arc::clone(&routed_state),
                        chunks: VecDeque::from([Bytes::from_static(&[0x44])]),
                        stream_id: VarInt::from_u32(12),
                    }) as BoxQuicStreamReader,
                )
                .is_ok()
        );

        let mut reader = session
            .accept_uni()
            .await
            .expect("accept_uni should succeed");
        assert_eq!(
            reader
                .next()
                .await
                .expect("reader should yield a chunk")
                .expect("reader chunk should succeed"),
            Bytes::from_static(&[0x44])
        );
        assert!(routed_state.stopped_codes().is_empty());
    }

    #[tokio::test]
    async fn accept_bi_maps_connection_closed() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        match session.accept_bi().await {
            Ok(_) => panic!("accept_bi should fail"),
            Err(error) => match error {
                AcceptStreamError::Connection { source } => {
                    assert_transport_reason(&source, "connection closed");
                }
                other => panic!("expected connection error, got {other:?}"),
            },
        }
    }

    #[tokio::test]
    async fn accept_bi_prefers_connection_closed_over_queued_stream() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed with queued bidi".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);
        let routed_state = Arc::new(StreamState::default());
        assert!(
            registry
                .route_bi(
                    session.id(),
                    (
                        Box::pin(TestReadStream {
                            state: Arc::clone(&routed_state),
                            chunks: VecDeque::from([Bytes::from_static(&[0x66])]),
                            stream_id: VarInt::from_u32(14),
                        }) as BoxQuicStreamReader,
                        Box::pin(TestWriteStream {
                            state: Arc::clone(&routed_state),
                            stream_id: VarInt::from_u32(14),
                        }) as BoxQuicStreamWriter,
                    ),
                )
                .is_ok()
        );

        match session.accept_bi().await {
            Ok(_) => panic!("accept_bi should prefer closed connection"),
            Err(AcceptStreamError::Connection { source }) => {
                assert_transport_reason(&source, "connection closed with queued bidi");
            }
            Err(other) => panic!("expected connection error, got {other:?}"),
        }
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn accept_uni_prefers_connection_closed_over_queued_stream() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed with queued uni".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);
        let routed_state = Arc::new(StreamState::default());
        assert!(
            registry
                .route_uni(
                    session.id(),
                    Box::pin(TestReadStream {
                        state: Arc::clone(&routed_state),
                        chunks: VecDeque::from([Bytes::from_static(&[0x77])]),
                        stream_id: VarInt::from_u32(15),
                    }) as BoxQuicStreamReader,
                )
                .is_ok()
        );

        match session.accept_uni().await {
            Ok(_) => panic!("accept_uni should prefer closed connection"),
            Err(AcceptStreamError::Connection { source }) => {
                assert_transport_reason(&source, "connection closed with queued uni");
            }
            Err(other) => panic!("expected connection error, got {other:?}"),
        }
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn accept_uni_maps_connection_closed() {
        let conn = Arc::new(MockConnection::new());
        conn.set_terminal_error(quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(1),
                frame_type: VarInt::from_u32(0),
                reason: "connection closed".into(),
            },
        });
        let erased: Arc<dyn quic::DynConnection> = conn;
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), erased);

        match session.accept_uni().await {
            Ok(_) => panic!("accept_uni should fail"),
            Err(error) => match error {
                AcceptStreamError::Connection { source } => {
                    assert_transport_reason(&source, "connection closed");
                }
                other => panic!("expected connection error, got {other:?}"),
            },
        }
    }

    #[tokio::test]
    async fn datagram_methods_return_unsupported() {
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let (_registry, session) =
            session_with_connection(StreamId::from(VarInt::from_u32(4)), conn);

        assert!(matches!(
            session
                .send_datagram(b"hello")
                .await
                .expect_err("send_datagram should be unsupported"),
            DatagramError::Unsupported
        ));
        assert!(matches!(
            session
                .recv_datagram()
                .await
                .expect_err("recv_datagram should be unsupported"),
            DatagramError::Unsupported
        ));
    }

    #[tokio::test]
    async fn control_task_closes_session_after_connect_stream_payload_and_eof() {
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(24));
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let connect = EstablishedConnect::ready(
            session_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection_without_webtransport(),
            read_stream_with_bytes(24, &[0x00, 0x03, b'a', b'b', b'c']).await,
            write_stream_for_test(session_id.0),
        );

        let session = WebTransportSession::from_registered(registered, conn, connect);
        wait_until_session_closed(&session).await;
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn control_task_closes_session_after_connect_stream_read_error() {
        let _guard = enable_debug_tracing_for_test();
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(25));
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let connect = EstablishedConnect::ready(
            session_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection_without_webtransport(),
            read_stream_with_reset(25, VarInt::from_u32(0xaa)).await,
            write_stream_for_test(session_id.0),
        );

        let session = WebTransportSession::from_registered(registered, conn, connect);
        wait_until_session_closed(&session).await;
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn control_task_closes_session_when_connect_takeover_fails() {
        let _guard = enable_debug_tracing_for_test();
        let registry = Registry::default();
        let session_id = StreamId::from(VarInt::from_u32(26));
        let registered = registry
            .register(session_id)
            .expect("session registration should succeed");
        let conn: Arc<dyn quic::DynConnection> = Arc::new(TestConnection {
            state: Arc::new(StreamState::default()),
        });
        let connect = EstablishedConnect::pending(
            session_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection_without_webtransport(),
            read_stream_for_test(session_id.0),
            future::ready(Err(
                crate::extended_connect::PendingWriteStreamError::Aborted,
            )),
        );

        let session = WebTransportSession::from_registered(registered, conn, connect);
        wait_until_session_closed(&session).await;
        assert_eq!(registry.len(), 0);
    }
}
