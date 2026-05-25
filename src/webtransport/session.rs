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
    codec::{BoxReadStream, BoxWriteStream, EncodeExt, EncodeInto, SinkWriter},
    extended_connect::EstablishedConnect,
    quic::{self},
    stream_id::StreamId,
    varint::VarInt,
};

// ============================================================================
// Stream type aliases
// ============================================================================

/// A routed bidirectional stream (reader + writer) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedBiStream = (BoxReadStream, BoxWriteStream);

/// A routed unidirectional stream (reader only) after signal/session-ID
/// consumption by the protocol layer.
pub(super) type RoutedUniStream = BoxReadStream;

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
    pub async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
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
    pub async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
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
    pub async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), AcceptStreamError> {
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
    pub async fn accept_uni(&self) -> Result<BoxReadStream, AcceptStreamError> {
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
    writer: BoxWriteStream,
    signal: VarInt,
    session_id: StreamId,
) -> Result<BoxWriteStream, OpenStreamError> {
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
    codec_writer: &mut SinkWriter<BoxWriteStream>,
    value: T,
) -> Result<(), quic::StreamError>
where
    T: Send,
    for<'a> T: EncodeInto<&'a mut SinkWriter<BoxWriteStream>, Error = std::io::Error, Output = ()>,
{
    codec_writer.encode_one(value).await?;
    Ok(())
}

async fn flush_header(
    codec_writer: &mut SinkWriter<BoxWriteStream>,
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
    use std::sync::Arc;

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        extended_connect::EstablishedConnect,
        message::test::{read_stream_for_test, write_stream_for_test},
        protocol::Protocols,
        qpack::field::Protocol,
        quic,
        stream_id::StreamId,
        varint::VarInt,
        webtransport::{WEBTRANSPORT_H3, WebTransportProtocol},
    };

    const fn assert_send_sync<T: Send + Sync>() {}
    const _: () = assert_send_sync::<WebTransportSession>();

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
}
