//! WebTransport over HTTP/3 protocol layer.
//!
//! Provides a [`WebTransportProtocol`] layer that integrates into h3x's layered
//! protocol architecture to route WebTransport streams to registered sessions.
//!
//! # Overview
//!
//! WebTransport (draft-ietf-webtrans-http3) enables multiplexed, bidirectional
//! and unidirectional streams within an HTTP/3 connection. A session is
//! established via Extended CONNECT with `:protocol=webtransport-h3`, after which
//! both peers can open streams associated with that session.
//!
//! # Stream identification
//!
//! WebTransport streams carry a signal value and session ID prefix:
//!
//! - **Bidirectional**: `VarInt(0x41)` + `VarInt(session_id)` + application data
//! - **Unidirectional**: `VarInt(0x54)` + `VarInt(session_id)` + application data
//!
//! The protocol layer peeks these bytes, routes the stream to the correct
//! [`WebTransportSession`], and delivers it with the prefix already consumed.
//!
//! # Usage
//!
//! ```ignore
//! let (response, connect) = h3x::hyper::extended_connect::accept(request).await?;
//! let session = h3x::webtransport::WebTransportSession::try_from(connect)?;
//! let (reader, writer) = session.open_bi().await?;
//! let (reader, writer) = session.accept_bi().await?;
//! let reader = session.accept_uni().await?;
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```

use futures::future::BoxFuture;

use crate::{
    quic::{BoxQuicStreamReader, BoxQuicStreamWriter, ReadStream, WriteStream},
    stream_id::StreamId,
};

mod error;
mod protocol;
mod registry;
mod session;

pub use error::{
    AcceptStreamError, DatagramError, OpenStreamError, RegisterSessionError, SessionClosed,
};
#[cfg(feature = "rpc")]
pub(crate) use error::{accept_stream_error, open_stream_error};
pub use protocol::{
    WEBTRANSPORT_BIDI_SIGNAL, WEBTRANSPORT_H3, WEBTRANSPORT_UNI_SIGNAL, WT_SESSION_GONE,
    WebTransportProtocol, WebTransportProtocolFactory,
};
pub use session::{
    WebTransportSession,
    stream::{WebTransportStreamReader, WebTransportStreamWriter},
};

// ============================================================================
// Session trait (AFIT)
// ============================================================================

/// Stream management for a WebTransport session.
///
/// This is the AFIT (async fn in trait) version with concrete associated types.
/// A blanket impl provides [`DynSession`] automatically.
pub trait Session: Send + Sync {
    type StreamReader: ReadStream + Unpin;
    type StreamWriter: WriteStream + Unpin;

    fn id(&self) -> StreamId;

    fn open_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError>>
    + Send
    + '_;

    fn open_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamWriter, OpenStreamError>> + Send + '_;

    fn accept_bi(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), AcceptStreamError>>
    + Send
    + '_;

    fn accept_uni(
        &self,
    ) -> impl Future<Output = Result<Self::StreamReader, AcceptStreamError>> + Send + '_;
}

// ============================================================================
// DynSession trait (object-safe)
// ============================================================================

/// Object-safe version of [`Session`] with type-erased streams.
///
/// Stream types are fixed to [`BoxQuicStreamReader`] / [`BoxQuicStreamWriter`].
/// A blanket impl is provided for all `T: Session`.
pub trait DynSession: Send + Sync {
    fn id(&self) -> StreamId;

    #[allow(clippy::type_complexity)]
    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxQuicStreamReader, BoxQuicStreamWriter), OpenStreamError>>;

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxQuicStreamWriter, OpenStreamError>>;

    #[allow(clippy::type_complexity)]
    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxQuicStreamReader, BoxQuicStreamWriter), AcceptStreamError>>;

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxQuicStreamReader, AcceptStreamError>>;
}

impl<T: Session> DynSession for T {
    fn id(&self) -> StreamId {
        Session::id(self)
    }

    fn open_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxQuicStreamReader, BoxQuicStreamWriter), OpenStreamError>> {
        Box::pin(async {
            let (r, w) = Session::open_bi(self).await?;
            Ok((
                Box::pin(r) as BoxQuicStreamReader,
                Box::pin(w) as BoxQuicStreamWriter,
            ))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxQuicStreamWriter, OpenStreamError>> {
        Box::pin(async {
            let w = Session::open_uni(self).await?;
            Ok(Box::pin(w) as BoxQuicStreamWriter)
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxQuicStreamReader, BoxQuicStreamWriter), AcceptStreamError>> {
        Box::pin(async {
            let (r, w) = Session::accept_bi(self).await?;
            Ok((
                Box::pin(r) as BoxQuicStreamReader,
                Box::pin(w) as BoxQuicStreamWriter,
            ))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxQuicStreamReader, AcceptStreamError>> {
        Box::pin(async {
            let r = Session::accept_uni(self).await?;
            Ok(Box::pin(r) as BoxQuicStreamReader)
        })
    }
}

// ============================================================================
// impl Session for WebTransportSession
// ============================================================================

impl Session for WebTransportSession {
    type StreamReader = WebTransportStreamReader;
    type StreamWriter = WebTransportStreamWriter;

    fn id(&self) -> StreamId {
        WebTransportSession::id(self)
    }

    async fn open_bi(&self) -> Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError> {
        WebTransportSession::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, OpenStreamError> {
        WebTransportSession::open_uni(self).await
    }

    async fn accept_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), AcceptStreamError> {
        WebTransportSession::accept_bi(self).await
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, AcceptStreamError> {
        WebTransportSession::accept_uni(self).await
    }
}

#[cfg(test)]
mod tests {
    use std::{future, sync::Arc};

    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};

    use super::*;
    use crate::{
        connection::{ConnectionState, tests::MockConnection},
        extended_connect::{EstablishedConnect, PendingWriteStreamError},
        message::{stream::MessageWriter, test::read_stream_for_test},
        protocol::Protocols,
        qpack::field::Protocol,
        quic::{self, GetStreamIdExt},
        varint::VarInt,
    };

    #[derive(Debug)]
    struct TestSession {
        id: StreamId,
    }

    #[derive(Debug)]
    struct FailingSession {
        id: StreamId,
    }

    impl TestSession {
        fn new(id: StreamId) -> Self {
            Self { id }
        }
    }

    fn boxed_stream_pair(stream_id: u32) -> (BoxQuicStreamReader, BoxQuicStreamWriter) {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        (
            Box::pin(reader) as BoxQuicStreamReader,
            Box::pin(writer) as BoxQuicStreamWriter,
        )
    }

    fn connection_with_webtransport(
        mock: Arc<MockConnection>,
    ) -> Arc<ConnectionState<dyn quic::DynConnection>> {
        let erased: Arc<dyn quic::DynConnection> = mock.clone();
        let mut protocols = Protocols::new();
        protocols.insert(WebTransportProtocol::new_for_test(erased));
        Arc::new(ConnectionState::new_for_test(mock, Arc::new(protocols)).erase())
    }

    fn webtransport_session_for_test(
        mock: Arc<MockConnection>,
        stream_id: StreamId,
    ) -> WebTransportSession {
        WebTransportSession::try_from(EstablishedConnect::pending(
            stream_id,
            Some(Protocol::new(WEBTRANSPORT_H3)),
            connection_with_webtransport(mock),
            read_stream_for_test(stream_id.0),
            future::pending::<Result<MessageWriter, PendingWriteStreamError>>(),
        ))
        .expect("webtransport session should be registered")
    }

    fn connection_error(reason: &'static str) -> quic::ConnectionError {
        quic::ConnectionError::Transport {
            source: quic::TransportError {
                kind: VarInt::from_u32(0x01),
                frame_type: VarInt::from_u32(0x00),
                reason: reason.into(),
            },
        }
    }

    fn assert_transport_reason(error: &quic::ConnectionError, expected_reason: &str) {
        match error {
            quic::ConnectionError::Transport { source } => {
                assert_eq!(source.reason.as_ref(), expected_reason);
            }
            other => panic!("expected transport error, got {other:?}"),
        }
    }

    impl Session for TestSession {
        type StreamReader = BoxQuicStreamReader;
        type StreamWriter = BoxQuicStreamWriter;

        fn id(&self) -> StreamId {
            self.id
        }

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError> {
            Ok(boxed_stream_pair(1))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, OpenStreamError> {
            let (_reader, writer) = boxed_stream_pair(2);
            Ok(writer)
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), AcceptStreamError> {
            Ok(boxed_stream_pair(3))
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, AcceptStreamError> {
            let (reader, _writer) = boxed_stream_pair(4);
            Ok(reader)
        }
    }

    impl Session for FailingSession {
        type StreamReader = BoxQuicStreamReader;
        type StreamWriter = BoxQuicStreamWriter;

        fn id(&self) -> StreamId {
            self.id
        }

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), OpenStreamError> {
            Err(OpenStreamError::Closed {
                source: SessionClosed,
            })
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, OpenStreamError> {
            Err(OpenStreamError::Closed {
                source: SessionClosed,
            })
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), AcceptStreamError> {
            Err(AcceptStreamError::Closed {
                source: SessionClosed,
            })
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, AcceptStreamError> {
            Err(AcceptStreamError::Closed {
                source: SessionClosed,
            })
        }
    }

    async fn assert_roundtrip(
        reader: &mut BoxQuicStreamReader,
        writer: &mut BoxQuicStreamWriter,
        payload: &'static [u8],
    ) {
        let bytes = Bytes::from_static(payload);
        writer
            .send(bytes.clone())
            .await
            .expect("stream write should succeed");
        let received = reader
            .next()
            .await
            .expect("reader should receive one chunk")
            .expect("stream read should succeed");

        assert_eq!(received, bytes);
    }

    #[tokio::test]
    async fn dyn_session_delegates_all_stream_operations() {
        let session = TestSession::new(StreamId(VarInt::from_u32(42)));
        let dyn_session: &dyn DynSession = &session;

        assert_eq!(dyn_session.id(), StreamId(VarInt::from_u32(42)));

        let (mut reader, mut writer) = dyn_session.open_bi().await.expect("open_bi should succeed");
        assert_eq!(reader.stream_id().await.unwrap(), VarInt::from_u32(1));
        assert_eq!(writer.stream_id().await.unwrap(), VarInt::from_u32(1));
        assert_roundtrip(&mut reader, &mut writer, b"open-bidi").await;

        let mut writer = dyn_session
            .open_uni()
            .await
            .expect("open_uni should succeed");
        assert_eq!(writer.stream_id().await.unwrap(), VarInt::from_u32(2));

        let (mut reader, mut writer) = dyn_session
            .accept_bi()
            .await
            .expect("accept_bi should succeed");
        assert_eq!(reader.stream_id().await.unwrap(), VarInt::from_u32(3));
        assert_eq!(writer.stream_id().await.unwrap(), VarInt::from_u32(3));
        assert_roundtrip(&mut reader, &mut writer, b"accept-bidi").await;

        let mut reader = dyn_session
            .accept_uni()
            .await
            .expect("accept_uni should succeed");
        assert_eq!(reader.stream_id().await.unwrap(), VarInt::from_u32(4));
    }

    #[tokio::test]
    async fn dyn_session_preserves_operation_errors() {
        let session = FailingSession {
            id: StreamId(VarInt::from_u32(7)),
        };
        let dyn_session: &dyn DynSession = &session;

        assert_eq!(dyn_session.id(), StreamId(VarInt::from_u32(7)));
        assert!(matches!(
            dyn_session.open_bi().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            dyn_session.open_uni().await,
            Err(OpenStreamError::Closed { .. })
        ));
        assert!(matches!(
            dyn_session.accept_bi().await,
            Err(AcceptStreamError::Closed { .. })
        ));
        assert!(matches!(
            dyn_session.accept_uni().await,
            Err(AcceptStreamError::Closed { .. })
        ));
    }

    #[tokio::test]
    async fn dyn_session_bridge_uses_webtransport_session_open_impls() {
        let mock = Arc::new(MockConnection::new());
        mock.enable_stream_ops();
        let session_id = StreamId(VarInt::from_u32(44));
        let session = webtransport_session_for_test(Arc::clone(&mock), session_id);
        let dyn_session: &dyn DynSession = &session;

        assert_eq!(dyn_session.id(), session_id);

        let (mut reader, mut writer) = dyn_session.open_bi().await.expect("open_bi should work");
        assert_eq!(reader.stream_id().await.unwrap(), VarInt::from_u32(0));
        assert_eq!(writer.stream_id().await.unwrap(), VarInt::from_u32(0));

        let mut writer = dyn_session.open_uni().await.expect("open_uni should work");
        assert_eq!(writer.stream_id().await.unwrap(), VarInt::from_u32(0));

        assert_eq!(mock.stream_calls(), vec!["open_bi", "open_uni"]);
    }

    #[tokio::test]
    async fn dyn_session_bridge_uses_webtransport_session_accept_impls() {
        let mock = Arc::new(MockConnection::new());
        mock.set_terminal_error(connection_error("bidi closed"));
        let session =
            webtransport_session_for_test(Arc::clone(&mock), StreamId(VarInt::from_u32(46)));
        let dyn_session: &dyn DynSession = &session;

        match dyn_session.accept_bi().await {
            Err(AcceptStreamError::Connection { source }) => {
                assert_transport_reason(&source, "bidi closed");
            }
            Err(_) => panic!("expected connection error"),
            Ok(_) => panic!("accept_bi should fail"),
        }

        let mock = Arc::new(MockConnection::new());
        mock.set_terminal_error(connection_error("uni closed"));
        let session =
            webtransport_session_for_test(Arc::clone(&mock), StreamId(VarInt::from_u32(48)));
        let dyn_session: &dyn DynSession = &session;

        match dyn_session.accept_uni().await {
            Err(AcceptStreamError::Connection { source }) => {
                assert_transport_reason(&source, "uni closed");
            }
            Err(_) => panic!("expected connection error"),
            Ok(_) => panic!("accept_uni should fail"),
        }
    }

    #[cfg(feature = "rpc")]
    mod lifecycle_ext_tests {
        use std::{borrow::Cow, future::pending};

        use super::*;
        use crate::{
            error::Code,
            rpc::{
                lifecycle::{
                    ConnectionErrorLatch, HasLatch, LifecycleExt as ConnectionLifecycleExt,
                },
                webtransport::LifecycleExt as _,
            },
        };

        #[derive(Debug, Default)]
        struct TestLifecycle {
            latch: ConnectionErrorLatch,
        }

        impl HasLatch for TestLifecycle {
            fn latch(&self) -> &ConnectionErrorLatch {
                &self.latch
            }
        }

        impl quic::Lifecycle for TestLifecycle {
            fn close(&self, _code: Code, _reason: Cow<'static, str>) {}

            fn check(&self) -> Result<(), quic::ConnectionError> {
                self.check_with_probe(|| None)
            }

            async fn closed(&self) -> quic::ConnectionError {
                self.resolve_closed(pending()).await
            }
        }

        fn connection_error(reason: &'static str) -> quic::ConnectionError {
            quic::ConnectionError::Transport {
                source: quic::TransportError {
                    kind: VarInt::from_u32(0x01),
                    frame_type: VarInt::from_u32(0x00),
                    reason: reason.into(),
                },
            }
        }

        #[tokio::test]
        async fn module_scoped_lifecycle_ext_path_exposes_helper_set() {
            let lifecycle = TestLifecycle::default();

            lifecycle.check_open().expect("open check should pass");
            lifecycle.check_accept().expect("accept check should pass");

            lifecycle
                .guard_open(async { Ok::<_, OpenStreamError>(()) })
                .await
                .expect("guard_open should be available on the module path");

            let lifecycle = TestLifecycle::default();
            lifecycle
                .guard_accept(async { Ok::<_, AcceptStreamError>(()) })
                .await
                .expect("guard_accept should be available on the module path");

            let lifecycle = TestLifecycle::default();
            lifecycle
                .guard_accept_err(async { Err::<(), _>("closed") }, |_| None)
                .await
                .expect_err("guard_accept_err should be available on the module path");

            let lifecycle = TestLifecycle::default();
            lifecycle
                .guard_open_with(async { Err::<(), _>("open") }, |_| OpenStreamError::Open {
                    source: connection_error("open"),
                })
                .await
                .expect_err("guard_open_with should be available on the old path");
        }
    }
}
