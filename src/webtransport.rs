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
    codec::{BoxReadStream, BoxWriteStream},
    quic::{ReadStream, WriteStream},
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
    WEBTRANSPORT_BIDI_SIGNAL, WEBTRANSPORT_H3, WEBTRANSPORT_UNI_SIGNAL, WebTransportProtocol,
    WebTransportProtocolFactory,
};
pub use session::WebTransportSession;

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
/// Stream types are fixed to [`BoxReadStream`] / [`BoxWriteStream`].
/// A blanket impl is provided for all `T: Session`.
pub trait DynSession: Send + Sync {
    fn id(&self) -> StreamId;

    #[allow(clippy::type_complexity)]
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), OpenStreamError>>;

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, OpenStreamError>>;

    #[allow(clippy::type_complexity)]
    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), AcceptStreamError>>;

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, AcceptStreamError>>;
}

impl<T: Session> DynSession for T {
    fn id(&self) -> StreamId {
        Session::id(self)
    }

    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), OpenStreamError>> {
        Box::pin(async {
            let (r, w) = Session::open_bi(self).await?;
            Ok((Box::pin(r) as BoxReadStream, Box::pin(w) as BoxWriteStream))
        })
    }

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, OpenStreamError>> {
        Box::pin(async {
            let w = Session::open_uni(self).await?;
            Ok(Box::pin(w) as BoxWriteStream)
        })
    }

    fn accept_bi(
        &self,
    ) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), AcceptStreamError>> {
        Box::pin(async {
            let (r, w) = Session::accept_bi(self).await?;
            Ok((Box::pin(r) as BoxReadStream, Box::pin(w) as BoxWriteStream))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, AcceptStreamError>> {
        Box::pin(async {
            let r = Session::accept_uni(self).await?;
            Ok(Box::pin(r) as BoxReadStream)
        })
    }
}

// ============================================================================
// impl Session for WebTransportSession
// ============================================================================

impl Session for WebTransportSession {
    type StreamReader = BoxReadStream;
    type StreamWriter = BoxWriteStream;

    fn id(&self) -> StreamId {
        WebTransportSession::id(self)
    }

    async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
        WebTransportSession::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
        WebTransportSession::open_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), AcceptStreamError> {
        WebTransportSession::accept_bi(self).await
    }

    async fn accept_uni(&self) -> Result<BoxReadStream, AcceptStreamError> {
        WebTransportSession::accept_uni(self).await
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};

    use super::*;
    use crate::{
        quic::{self, GetStreamIdExt},
        varint::VarInt,
    };

    #[derive(Debug)]
    struct TestSession {
        id: StreamId,
    }

    impl TestSession {
        fn new(id: StreamId) -> Self {
            Self { id }
        }
    }

    fn boxed_stream_pair(stream_id: u32) -> (BoxReadStream, BoxWriteStream) {
        let (reader, writer) = quic::test::mock_stream_pair(VarInt::from_u32(stream_id));
        (
            Box::pin(reader) as BoxReadStream,
            Box::pin(writer) as BoxWriteStream,
        )
    }

    impl Session for TestSession {
        type StreamReader = BoxReadStream;
        type StreamWriter = BoxWriteStream;

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

    async fn assert_roundtrip(
        reader: &mut BoxReadStream,
        writer: &mut BoxWriteStream,
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
}
