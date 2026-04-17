//! WebTransport over HTTP/3 protocol layer.
//!
//! Provides a [`WebTransportProtocol`] layer that integrates into h3x's layered
//! protocol architecture to route WebTransport streams to registered sessions.
//!
//! # Overview
//!
//! WebTransport (draft-ietf-webtrans-http3) enables multiplexed, bidirectional
//! and unidirectional streams within an HTTP/3 connection. A session is
//! established via Extended CONNECT with `:protocol=webtransport`, after which
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
//! // Server handler: accept a WebTransport CONNECT request
//! let wt = request.protocols().get::<WebTransportProtocol>().unwrap();
//! let session = wt.register(request.stream_id().into_inner())?;
//!
//! // Open / accept streams within the session
//! let (reader, writer) = session.open_bi().await?;
//! let (reader, writer) = session.accept_bi().await?;
//! let reader = session.accept_uni().await?;
//! ```

use std::future::Future;

use futures::future::BoxFuture;

use crate::{
    codec::{BoxReadStream, BoxWriteStream},
    quic::{ReadStream, WriteStream},
    varint::VarInt,
};

mod error;
mod protocol;
mod session;

pub use error::{Closed, DatagramError, OpenSnafu, OpenStreamError, RegisterError};
pub use protocol::{
    WT_BIDI_SIGNAL, WT_UNI_SIGNAL, WebTransportProtocol, WebTransportProtocolFactory,
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

    fn session_id(&self) -> VarInt;

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
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Closed>> + Send + '_;

    fn accept_uni(&self) -> impl Future<Output = Result<Self::StreamReader, Closed>> + Send + '_;
}

// ============================================================================
// DynSession trait (object-safe)
// ============================================================================

/// Object-safe version of [`Session`] with type-erased streams.
///
/// Stream types are fixed to [`BoxReadStream`] / [`BoxWriteStream`].
/// A blanket impl is provided for all `T: Session`.
pub trait DynSession: Send + Sync {
    fn session_id(&self) -> VarInt;

    #[allow(clippy::type_complexity)]
    fn open_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), OpenStreamError>>;

    fn open_uni(&self) -> BoxFuture<'_, Result<BoxWriteStream, OpenStreamError>>;

    #[allow(clippy::type_complexity)]
    fn accept_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), Closed>>;

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, Closed>>;
}

impl<T: Session> DynSession for T {
    fn session_id(&self) -> VarInt {
        Session::session_id(self)
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

    fn accept_bi(&self) -> BoxFuture<'_, Result<(BoxReadStream, BoxWriteStream), Closed>> {
        Box::pin(async {
            let (r, w) = Session::accept_bi(self).await?;
            Ok((Box::pin(r) as BoxReadStream, Box::pin(w) as BoxWriteStream))
        })
    }

    fn accept_uni(&self) -> BoxFuture<'_, Result<BoxReadStream, Closed>> {
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

    fn session_id(&self) -> VarInt {
        WebTransportSession::session_id(self)
    }

    async fn open_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), OpenStreamError> {
        WebTransportSession::open_bi(self).await
    }

    async fn open_uni(&self) -> Result<BoxWriteStream, OpenStreamError> {
        WebTransportSession::open_uni(self).await
    }

    async fn accept_bi(&self) -> Result<(BoxReadStream, BoxWriteStream), Closed> {
        WebTransportSession::accept_bi(self).await
    }

    async fn accept_uni(&self) -> Result<BoxReadStream, Closed> {
        WebTransportSession::accept_uni(self).await
    }
}

// ============================================================================
// Error-latching extensions for RPC/IPC
// ============================================================================

#[cfg(feature = "rpc")]
mod lifecycle_ext {
    use std::future::Future;

    use snafu::ResultExt;

    use super::{Closed, OpenSnafu, OpenStreamError};
    use crate::rpc::lifecycle::ConnectionErrorLatch;

    impl ConnectionErrorLatch {
        /// Latch an [`OpenStreamError`] with first-wins semantics.
        ///
        /// If the error wraps a [`ConnectionError`](crate::quic::ConnectionError)
        /// (the `Open` variant), the canonical (first) error is substituted.
        /// Other variants pass through unmodified.
        pub fn latch_open(&self, error: OpenStreamError) -> OpenStreamError {
            match error {
                OpenStreamError::Open { source } => OpenStreamError::Open {
                    source: self.latch(source),
                },
                other => other,
            }
        }

        /// Check the latch for open operations.
        pub fn check_open(&self) -> Result<(), OpenStreamError> {
            self.check().context(OpenSnafu)
        }

        /// Check the latch for accept operations.
        pub fn check_accept(&self) -> Result<(), Closed> {
            self.check().map_err(|_| Closed)
        }

        /// Guard an async open operation: check, execute, latch.
        pub async fn guard_open<T>(
            &self,
            fut: impl Future<Output = Result<T, OpenStreamError>>,
        ) -> Result<T, OpenStreamError> {
            self.check_open()?;
            fut.await.map_err(|e| self.latch_open(e))
        }
    }
}
