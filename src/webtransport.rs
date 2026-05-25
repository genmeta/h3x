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

use std::future::Future;

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

// ============================================================================
// Error-latching extensions for RPC/IPC
// ============================================================================

#[cfg(feature = "rpc")]
mod lifecycle_ext {
    use std::future::Future;

    use snafu::ResultExt;

    use super::{AcceptStreamError, OpenStreamError, SessionClosed};
    use crate::{
        quic::{self, ConnectionError},
        rpc::lifecycle::LifecycleExt,
        webtransport::error::{accept_stream_error, open_stream_error},
    };

    /// WebTransport-flavoured extension of [`LifecycleExt`].
    ///
    /// Adds check/guard helpers that surface [`OpenStreamError`] and
    /// [`AcceptStreamError`] instead of the raw [`ConnectionError`], while preserving
    /// the lazy first-wins latching discipline.
    ///
    /// Like [`LifecycleExt`], this trait is sealed: it is automatically
    /// implemented for any type that already satisfies [`LifecycleExt`].
    #[allow(async_fn_in_trait)]
    pub trait WebTransportLifecycleExt: LifecycleExt {
        /// Check liveness and surface any error as an [`OpenStreamError`].
        fn check_open(&self) -> Result<(), OpenStreamError> {
            quic::Lifecycle::check(self).context(open_stream_error::OpenSnafu)
        }

        /// Check liveness and surface any error as an [`AcceptStreamError`].
        fn check_accept(&self) -> Result<(), AcceptStreamError> {
            quic::Lifecycle::check(self).context(accept_stream_error::ConnectionSnafu)
        }

        /// Guard an async open operation whose error is already an
        /// [`OpenStreamError`].
        ///
        /// If the error wraps a [`ConnectionError`] (the `Open` variant), it
        /// is latched lazily so the first such error becomes canonical; other
        /// variants pass through untouched.
        async fn guard_open<T>(
            &self,
            fut: impl Future<Output = Result<T, OpenStreamError>>,
        ) -> Result<T, OpenStreamError> {
            self.check_open()?;
            match fut.await {
                Ok(v) => Ok(v),
                Err(OpenStreamError::Open { source }) => Err(OpenStreamError::Open {
                    source: self.latch().latch_with(|| source),
                }),
                Err(other) => Err(other),
            }
        }

        /// Guard an async open operation whose error must be lazily converted
        /// to an [`OpenStreamError`].
        ///
        /// `convert_error` is invoked only when the operation errored **and** no
        /// error has been latched yet. If the resulting
        /// [`OpenStreamError::Open`] carries a connection error, it is
        /// substituted with the already-latched value (first wins).
        async fn guard_open_with<T, E, M>(
            &self,
            fut: impl Future<Output = Result<T, E>>,
            convert_error: M,
        ) -> Result<T, OpenStreamError>
        where
            M: FnOnce(E) -> OpenStreamError,
        {
            self.check_open()?;
            match fut.await {
                Ok(v) => Ok(v),
                Err(e) => {
                    if let Some(existing) = self.latch().peek() {
                        return Err(OpenStreamError::Open { source: existing });
                    }
                    Err(match convert_error(e) {
                        OpenStreamError::Open { source } => OpenStreamError::Open {
                            source: self.latch().latch_with(|| source),
                        },
                        other => other,
                    })
                }
            }
        }

        /// Guard an async accept operation whose error is already a
        /// [`AcceptStreamError`].
        async fn guard_accept<T>(
            &self,
            fut: impl Future<Output = Result<T, AcceptStreamError>>,
        ) -> Result<T, AcceptStreamError> {
            self.check_accept()?;
            match fut.await {
                Ok(v) => Ok(v),
                Err(AcceptStreamError::Connection { source }) => {
                    Err(AcceptStreamError::Connection {
                        source: self.latch().latch_with(|| source),
                    })
                }
                Err(other) => Err(other),
            }
        }

        /// Guard an async accept operation whose error carries richer
        /// information than [`SessionClosed`].
        ///
        /// `convert_error` is invoked only when the operation errored **and** no
        /// error has been latched yet. Returning `Some(error)` from it will
        /// lazily install that error in the latch so later observers (on the
        /// connection path) see a meaningful terminal cause; the caller
        /// sees either a structured connection error or a plain session closure.
        async fn guard_accept_err<T, E, M>(
            &self,
            fut: impl Future<Output = Result<T, E>>,
            convert_error: M,
        ) -> Result<T, AcceptStreamError>
        where
            M: FnOnce(E) -> Option<ConnectionError>,
        {
            self.check_accept()?;
            match fut.await {
                Ok(v) => Ok(v),
                Err(e) => {
                    if let Some(existing) = self.latch().peek() {
                        return Err(AcceptStreamError::Connection { source: existing });
                    }
                    if let Some(error) = convert_error(e) {
                        return Err(AcceptStreamError::Connection {
                            source: self.latch().latch_with(|| error),
                        });
                    }
                    Err(AcceptStreamError::Closed {
                        source: SessionClosed,
                    })
                }
            }
        }
    }

    impl<T: LifecycleExt + ?Sized> WebTransportLifecycleExt for T {}
}

#[cfg(feature = "rpc")]
pub use lifecycle_ext::WebTransportLifecycleExt;
