//! RPC forwarding for the WebTransport session layer.
//!
//! Re-exports the RTC trait, generated client/server types, and the
//! [`RemoteWebTransportSession`] convenience wrapper.

use std::future::Future;

use snafu::ResultExt;

mod session;

pub use self::session::{
    RemoteWebTransportSession, WebTransportRpcSessionClient, WebTransportRpcSessionReqReceiver,
    WebTransportRpcSessionServer, WebTransportRpcSessionServerRef,
    WebTransportRpcSessionServerRefMut, WebTransportRpcSessionServerShared,
    WebTransportRpcSessionServerSharedMut,
};
use crate::{
    quic::{self, ConnectionError},
    rpc::lifecycle::LifecycleExt as ConnectionLifecycleExt,
    webtransport::{
        self, AcceptStreamError, CloseReason, CloseSessionError, ControlCommandError,
        DrainSessionError, OpenStreamError, SessionClosed, accept_stream_error, open_stream_error,
    },
};

/// WebTransport-flavoured lifecycle helpers for RPC-backed session handles.
///
/// The trait is intentionally named `LifecycleExt`; the module namespace
/// (`rpc::webtransport::LifecycleExt`) carries the domain. It builds on the
/// connection-level RPC lifecycle latch and maps WebTransport operations into
/// [`OpenStreamError`] / [`AcceptStreamError`] without introducing a separate
/// latch mechanism.
///
/// Implementers still must satisfy the latch-aware lifecycle invariant from
/// [`crate::rpc::lifecycle`]: their [`quic::Lifecycle`] implementation must
/// consult and resolve the same latch used by these guard helpers.
#[allow(async_fn_in_trait)]
pub trait LifecycleExt: ConnectionLifecycleExt {
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

    /// Guard an async open operation whose error must be lazily converted to
    /// an [`OpenStreamError`].
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

    /// Guard an async accept operation whose error is already an
    /// [`AcceptStreamError`].
    async fn guard_accept<T>(
        &self,
        fut: impl Future<Output = Result<T, AcceptStreamError>>,
    ) -> Result<T, AcceptStreamError> {
        self.check_accept()?;
        match fut.await {
            Ok(v) => Ok(v),
            Err(AcceptStreamError::Connection { source }) => Err(AcceptStreamError::Connection {
                source: self.latch().latch_with(|| source),
            }),
            Err(other) => Err(other),
        }
    }

    /// Guard an async accept operation whose error carries richer information
    /// than [`SessionClosed`].
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

impl<T: ConnectionLifecycleExt + ?Sized> LifecycleExt for T {}

impl From<remoc::rtc::CallError> for webtransport::OpenStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        webtransport::OpenStreamError::Open {
            source: quic::ConnectionError::from(error),
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::AcceptStreamError {
    fn from(error: remoc::rtc::CallError) -> Self {
        webtransport::AcceptStreamError::Connection {
            source: quic::ConnectionError::from(error),
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::DrainSessionError {
    fn from(_error: remoc::rtc::CallError) -> Self {
        DrainSessionError::Command {
            source: ControlCommandError::Closed,
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::CloseSessionError {
    fn from(_error: remoc::rtc::CallError) -> Self {
        CloseSessionError::Command {
            source: ControlCommandError::Closed,
        }
    }
}

impl From<remoc::rtc::CallError> for webtransport::CloseReason {
    fn from(error: remoc::rtc::CallError) -> Self {
        CloseReason::Connection(quic::ConnectionError::from(error))
    }
}

#[cfg(test)]
mod tests {
    use std::{borrow::Cow, future::pending};

    use super::*;
    use crate::{
        error::Code,
        rpc::lifecycle::{ConnectionErrorLatch, HasLatch, LifecycleExt as ConnectionLifecycleExt},
        varint::VarInt,
        webtransport::{AcceptStreamError, OpenStreamError},
    };

    #[test]
    fn call_error_maps_to_open_stream_connection_error() {
        let error = webtransport::OpenStreamError::from(remoc::rtc::CallError::Dropped);
        let webtransport::OpenStreamError::Open { source } = error else {
            panic!("call error should map to open stream connection error");
        };

        assert!(source.is_transport());
    }

    #[test]
    fn call_error_maps_to_accept_stream_connection_error() {
        let error = webtransport::AcceptStreamError::from(remoc::rtc::CallError::Dropped);
        let webtransport::AcceptStreamError::Connection { source } = error else {
            panic!("call error should map to accept stream connection error");
        };

        assert!(source.is_transport());
    }

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

    fn assert_reason(error: &quic::ConnectionError, expected: &str) {
        let quic::ConnectionError::Transport { source } = error else {
            panic!("expected transport error");
        };
        assert_eq!(source.reason.as_ref(), expected);
    }

    #[tokio::test]
    async fn lifecycle_checks_and_latches_open_errors() {
        let lifecycle = TestLifecycle::default();

        lifecycle.check_open().expect("open check should pass");
        lifecycle.check_accept().expect("accept check should pass");

        let error = lifecycle
            .guard_open(async {
                Err::<(), _>(OpenStreamError::Open {
                    source: connection_error("first"),
                })
            })
            .await
            .expect_err("open error should be returned");
        let OpenStreamError::Open { source } = error else {
            panic!("expected open error");
        };
        assert_reason(&source, "first");

        let error = lifecycle
            .guard_open(async {
                Err::<(), _>(OpenStreamError::Open {
                    source: connection_error("second"),
                })
            })
            .await
            .expect_err("latched open error should be returned");
        let OpenStreamError::Open { source } = error else {
            panic!("expected open error");
        };
        assert_reason(&source, "first");
    }

    #[tokio::test]
    async fn lifecycle_guard_open_with_converts_lazily() {
        let lifecycle = TestLifecycle::default();

        let error = lifecycle
            .guard_open_with(async { Err::<(), _>("boom") }, |_| OpenStreamError::Open {
                source: connection_error("converted"),
            })
            .await
            .expect_err("converted open error should be returned");

        let OpenStreamError::Open { source } = error else {
            panic!("expected open error");
        };
        assert_reason(&source, "converted");
    }

    #[tokio::test]
    async fn lifecycle_open_guards_return_success_and_passthrough_closed() {
        let lifecycle = TestLifecycle::default();

        let value = lifecycle
            .guard_open(async { Ok::<_, OpenStreamError>(7) })
            .await
            .expect("successful open operation should pass through");
        assert_eq!(value, 7);

        let error = lifecycle
            .guard_open(async {
                Err::<(), _>(OpenStreamError::Closed {
                    source: SessionClosed,
                })
            })
            .await
            .expect_err("closed session error should pass through");
        assert!(matches!(error, OpenStreamError::Closed { .. }));
        lifecycle
            .check_open()
            .expect("non-connection open error must not latch");

        let error = lifecycle
            .guard_open_with(async { Err::<(), _>("closed") }, |_| {
                OpenStreamError::Closed {
                    source: SessionClosed,
                }
            })
            .await
            .expect_err("converted closed session error should pass through");
        assert!(matches!(error, OpenStreamError::Closed { .. }));
        lifecycle
            .check_open()
            .expect("converted non-connection open error must not latch");
    }

    #[tokio::test]
    async fn lifecycle_open_guard_with_uses_error_latched_during_operation() {
        let lifecycle = TestLifecycle::default();
        let latch = lifecycle.latch.clone();

        let error = lifecycle
            .guard_open_with(
                async move {
                    latch.latch_with(|| connection_error("latched during open"));
                    Err::<(), _>("unconverted")
                },
                |_| {
                    panic!("conversion should be skipped once operation latched a connection error")
                },
            )
            .await
            .expect_err("latched open error should be returned");

        let OpenStreamError::Open { source } = error else {
            panic!("expected open error");
        };
        assert_reason(&source, "latched during open");
    }

    #[tokio::test]
    async fn lifecycle_checks_surface_latched_open_error() {
        let lifecycle = TestLifecycle::default();

        let error = lifecycle
            .guard_open(async {
                Err::<(), _>(OpenStreamError::Open {
                    source: connection_error("check latch"),
                })
            })
            .await
            .expect_err("open error should be returned");
        let OpenStreamError::Open { source } = error else {
            panic!("expected open error");
        };
        assert_reason(&source, "check latch");

        let open_error = lifecycle
            .check_open()
            .expect_err("open check should surface latched error");
        let OpenStreamError::Open { source } = open_error else {
            panic!("expected open error");
        };
        assert_reason(&source, "check latch");

        let accept_error = lifecycle
            .check_accept()
            .expect_err("accept check should surface latched error");
        let AcceptStreamError::Connection { source } = accept_error else {
            panic!("expected connection error");
        };
        assert_reason(&source, "check latch");
    }

    #[tokio::test]
    async fn lifecycle_accept_guards_preserve_error_shape() {
        let lifecycle = TestLifecycle::default();

        let error = lifecycle
            .guard_accept(async {
                Err::<(), _>(AcceptStreamError::Connection {
                    source: connection_error("accept"),
                })
            })
            .await
            .expect_err("accept error should be returned");
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected connection error");
        };
        assert_reason(&source, "accept");

        let lifecycle = TestLifecycle::default();
        let error = lifecycle
            .guard_accept_err(async { Err::<(), _>("closed") }, |_| None)
            .await
            .expect_err("closed session should be returned");
        assert!(matches!(error, AcceptStreamError::Closed { .. }));

        let lifecycle = TestLifecycle::default();
        let error = lifecycle
            .guard_accept_err(async { Err::<(), _>("connection") }, |_| {
                Some(connection_error("converted accept"))
            })
            .await
            .expect_err("converted accept error should be returned");
        let AcceptStreamError::Connection { source } = error else {
            panic!("expected connection error");
        };
        assert_reason(&source, "converted accept");
    }

    #[tokio::test]
    async fn lifecycle_accept_guards_return_success_and_passthrough_closed() {
        let lifecycle = TestLifecycle::default();

        let value = lifecycle
            .guard_accept(async { Ok::<_, AcceptStreamError>(11) })
            .await
            .expect("successful accept operation should pass through");
        assert_eq!(value, 11);

        let error = lifecycle
            .guard_accept(async {
                Err::<(), _>(AcceptStreamError::Closed {
                    source: SessionClosed,
                })
            })
            .await
            .expect_err("closed session error should pass through");
        assert!(matches!(error, AcceptStreamError::Closed { .. }));
        lifecycle
            .check_accept()
            .expect("non-connection accept error must not latch");

        let value = lifecycle
            .guard_accept_err(async { Ok::<_, &'static str>(13) }, |_| {
                panic!("conversion should not run for successful accept operation")
            })
            .await
            .expect("successful converted accept operation should pass through");
        assert_eq!(value, 13);
    }

    #[tokio::test]
    async fn lifecycle_accept_guard_uses_error_latched_during_operation() {
        let lifecycle = TestLifecycle::default();
        let latch = lifecycle.latch.clone();

        let error = lifecycle
            .guard_accept_err(
                async move {
                    latch.latch_with(|| connection_error("latched during accept"));
                    Err::<(), _>("unconverted")
                },
                |_| {
                    panic!("conversion should be skipped once operation latched a connection error")
                },
            )
            .await
            .expect_err("latched accept error should be returned");

        let AcceptStreamError::Connection { source } = error else {
            panic!("expected connection error");
        };
        assert_reason(&source, "latched during accept");
    }
}
