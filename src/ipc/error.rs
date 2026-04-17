//! Shared IPC error types.
//!
//! These types are used by both the connection-level ([`super::quic`]) and
//! session-level ([`super::webtransport`]) IPC modules.

use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::quic::ConnectionError;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Infrastructure-level error for IPC plumbing failures.
///
/// This type captures failures in the RPC transport or OS-level I/O
/// (socketpair creation, FD conversion, queue operations).  It deliberately
/// excludes stream-level errors ([`StreamError`](crate::quic::StreamError)),
/// which are application-layer concerns carried in [`Resolved`](crate::util::deferred::Resolved).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_plumbing_error), visibility(pub))]
pub enum IpcPlumbingError {
    /// RPC call failed.
    #[snafu(transparent)]
    Rpc { source: remoc::rtc::CallError },

    /// OS-level or infrastructure I/O failure.
    #[snafu(display("{message}"))]
    Io { message: String },
}

/// Errors from IPC `open_bi` / `open_uni` operations at the connection level.
///
/// Distinguishes between connection-level failures (the connection itself is
/// broken) and plumbing failures (the IPC infrastructure failed).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_open_error), visibility(pub))]
pub enum IpcOpenError {
    /// The underlying connection failed.
    #[snafu(transparent)]
    Connection { source: ConnectionError },

    /// IPC plumbing failure (RPC or I/O).
    #[snafu(transparent)]
    Plumbing { source: IpcPlumbingError },
}

/// Errors from IPC `accept_bi` / `accept_uni` operations at the connection level.
///
/// Structurally identical to [`IpcOpenError`] but kept separate for
/// type-level distinction between open and accept paths.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Snafu)]
#[snafu(module(ipc_accept_error), visibility(pub))]
pub enum IpcAcceptError {
    /// The underlying connection failed.
    #[snafu(transparent)]
    Connection { source: ConnectionError },

    /// IPC plumbing failure (RPC or I/O).
    #[snafu(transparent)]
    Plumbing { source: IpcPlumbingError },
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<remoc::rtc::CallError> for IpcOpenError {
    fn from(error: remoc::rtc::CallError) -> Self {
        IpcPlumbingError::Rpc { source: error }.into()
    }
}

impl From<remoc::rtc::CallError> for IpcAcceptError {
    fn from(error: remoc::rtc::CallError) -> Self {
        IpcPlumbingError::Rpc { source: error }.into()
    }
}
